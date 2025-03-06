#define _GNU_SOURCE
#define _FILE_OFFSET_BITS 64

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <getopt.h>
#include <netdb.h>
#include <netinet/tcp.h>
#include <poll.h>
#include <signal.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/epoll.h>
#include <sys/fcntl.h>
#include <sys/signalfd.h>
#include <unistd.h>

#include <ares.h>

#include "protocol.h"
#include "util.h"

static const size_t CLIENT_BUFFER_SIZE = 1 << 20;

enum LogLevel {
    LOG_LEVEL_ERROR   = 0,
    LOG_LEVEL_WARNING = 1,
    LOG_LEVEL_INFO    = 2,
    LOG_LEVEL_DEBUG   = 3,
};

static const enum LogLevel LOG_LEVEL = LOG_LEVEL_DEBUG;

struct AuthenticationContext {
    char* username;
    char* password;
};

enum ClientState {
    CLIENT_STATE_WAIT_GREET,
    CLIENT_STATE_WAIT_AUTH,
    CLIENT_STATE_WAIT_REQUEST,
    CLIENT_STATE_WAIT_CONNECT,
    CLIENT_STATE_STREAMING,
    CLIENT_STATE_DISCONNECTING
};

struct SharedClientContext {
    int             epoll_fd;
    ares_channel_t* ares_channel;
};

struct ClientContext {
    struct SharedClientContext* shared_ctx;

    enum ClientState            state;

    union {
        int arr[2];
        struct {
            int out;
            int in;
        };
    } in_pipe;
    size_t in_pipe_size;

    union {
        int arr[2];
        struct {
            int out;
            int in;
        };
    } out_pipe;
    size_t                        out_pipe_size;

    struct sockaddr_in            sin;
    struct sockaddr_in            remote_sin;

    int                           sock;
    int                           remote_sock;

    struct ClientContextPollData* poll_data;
    int                           interests;

    struct ClientContextPollData* remote_poll_data;
    int                           remote_interests;

    bool                          ready;
};

struct ClientContextPollData {
    struct ClientContext* client;
    int                   events;
};

static int client_ctx_init(struct ClientContext* client, int sock,
                           struct SharedClientContext* shared_ctx) {
    client->shared_ctx = shared_ctx;
    client->state      = CLIENT_STATE_WAIT_GREET;

    client->sock        = sock;
    client->remote_sock = INVALID_SOCKFD;

    if (pipe2((int*)&client->in_pipe, O_NONBLOCK) < 0) {
        perror("In pipe creation failed");
        return -1;
    }

    fcntl(client->in_pipe.out, F_SETPIPE_SZ, CLIENT_BUFFER_SIZE);

    if (pipe2((int*)&client->out_pipe, O_NONBLOCK) < 0) {
        perror("Out pipe creation failed");
        return -1;
    }

    fcntl(client->out_pipe.out, F_SETPIPE_SZ, CLIENT_BUFFER_SIZE);

    client->in_pipe_size = client->out_pipe_size = 0;

    client->poll_data = NULL;
    client->interests = 0;

    client->remote_poll_data = NULL;
    client->remote_interests = 0;

    client->ready = false;

    return 0;
}

static const char* client_ctx_state(struct ClientContext* client) {
    switch (client->state) {
        case CLIENT_STATE_WAIT_GREET:
            return "WAIT_GREET";
        case CLIENT_STATE_WAIT_AUTH:
            return "WAIT_AUTH";
        case CLIENT_STATE_WAIT_REQUEST:
            return "WAIT_REQUEST";
        case CLIENT_STATE_WAIT_CONNECT:
            return "WAIT_CONNECT";
        case CLIENT_STATE_STREAMING:
            return "STREAMING";
        case CLIENT_STATE_DISCONNECTING:
            return "DISCONNECTING";
    }

    return NULL;
}

static void client_ctx_get_address(struct ClientContext* client, char* buffer,
                                   size_t size) {
    char address[32];
    if (inet_ntop(AF_INET, &client->sin.sin_addr, address, sizeof(address)) ==
        NULL) {
        perror("inet_ntop failed");
        strcpy(address, "<unknown>");
    }

    snprintf(buffer, size, "%s:%hu", address, ntohs(client->sin.sin_port));
}

static void client_ctx_get_remote_address(struct ClientContext* client,
                                          char* buffer, size_t size) {
    char address[32];
    if (inet_ntop(AF_INET, &client->remote_sin.sin_addr, address,
                  sizeof(address)) == NULL) {
        perror("inet_ntop failed");
        strcpy(address, "<unknown>");
    }

    snprintf(buffer, size, "%s:%hu", address,
             ntohs(client->remote_sin.sin_port));
}

static int client_ctx_write_in_queue(struct ClientContext* client,
                                     const void* data, size_t size) {
    const ssize_t sent = write(client->in_pipe.in, data, size);
    if (sent < 0) {
        perror("Write failed");
        return -1;
    }

    client->in_pipe_size += sent;
    return (size_t)sent;
}

static int client_ctx_on_hup(struct ClientContext* client) {
    if (LOG_LEVEL >= LOG_LEVEL_INFO) {
        char address[64];
        client_ctx_get_address(client, address, sizeof(address));

        printf("%-21s [%-13s]: Disconnected\n", address,
               client_ctx_state(client));
    }

    return -1;
}

static int client_ctx_on_remote_hup(struct ClientContext* client) {
    if (LOG_LEVEL >= LOG_LEVEL_INFO) {
        char address[64];
        client_ctx_get_address(client, address, sizeof(address));

        printf("%-21s [%-13s]: Remote disconnected\n", address,
               client_ctx_state(client));
    }

    // Close sock to remove it from epoll
    close(client->remote_sock);
    client->remote_sock = INVALID_SOCKFD;

    // Will be removed in server_free_client
    client->remote_poll_data->events = 0;

    if (client->state == CLIENT_STATE_WAIT_CONNECT) {
        char response[4 + 4 + 2];
        response[0]              = 0x05;                               //ver
        response[1]              = 0x05;                               //status
        response[2]              = 0x00;                               //rsv
        response[3]              = 0x01;                               //ipv4
        *(uint32_t*)&response[4] = client->remote_sin.sin_addr.s_addr; //addr
        *(uint16_t*)&response[4 + 4] = client->remote_sin.sin_port;    //port

        client_ctx_write_in_queue(client, response, sizeof(response));

        client->state = CLIENT_STATE_DISCONNECTING;

        return 0;
    }

    // Still need to send the rest of the data
    if (client->in_pipe_size > 0) {
        client->state = CLIENT_STATE_DISCONNECTING;
        return 0;
    }

    return -1;
}

static void client_ctx_free(struct ClientContext* client) {
    // Close sockets
    close(client->sock);
    if (client->remote_sock != INVALID_SOCKFD)
        close(client->remote_sock);

    // Free poll data
    if (client->poll_data != NULL)
        free(list_node_from_data(client->poll_data));
    if (client->remote_poll_data != NULL)
        free(list_node_from_data(client->remote_poll_data));

    close(client->in_pipe.out);
    close(client->in_pipe.in);
    close(client->out_pipe.out);
    close(client->out_pipe.in);
}

static int client_ctx_splice_in(struct ClientContext* client) {
    const ssize_t read =
        splice(client->sock, NULL, client->out_pipe.in, NULL,
               CLIENT_BUFFER_SIZE, SPLICE_F_MOVE | SPLICE_F_NONBLOCK);
    if (read < 0) {
        if (errno != EAGAIN) {
            char address[64];
            client_ctx_get_address(client, address, sizeof(address));
            fprintf(stderr, "%-21s [%-13s]: client->out failed: %s\n", address,
                    client_ctx_state(client), strerror(errno));
            return -1;
        }

        if (client->out_pipe_size < 0xffff) {
            client->poll_data->events &= ~EPOLLIN;
        } else {
            // Pipe may be full, check who caused EAGAIN

            int       error      = 0;
            socklen_t error_size = sizeof(error);
            if (getsockopt(client->sock, SOL_SOCKET, SO_ERROR, &error,
                           &error_size) < 0) {
                perror("getsockopt");
                return -1;
            }

            if (error == EAGAIN) {
                // It's not a pipe error
                client->poll_data->events &= ~EPOLLIN;
            } else {
                // Wait for pipe to be freed
                client->interests &= ~EPOLLIN;
            }
        }

        return 0;
    }

    if (read == 0)
        return client_ctx_on_hup(client);

    client->out_pipe_size += read;

    return 0;
}

static ssize_t client_ctx_splice_out(struct ClientContext* client) {
    const ssize_t sent =
        splice(client->out_pipe.out, NULL, client->remote_sock, NULL,
               client->out_pipe_size, SPLICE_F_MOVE | SPLICE_F_NONBLOCK);
    if (sent < 0) {
        if (errno != EAGAIN) {
            char address[64];
            client_ctx_get_address(client, address, sizeof(address));
            fprintf(stderr, "%-21s [%-13s]: out->remote failed: %s\n", address,
                    client_ctx_state(client), strerror(errno));
            return -1;
        }

        client->remote_poll_data->events &= ~EPOLLOUT;

        return 0;
    }

    client->out_pipe_size -= sent;

    return sent;
}

static int client_ctx_recv(struct ClientContext* client, char* buffer,
                           size_t size) {
    ssize_t read = 0;
    do {
        const ssize_t read_chunk =
            recv(client->sock, (char*)buffer + read, size - read, 0);
        if (read_chunk < 0) {
            if (errno != EAGAIN) {
                char address[64];
                client_ctx_get_address(client, address, sizeof(address));
                fprintf(stderr, "%-21s [%-13s]: Recv failed: %s\n", address,
                        client_ctx_state(client), strerror(errno));
                return -1;
            }

            client->poll_data->events &= ~EPOLLIN;

            if (read == 0)
                return 0;

            break;
        }

        if (read_chunk == 0)
            break;

        read += read_chunk;
    } while ((size_t)read < size);

    if (read == 0)
        return client_ctx_on_hup(client);

    return read;
}

static int client_ctx_on_greet(struct ClientContext*         client,
                               struct AuthenticationContext* auth_ctx) {
    char    buffer[32];
    ssize_t read;
    if ((read = client_ctx_recv(client, buffer, sizeof(buffer))) == 0)
        return 0;

    char address[64];
    client_ctx_get_address(client, address, sizeof(address));

    ssize_t required_size = 2;
    if (read < required_size) {
        if (LOG_LEVEL >= LOG_LEVEL_WARNING)
            fprintf(stderr, "%-21s [%-13s]: Invalid size %zd\n", address,
                    client_ctx_state(client), read);
        return -1;
    }

    const uint8_t version = buffer[0];
    if (version != 0x05) {
        if (LOG_LEVEL >= LOG_LEVEL_WARNING)
            fprintf(stderr, "%-21s [%-13s]: Invalid version %02x\n", address,
                    client_ctx_state(client), version);
        return -1;
    }

    const uint8_t nauth = buffer[1];
    required_size += MIN(1, nauth);
    if (read < required_size) {
        if (LOG_LEVEL >= LOG_LEVEL_WARNING)
            fprintf(stderr, "%-21s [%-13s]: Invalid size %zd for nauth %hhu\n",
                    address, client_ctx_state(client), read, nauth);
        return -1;
    }

    bool       found = false;
    const bool should_auth =
        auth_ctx->username != NULL && auth_ctx->password != NULL;
    for (size_t idx = 0; idx < nauth; idx++) {
        uint8_t auth = buffer[2 + idx];
        if (!should_auth && auth == AUTH_METHOD_NO_AUTH) {
            found = true;
            break;
        } else if (should_auth && auth == AUTH_METHOD_USER_PASS) {
            found = true;
            break;
        }
    }

    if (!found) {
        if (LOG_LEVEL >= LOG_LEVEL_WARNING)
            fprintf(stderr, "%-21s [%-13s]: Auth %02x not supported\n", address,
                    client_ctx_state(client), buffer[2]);
        return -1;
    }

    if (should_auth) {
        if (LOG_LEVEL >= LOG_LEVEL_DEBUG)
            printf("%-21s [%-13s]: Waiting for auth\n", address,
                   client_ctx_state(client));

        uint8_t response[2] = {0x05, AUTH_METHOD_USER_PASS};
        client_ctx_write_in_queue(client, response, sizeof(response));

        client->state = CLIENT_STATE_WAIT_AUTH;
    } else {
        if (LOG_LEVEL >= LOG_LEVEL_DEBUG)
            printf("%-21s [%-13s]: Authenticated\n", address,
                   client_ctx_state(client));

        uint8_t response[2] = {0x05, AUTH_METHOD_NO_AUTH};
        client_ctx_write_in_queue(client, response, sizeof(response));

        client->state = CLIENT_STATE_WAIT_REQUEST;
    }

    client->interests |= EPOLLOUT;

    return 0;
}

static int client_ctx_auth(struct ClientContext*         client,
                           struct AuthenticationContext* auth_ctx) {
    char    buffer[512 + 3];
    ssize_t read;
    if ((read = client_ctx_recv(client, buffer, sizeof(buffer))) == 0)
        return 0;

    char address[64];
    client_ctx_get_address(client, address, sizeof(address));

    ssize_t required_size = 2;
    if (read < required_size) {
        if (LOG_LEVEL >= LOG_LEVEL_WARNING)
            fprintf(stderr, "%-21s [%-13s]: Invalid size %zd\n", address,
                    client_ctx_state(client), read);
        return -1;
    }

    size_t        offset  = 0;
    const uint8_t version = buffer[offset++];
    if (version != 0x01) {
        if (LOG_LEVEL >= LOG_LEVEL_WARNING)
            fprintf(stderr, "%-21s [%-13s]: Invalid version %02x\n", address,
                    client_ctx_state(client), version);
        return -1;
    }

    const uint8_t username_length = buffer[offset++];
    required_size += username_length;
    if (read < required_size) {
        if (LOG_LEVEL >= LOG_LEVEL_WARNING)
            fprintf(stderr, "%-21s [%-13s]: Invalid size %zd\n", address,
                    client_ctx_state(client), read);
        return -1;
    }

    char username[255];
    memcpy(username, buffer + offset, username_length);
    username[username_length] = '\0';
    offset += username_length;

    const uint8_t password_length = buffer[offset++];
    required_size += password_length;
    if (read < required_size) {
        if (LOG_LEVEL >= LOG_LEVEL_WARNING)
            fprintf(stderr, "%-21s [%-13s]: Invalid size %zd\n", address,
                    client_ctx_state(client), read);
        return -1;
    }

    char password[255];
    memcpy(password, buffer + offset, password_length);
    password[password_length] = '\0';

    // TODO: Use hash
    if (strcmp(username, auth_ctx->username)) {
        if (LOG_LEVEL >= LOG_LEVEL_WARNING)
            fprintf(stderr, "%-21s [%-13s]: Invalid password\n", address,
                    client_ctx_state(client));
        return -1;
    }

    if (strcmp(password, auth_ctx->password)) {
        if (LOG_LEVEL >= LOG_LEVEL_WARNING)
            fprintf(stderr, "%-21s [%-13s]: Invalid password\n", address,
                    client_ctx_state(client));
        return -1;
    }

    if (LOG_LEVEL >= LOG_LEVEL_DEBUG)
        printf("%-21s [%-13s]: Authenticated\n", address,
               client_ctx_state(client));

    // Send auth success
    const uint8_t response[2] = {0x01, 0x00};
    client_ctx_write_in_queue(client, response, sizeof(response));

    client->interests = EPOLLIN | EPOLLOUT;
    client->state     = CLIENT_STATE_WAIT_REQUEST;

    return 0;
}

static int client_ctx_setup_connection(struct ClientContext* client,
                                       int                   epoll_fd) {
    if (LOG_LEVEL >= LOG_LEVEL_DEBUG) {
        char address[64];
        client_ctx_get_address(client, address, sizeof(address));

        char remote_address_str[64];
        client_ctx_get_remote_address(client, remote_address_str,
                                      sizeof(remote_address_str));

        printf("%-21s [%-13s]: Connecting to %s\n", address,
               client_ctx_state(client), remote_address_str);
    }

    const int remote_sock = socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK, 0);
    if (remote_sock < 0) {
        perror("Failed to create a remote socket");
        return -1;
    }

    const int status =
        connect(remote_sock, (const struct sockaddr*)&client->remote_sin,
                sizeof(client->remote_sin));
    if (status < 0 && errno != EINPROGRESS && errno != EAGAIN) {
        perror("Connect failed");
        close(remote_sock);
        return -1;
    }

    // Disable nagle algorithm
    if (setsockopt(remote_sock, IPPROTO_TCP, TCP_NODELAY, &(int){1},
                   sizeof(int)) < 0) {
        perror("setsockopt TCP_NODELAY");
        close(remote_sock);
        return -1;
    }

    struct ClientContextPollData* const poll_data = client->remote_poll_data;

    // EPOLLOUT should be on until connection is made
    struct epoll_event event;
    event.events   = EPOLLIN | EPOLLOUT | EPOLLET;
    event.data.ptr = poll_data;

    if (epoll_ctl(epoll_fd, EPOLL_CTL_ADD, remote_sock, &event) < 0) {
        perror("epoll_ctl failed");
        close(remote_sock);
        return -1;
    }

    client->remote_sock = remote_sock;

    client->interests        = 0;
    client->remote_interests = EPOLLOUT;

    client->state = CLIENT_STATE_WAIT_CONNECT;

    return 0;
}

static void client_ctx_ares_callback(void* arg, int status, int timeouts,
                                     struct ares_addrinfo* result) {
    (void)status;
    (void)timeouts;

    struct ClientContext* const      client = arg;

    const struct ares_addrinfo_node* info = NULL;
    for (info = result->nodes; info != NULL; info = info->ai_next) {
        if (info->ai_family == AF_INET) {
            break;
        }
    }

    if (info == NULL) {
        // No available address found
        char response[4 + 4 + 2];
        response[0] = 0x05;                            //ver
        response[1] = SOCKS5_STATUS_GENERAL_FAILURE;   //status
        response[2] = 0x00;                            //rsv
        response[3] = 0x01;                            //ipv4
        memset(&response[4], 0, sizeof(uint32_t));     //addr
        memset(&response[4 + 4], 0, sizeof(uint16_t)); //port
        client_ctx_write_in_queue(client, response, sizeof(response));

        client->interests = EPOLLOUT;
        client->state     = CLIENT_STATE_DISCONNECTING;

        if (LOG_LEVEL >= LOG_LEVEL_INFO) {
            char address[64];
            client_ctx_get_address(client, address, sizeof(address));

            printf("%-21s [%-13s]: Failed to resolve %s\n", address,
                   client_ctx_state(client), result->name);
        }

        ares_freeaddrinfo(result);
        return;
    }

    const struct sockaddr_in* const sin = (struct sockaddr_in*)info->ai_addr;
    client->remote_sin.sin_family       = sin->sin_family;
    client->remote_sin.sin_addr         = sin->sin_addr;
    ares_freeaddrinfo(result);

    client_ctx_setup_connection(client, client->shared_ctx->epoll_fd);
}

static int client_ctx_on_request(struct ClientContext* client, int epoll_fd) {
    char    buffer[512];
    ssize_t read;
    if ((read = client_ctx_recv(client, buffer, sizeof(buffer))) == 0)
        return 0;

    char address[64];
    client_ctx_get_address(client, address, sizeof(address));

    ssize_t required_size = sizeof(struct Socks5ConnRequestHeader);
    if (read < required_size) {
        if (LOG_LEVEL >= LOG_LEVEL_WARNING)
            fprintf(stderr, "%-21s [%-13s]: Invalid size %zd\n", address,
                    client_ctx_state(client), read);
        return -1;
    }

    const struct Socks5ConnRequestHeader* const req =
        (struct Socks5ConnRequestHeader*)buffer;

    const uint8_t version = req->version;
    if (version != 0x05) {
        if (LOG_LEVEL >= LOG_LEVEL_WARNING)
            fprintf(stderr, "%-21s [%-13s]: Invalid version %02x\n", address,
                    client_ctx_state(client), version);
        return -1;
    }

    const uint8_t cmd = req->command;
    if (cmd != SOCKS5_CMD_TCP_STREAM) {
        if (LOG_LEVEL >= LOG_LEVEL_WARNING)
            fprintf(stderr, "%-21s [%-13s]: Unsupported command %02x\n",
                    address, client_ctx_state(client), cmd);
        return -1;
    }

    // TODO:
    const uint8_t address_type = req->address_type;
    if (address_type == SOCKS5_ADDR_IPV6) {
        char response[4 + 4 + 2];
        response[0] = 0x05;                                //ver
        response[1] = SOCKS5_STATUS_ADDRESS_NOT_SUPPORTED; //status
        response[2] = 0x00;                                //rsv
        response[3] = 0x01;                                //ipv4
        memset(&response[4], 0, sizeof(uint32_t));         //addr
        memset(&response[4 + 4], 0, sizeof(uint16_t));     //port
        client_ctx_write_in_queue(client, response, sizeof(response));

        client->interests = EPOLLOUT;
        client->state     = CLIENT_STATE_DISCONNECTING;

        if (LOG_LEVEL >= LOG_LEVEL_WARNING)
            fprintf(stderr, "%-21s [%-13s]: Unsupported address type %02x\n",
                    address, client_ctx_state(client), address_type);

        return 0;
    }

    size_t   offset         = sizeof(struct Socks5ConnRequestHeader);
    uint32_t remote_address = 0;
    uint16_t remote_port    = 0;
    if (address_type == SOCKS5_ADDR_IPV4) {
        required_size += 4 + 2;
        if (read < required_size) {
            if (LOG_LEVEL >= LOG_LEVEL_WARNING)
                fprintf(stderr, "%-21s [%-13s]: Invalid size %zd\n", address,
                        client_ctx_state(client), read);
            return -1;
        }

        memcpy(&remote_address, &buffer[offset], sizeof(remote_address));
        offset += 4;

        memcpy(&remote_port, &buffer[offset], sizeof(remote_port));

        client->remote_sin.sin_family      = AF_INET;
        client->remote_sin.sin_addr.s_addr = remote_address;
        client->remote_sin.sin_port        = htons(remote_port);
    } else if (address_type == SOCKS5_ADDR_DOMAIN) {
        required_size += 1 + 2;
        if (read < required_size) {
            if (LOG_LEVEL >= LOG_LEVEL_WARNING)
                fprintf(stderr, "%-21s [%-13s]: Invalid size %zd\n", address,
                        client_ctx_state(client), read);
            return -1;
        }

        uint8_t domain_size = buffer[offset++];
        required_size += domain_size;
        if (read < required_size) {
            if (LOG_LEVEL >= LOG_LEVEL_WARNING)
                fprintf(stderr, "%-21s [%-13s]: Invalid size %zd\n", address,
                        client_ctx_state(client), read);
            return -1;
        }

        char domain[255];
        memcpy(domain, buffer + offset, domain_size);
        domain[domain_size] = '\0';
        offset += domain_size;

        memcpy(&remote_port, &buffer[offset], sizeof(remote_port));
        if (LOG_LEVEL >= LOG_LEVEL_DEBUG)
            printf("%-21s [%-13s]: Resolving domain %s\n", address,
                   client_ctx_state(client), domain);

        client->remote_sin.sin_port = remote_port;

        client->interests        = 0;
        client->remote_interests = 0;

        // Resolve the domain
        struct ares_addrinfo_hints hints;
        memset(&hints, 0, sizeof(hints));
        hints.ai_family = AF_UNSPEC;
        hints.ai_flags  = ARES_AI_CANONNAME;
        ares_getaddrinfo(client->shared_ctx->ares_channel, domain, NULL, &hints,
                         client_ctx_ares_callback, client);

        return 0;
    }

    return client_ctx_setup_connection(client, epoll_fd);
}

static int client_ctx_stream(struct ClientContext* client) {
    if (client_ctx_splice_in(client) < 0)
        return -1;

    if (client->out_pipe_size > 0)
        client->remote_interests |= EPOLLOUT;

    return 0;
}

static int client_ctx_on_recv(struct ClientContext* client, int epoll_fd,
                              struct AuthenticationContext* auth_ctx) {
    switch (client->state) {
        case CLIENT_STATE_STREAMING:
            return client_ctx_stream(client);
        case CLIENT_STATE_WAIT_GREET:
            return client_ctx_on_greet(client, auth_ctx);
        case CLIENT_STATE_WAIT_AUTH:
            return client_ctx_auth(client, auth_ctx);
        case CLIENT_STATE_WAIT_REQUEST:
            return client_ctx_on_request(client, epoll_fd);
        default:
            return 0;
    }
}

static int client_ctx_splice_remote_in(struct ClientContext* client) {
    const ssize_t read =
        splice(client->remote_sock, NULL, client->in_pipe.in, NULL,
               CLIENT_BUFFER_SIZE, SPLICE_F_MOVE | SPLICE_F_NONBLOCK);
    if (read < 0) {
        if (errno != EAGAIN) {
            char address[64];
            client_ctx_get_address(client, address, sizeof(address));
            fprintf(stderr, "%-21s [%-13s]: remote->in failed: %s\n", address,
                    client_ctx_state(client), strerror(errno));
            return -1;
        }

        if (client->in_pipe_size < 0xffff) {
            client->remote_poll_data->events &= ~EPOLLIN;
        } else {
            // Pipe may be full, check who caused EAGAIN

            int       error      = 0;
            socklen_t error_size = sizeof(error);
            if (getsockopt(client->remote_sock, SOL_SOCKET, SO_ERROR, &error,
                           &error_size) < 0) {
                perror("getsockopt");
                return -1;
            }

            if (error == EAGAIN) {
                // It's not a pipe error
                client->remote_poll_data->events &= ~EPOLLIN;
            }
        }

        return 0;
    }

    if (read == 0)
        return client_ctx_on_remote_hup(client);

    client->in_pipe_size += read;

    return 0;
}

static ssize_t client_ctx_splice_remote_out(struct ClientContext* client) {
    const ssize_t sent =
        splice(client->in_pipe.out, NULL, client->sock, NULL,
               client->in_pipe_size, SPLICE_F_MOVE | SPLICE_F_NONBLOCK);
    if (sent < 0) {
        if (errno != EAGAIN) {
            char address[64];
            client_ctx_get_address(client, address, sizeof(address));
            fprintf(stderr, "%-21s [%-13s]: in->client failed: %s\n", address,
                    client_ctx_state(client), strerror(errno));
            return -1;
        }

        client->poll_data->events &= ~EPOLLOUT;

        return 0;
    }

    client->in_pipe_size -= sent;

    return sent;
}

static int client_ctx_on_remote_recv(struct ClientContext* client) {
    if (client_ctx_splice_remote_in(client) < 0)
        return -1;

    if (client->in_pipe_size > 0)
        client->interests |= EPOLLOUT;

    return 0;
}

static int client_ctx_on_send(struct ClientContext* client) {
    if (client->in_pipe_size > 0) {
        const ssize_t sent = client_ctx_splice_remote_out(client);
        if (sent < 0)
            return -1;

        if (sent > 0)
            client->interests |= EPOLLOUT;

        if (client->in_pipe_size == 0) {
            // Wait for everything to be sent, then disconnect
            if (client->state == CLIENT_STATE_DISCONNECTING) {
                char address[64];
                client_ctx_get_address(client, address, sizeof(address));

                if (LOG_LEVEL >= LOG_LEVEL_INFO)
                    printf("%-21s [%-13s]: Disconnecting\n", address,
                           client_ctx_state(client));

                return -1;
            }

            // There is nothing to send to the client
            client->interests &= ~EPOLLOUT;
        }
    }

    return 0;
}

static int client_ctx_on_remote_send(struct ClientContext* client) {
    if (LIKELY(client->state == CLIENT_STATE_STREAMING)) {
        if (client->out_pipe_size > 0) {
            const ssize_t sent = client_ctx_splice_out(client);
            if (sent < 0)
                return -1;

            if (sent > 0)
                client->interests |= EPOLLIN;

            // There is nothing to send to the remote
            if (client->out_pipe_size == 0)
                client->remote_interests &= ~EPOLLOUT;
        }

        return 0;
    }

    if (UNLIKELY(client->state == CLIENT_STATE_WAIT_CONNECT)) {
        char response[4 + 4 + 2];
        response[0] = 0x05;                          //ver
        response[1] = SOCKS5_STATUS_REQUEST_GRANTED; //status
        response[2] = 0x00;                          //rsv
        response[3] = 0x01;                          //ipv4
        memcpy(&response[4], &client->remote_sin.sin_addr.s_addr,
               sizeof(uint32_t)); //addr
        memcpy(&response[4 + 4], &client->remote_sin.sin_port,
               sizeof(uint16_t)); //port

        client_ctx_write_in_queue(client, response, sizeof(response));

        // Enable nagle algorithm back
        if (setsockopt(client->sock, IPPROTO_TCP, TCP_NODELAY, &(int){0},
                       sizeof(int)) < 0) {
            perror("setsockopt TCP_NODELAY");
            return -1;
        }

        if (LOG_LEVEL >= LOG_LEVEL_DEBUG) {
            char address[64];
            client_ctx_get_address(client, address, sizeof(address));

            printf("%-21s [%-13s]: Connected to remote\n", address,
                   client_ctx_state(client));
        }

        // Start proxying
        client->interests        = EPOLLOUT | EPOLLIN;
        client->remote_interests = EPOLLIN;

        client->state = CLIENT_STATE_STREAMING;
    }

    return 0;
}

struct ServerContext {
    struct SharedClientContext shared_ctx;

    int                        epoll_fd;

    int                        server_sock;
    int                        events;

    struct List                clients;
    struct List                poll_data_list;
    struct List                ready_clients;
    size_t                     ready_clients_count;
};

static int server_ctx_init(struct ServerContext* server, uint16_t port,
                           ares_channel_t* ares_channel) {

    const int server_sock = server->server_sock =
        socket(AF_INET, SOCK_STREAM | O_NONBLOCK, 0);
    if (server_sock < 0) {
        perror("Failed to create server socket");
        goto failure_socket;
    }

    const int value = 1;
    if (setsockopt(server_sock, SOL_SOCKET, SO_REUSEADDR, &value,
                   sizeof(value)) < 0) {
        perror("setsockopt failed");
        goto failure_socket;
    }

    {
        struct sockaddr_in sin;
        sin.sin_family      = AF_INET;
        sin.sin_addr.s_addr = INADDR_ANY;
        sin.sin_port        = htons(port);
        if (bind(server_sock, (const struct sockaddr*)&sin, sizeof(sin)) < 0) {
            perror("Bind failed");
            goto failure_socket;
        }

        if (listen(server_sock, 4096) < 0) {
            perror("Listen failed");
            goto failure_socket;
        }
    }

    server->events = 0;

    list_init(&server->clients);
    list_init(&server->ready_clients);
    list_init(&server->poll_data_list);
    server->ready_clients_count = 0;

    const int epoll_fd = server->epoll_fd = epoll_create1(0);
    if (epoll_fd < 0) {
        perror("epoll_create1 failed");
        goto failure_socket;
    }

    // Add server pollfd
    struct epoll_event event;
    event.events   = EPOLLIN | EPOLLET;
    event.data.ptr = server;

    if (epoll_ctl(epoll_fd, EPOLL_CTL_ADD, server_sock, &event) < 0) {
        perror("epoll_ctl failed");
        goto failure_epoll;
    }

    server->shared_ctx.epoll_fd     = epoll_fd;
    server->shared_ctx.ares_channel = ares_channel;

    return 0;

failure_epoll:
    close(epoll_fd);
failure_socket:
    close(server_sock);
    return -1;
}

static int server_ctx_setup_signal_handler(const struct ServerContext* server,
                                           sigset_t                    mask) {
    int sfd = signalfd(-1, &mask, 0);
    if (sfd == -1) {
        perror("signalfd");
        return -1;
    }

    struct epoll_event event;
    event.events   = EPOLLIN | EPOLLET;
    event.data.ptr = NULL;

    if (epoll_ctl(server->epoll_fd, EPOLL_CTL_ADD, sfd, &event) < 0) {
        perror("epoll_ctl failed");
        close(sfd);
        return 1;
    }

    return 0;
}

static int server_ctx_accept(struct ServerContext* server) {
    // Accept socket
    struct sockaddr_in sin;
    socklen_t          sin_length = sizeof(sin);
    const int          client_sock =
        accept(server->server_sock, (struct sockaddr*)&sin, &sin_length);
    if (client_sock < 0) {
        if (errno != EAGAIN) {
            perror("Accept failed");
            goto failure_accept;
        }

        server->events = 0;

        return 0;
    }

    // Allocate a new client
    struct ListNode* const client_node =
        list_alloc(&server->clients, sizeof(struct ClientContext));
    if (client_node == NULL) {
        perror("Failed to allocate a ClientContext node");
        goto failure_accept;
    }

    list_append(&server->clients, client_node);

    struct ClientContext* const client = list_node_data(client_node);
    if (client_ctx_init(client, client_sock, &server->shared_ctx) < 0) {
        perror("Client initialization failed");
        goto failure_client_alloc;
    }

    memcpy(&client->sin, &sin, sizeof(sin));

    // Make it non-blocking
    const int flags = fcntl(client_sock, F_GETFL);
    if (flags < 0) {
        perror("F_GETFL failed");
        goto failure_client_alloc;
    }

    if (fcntl(client_sock, F_SETFL, flags | O_NONBLOCK) < 0) {
        perror("F_SETFL O_NONBLOCK failed");
        goto failure_client_alloc;
    }

    // Disable nagle algorithm
    if (setsockopt(client->sock, IPPROTO_TCP, TCP_NODELAY, &(int){1},
                   sizeof(int)) < 0) {
        perror("setsockopt TCP_NODELAY");
        goto failure_client_alloc;
    }

    if (LOG_LEVEL >= LOG_LEVEL_INFO) {
        char address[64];
        client_ctx_get_address(client, address, sizeof(address));

        printf("%-21s [%-13s]: Connected %p\n", address,
               client_ctx_state(client), (void*)client);
    }

    // Preallocate remote epoll data
    struct ListNode* const remote_epoll_data_node = list_alloc(
        &server->poll_data_list, sizeof(struct ClientContextPollData));
    if (remote_epoll_data_node == NULL) {
        perror("Failed to allocate a ClientContextPollData node");
        goto failure_client_alloc;
    }

    {
        struct ClientContextPollData* const poll_data =
            list_node_data(remote_epoll_data_node);
        poll_data->client = client;
        poll_data->events = 0;

        client->remote_poll_data = poll_data;

        list_append(&server->poll_data_list, remote_epoll_data_node);
    }

    // Allocate epoll data
    struct ListNode* const epoll_data_node = list_alloc(
        &server->poll_data_list, sizeof(struct ClientContextPollData));
    if (epoll_data_node == NULL) {
        perror("Failed to allocate a ClientContextPollData node");
        goto failure_remote_epoll_data;
    }

    {
        struct ClientContextPollData* const poll_data =
            list_node_data(epoll_data_node);
        poll_data->client = client;
        poll_data->events = 0;

        client->poll_data = poll_data;

        list_append(&server->poll_data_list, epoll_data_node);

        // Add to epoll fd
        struct epoll_event event;
        event.events   = EPOLLIN | EPOLLOUT | EPOLLET;
        event.data.ptr = poll_data;

        if (epoll_ctl(server->epoll_fd, EPOLL_CTL_ADD, client_sock, &event) <
            0) {
            perror("epoll_ctl failed");
            goto failure_epoll_data;
        }
    }

    // Wait for command
    client->interests |= EPOLLIN;

    return 0;

failure_epoll_data:
    list_remove(&server->clients, epoll_data_node);
    free(epoll_data_node);
failure_remote_epoll_data:
    list_remove(&server->clients, remote_epoll_data_node);
    free(remote_epoll_data_node);
failure_client_alloc:
    list_remove(&server->clients, client_node);
    free(client_node);
failure_accept:
    close(client_sock);
    return -1;
}

static int server_free_client(struct ServerContext* server,
                              struct ListNode*      client_node) {
    struct ClientContext* const client =
        (struct ClientContext*)list_node_data(client_node);

    if (LOG_LEVEL >= LOG_LEVEL_INFO) {
        char address[64];
        client_ctx_get_address(client, address, sizeof(address));

        printf("%-21s [%-13s]: Freeing client %p\n", address,
               client_ctx_state(client), (void*)client);
    }

    if (client->ready) {
        list_remove(&server->ready_clients, client_node);
        server->ready_clients_count--;
    } else {
        list_remove(&server->clients, client_node);
    }

    {
        struct ListNode* poll_data_node =
            list_node_from_data(client->poll_data);
        list_remove(&server->poll_data_list, poll_data_node);
    }

    {
        struct ListNode* remote_poll_data_node =
            list_node_from_data(client->remote_poll_data);
        list_remove(&server->poll_data_list, remote_poll_data_node);
    }

    client_ctx_free(client);
    free(client_node);

    return 0;
}

static void server_ctx_free(struct ServerContext* server) {
    // Move everyone from ready list to clients list
    if (server->clients.head == NULL) {
        server->clients.head = server->ready_clients.head;
        server->clients.tail = server->ready_clients.tail;
    } else {
        server->clients.tail->next = server->ready_clients.head;
        server->clients.tail       = server->ready_clients.tail;
    }

    // Free clients
    {
        struct ListNode* client_node = server->clients.head;
        while (client_node != NULL) {
            struct ListNode*      next   = client_node->next;
            struct ClientContext* client = list_node_data(client_node);

            client_ctx_free(client);

            free(client_node);
            client_node = next;
        }
    }

    close(server->epoll_fd);
    close(server->server_sock);
}

int main(int argc, char* argv[]) {
    if (argc <= 1) {
        fprintf(stderr, "Usage: %s [OPTIONS]\n", argv[0]);
        fprintf(stderr, "Options:\n");
        fprintf(stderr, "  -P port\n");
        fprintf(stderr, "  -u username\n");
        fprintf(stderr, "  -p password\n");
        return 1;
    }

    uint16_t                     server_port = 0;
    struct AuthenticationContext auth_ctx;
    auth_ctx.username = NULL;
    auth_ctx.password = NULL;

    int flag;
    while ((flag = getopt(argc, argv, "P:u:p:")) != -1) {
        switch (flag) {
            case 'P':
                server_port = strtoul(optarg, NULL, 10);
                break;
            case 'u':
                if (auth_ctx.username)
                    free(auth_ctx.username);
                auth_ctx.username = strdup(optarg);
                break;
            case 'p':
                if (auth_ctx.password)
                    free(auth_ctx.password);
                auth_ctx.password = strdup(optarg);
                break;
            default:
                return 1;
        }
    }

    if (server_port == 0) {
        fprintf(stderr, "%s: 'P' must be specified\n", argv[0]);
        return 1;
    }

    if (auth_ctx.username != NULL && auth_ctx.password == NULL) {
        fprintf(stderr, "%s: 'p' must be specified if 'u' is specified\n",
                argv[0]);
        return 1;
    } else if (auth_ctx.username == NULL && auth_ctx.password != NULL) {
        fprintf(stderr, "%s: 'u' must be specified if 'p' is specified\n",
                argv[0]);
        return 1;
    }

    // Initialize c-ares
    ares_channel_t* ares_channel = NULL;
    if (ares_library_init(ARES_LIB_INIT_ALL) != ARES_SUCCESS) {
        fprintf(stderr, "c-ares library initialization failed\n");
        return 1;
    }

    if (!ares_threadsafety()) {
        fprintf(stderr, "c-ares not compiled with thread support\n");
        return 1;
    }

    struct ares_options options;
    memset(&options, 0, sizeof(options));
    options.evsys = ARES_EVSYS_DEFAULT;
    if (ares_init_options(&ares_channel, &options, ARES_OPT_EVENT_THREAD) !=
        ARES_SUCCESS) {
        fprintf(stderr, "c-ares initialization failed\n");
        return 1;
    }

    struct ServerContext server;
    if (server_ctx_init(&server, server_port, ares_channel) < 0)
        return 1;

    // Setup signal handlers
    signal(SIGPIPE, SIG_IGN);
    {
        sigset_t mask;
        sigemptyset(&mask);
        sigaddset(&mask, SIGINT);
        sigaddset(&mask, SIGQUIT);

        if (sigprocmask(SIG_BLOCK, &mask, NULL) == -1) {
            perror("sigprocmask");
            return 1;
        }

        if (server_ctx_setup_signal_handler(&server, mask) < 0)
            return 1;
    }

    if (LOG_LEVEL >= LOG_LEVEL_INFO)
        printf("Starting on port %hu\n", server_port);

    while (true) {
        struct epoll_event events[256];

        int                ready = 0;
        {
            int timeout = server.ready_clients_count > 0 ? 0 : -1;
            ready       = epoll_wait(server.epoll_fd, events,
                                     sizeof(events) / sizeof(*events), timeout);
        }

        if (UNLIKELY(ready < 0)) {
            perror("poll failed");
            break;
        }

        bool should_stop = false;
        for (size_t idx = 0; idx < (size_t)ready; idx++) {
            const struct epoll_event* const event = &events[idx];
            if (UNLIKELY(event->data.ptr == &server)) {
                server.events = event->events;
                continue;
            } else if (UNLIKELY(event->data.ptr == NULL)) {
                should_stop = true;
                break;
            }

            struct ClientContextPollData* const poll_data = event->data.ptr;
            struct ClientContext* const         client    = poll_data->client;
            struct ClientContextPollData* const remote_poll_data =
                client->remote_poll_data;

#if 0
            printf("Got event for ");
            if (event->data.ptr == client->poll_data)
                printf("LOCAL");
            else
                printf("REMOTE");
            printf(" [ ");
            if (event->events & EPOLLIN)
                printf("EPOLLIN ");
            if (event->events & EPOLLOUT)
                printf("EPOLLOUT ");
            if (event->events & EPOLLHUP)
                printf("EPOLLHUP ");
            printf("]\n");
#endif

            const int interests = poll_data == remote_poll_data ?
                client->remote_interests :
                client->interests;
            if (!client->ready && (event->events & interests)) {
                // Move to ready list

                struct ListNode* const client_node =
                    list_node_from_data(client);
                list_remove(&server.clients, client_node);
                list_append(&server.ready_clients, client_node);
                server.ready_clients_count++;

                client->ready = true;
            }

            poll_data->events = event->events;
        }

        if (should_stop)
            break;

        if (server.events & EPOLLIN) {
            if (server_ctx_accept(&server) < 0)
                break;
        }

        struct ListNode* client_node = server.ready_clients.head;
        while (client_node != NULL) {
            struct ListNode* const      next   = client_node->next;
            struct ClientContext* const client = list_node_data(client_node);

            struct ClientContextPollData* const poll_data = client->poll_data;
            struct ClientContextPollData* const remote_poll_data =
                client->remote_poll_data;

            int poll_data_events        = poll_data->events;
            int remote_poll_data_events = remote_poll_data->events;

            if (poll_data_events & EPOLLIN &&
                client_ctx_on_recv(client, server.epoll_fd, &auth_ctx) < 0) {
                if (LOG_LEVEL >= LOG_LEVEL_DEBUG)
                    printf("Freeing client: on_recv failed\n");
                server_free_client(&server, client_node);
                goto goto_next;
            }

            if (remote_poll_data_events & EPOLLOUT &&
                client_ctx_on_remote_send(client) < 0) {
                if (LOG_LEVEL >= LOG_LEVEL_DEBUG)
                    printf("Freeing client: on_remote_send failed\n");
                server_free_client(&server, client_node);
                goto goto_next;
            }

            if (remote_poll_data_events & EPOLLIN &&
                client_ctx_on_remote_recv(client) < 0) {
                if (LOG_LEVEL >= LOG_LEVEL_DEBUG)
                    printf("Freeing client: on_remote_recv failed\n");
                server_free_client(&server, client_node);
                goto goto_next;
            }

            if (poll_data_events & EPOLLOUT && client_ctx_on_send(client) < 0) {
                if (LOG_LEVEL >= LOG_LEVEL_DEBUG)
                    printf("Freeing client: on_send failed\n");
                server_free_client(&server, client_node);
                goto goto_next;
            }

            // Remove from ready list if all events are processed
            if (!((client->interests & poll_data->events) |
                  (client->remote_interests &
                   client->remote_poll_data->events))) {
#if 0
                printf("exhausted with interests [ ");
                if (client->interests & EPOLLIN)
                    printf("EPOLLIN ");
                if (client->interests & EPOLLOUT)
                    printf("EPOLLOUT ");
                if (client->remote_interests & EPOLLIN)
                    printf("REMOTE_EPOLLIN ");
                if (client->remote_interests & EPOLLOUT)
                    printf("REMOTE_EPOLLOUT ");
                printf("] ready: %zu\n", server.ready_clients_count - 1);
#endif

                list_remove(&server.ready_clients, client_node);
                list_append(&server.clients, client_node);
                server.ready_clients_count--;

                client->ready = false;
            }

        goto_next:
            client_node = next;
        }
    }

    if (LOG_LEVEL >= LOG_LEVEL_INFO)
        printf("Cleaning up\n");

    // Wait for requests to be completed before freeing clients
    ares_queue_wait_empty(ares_channel, -1);

    server_ctx_free(&server);

    if (auth_ctx.username != NULL && auth_ctx.password != NULL) {
        free(auth_ctx.username);
        free(auth_ctx.password);
    }

    ares_destroy(ares_channel);
    ares_library_cleanup();

    if (LOG_LEVEL >= LOG_LEVEL_DEBUG)
        printf("Exiting\n");

    return 0;
}
