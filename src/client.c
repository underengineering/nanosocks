#include "client.h"

#include <arpa/inet.h>
#include <errno.h>
#include <netinet/tcp.h>
#include <sys/epoll.h>
#include <sys/fcntl.h>
#include <unistd.h>

#include "list.h"
#include "log.h"
#include "protocol.h"
#include "util.h"

int client_ctx_init(struct ClientContext* client, int sock,
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

const char* client_ctx_state(struct ClientContext* client) {
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

void client_ctx_get_address(struct ClientContext* client, char* buffer,
                            size_t size) {
    char address[32];
    if (inet_ntop(AF_INET, &client->sin.sin_addr, address, sizeof(address)) ==
        NULL) {
        perror("inet_ntop failed");
        strcpy(address, "<unknown>");
    }

    snprintf(buffer, size, "%s:%hu", address, ntohs(client->sin.sin_port));
}

void client_ctx_get_remote_address(struct ClientContext* client, char* buffer,
                                   size_t size) {
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

void client_ctx_free(struct ClientContext* client) {
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
        client->remote_sin.sin_port        = remote_port;
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

int client_ctx_on_recv(struct ClientContext* client, int epoll_fd,
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

int client_ctx_on_remote_recv(struct ClientContext* client) {
    if (client_ctx_splice_remote_in(client) < 0)
        return -1;

    if (client->in_pipe_size > 0)
        client->interests |= EPOLLOUT;

    return 0;
}

int client_ctx_on_send(struct ClientContext* client) {
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

int client_ctx_on_remote_send(struct ClientContext* client) {
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
