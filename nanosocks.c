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
#include <unistd.h>

#include "nanosocks.h"

static const size_t CLIENT_RING_BUFFER_SIZE = 4096;
static const size_t CLIENT_BUFFER_SIZE      = 2048;

enum LogLevel {
    LOG_LEVEL_ERROR   = 0,
    LOG_LEVEL_WARNING = 1,
    LOG_LEVEL_INFO    = 2,
    LOG_LEVEL_DEBUG   = 3,
};

static const enum LogLevel LOG_LEVEL = LOG_LEVEL_INFO;

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

struct ClientContext {
    enum ClientState   state;

    struct RingBuffer  in_queue;
    struct RingBuffer  out_queue;

    struct sockaddr_in sin;
    struct sockaddr_in remote_sin;

    int                sock;
    int                remote_sock;

    size_t             pollfd_idx;
    size_t             remote_pollfd_idx;
};

static void client_ctx_init(struct ClientContext* ctx) {
    ctx->state = CLIENT_STATE_WAIT_GREET;

    ring_buffer_init(&ctx->in_queue, CLIENT_RING_BUFFER_SIZE);
    ring_buffer_init(&ctx->out_queue, CLIENT_RING_BUFFER_SIZE);

    ctx->remote_sock       = INVALID_SOCKFD;
    ctx->remote_pollfd_idx = INVALID_POLLFD;
}

static const char* client_ctx_state(struct ClientContext* ctx) {
    switch (ctx->state) {
        case CLIENT_STATE_WAIT_GREET: return "WAIT_GREET";
        case CLIENT_STATE_WAIT_AUTH: return "WAIT_AUTH";
        case CLIENT_STATE_WAIT_REQUEST: return "WAIT_REQUEST";
        case CLIENT_STATE_WAIT_CONNECT: return "WAIT_CONNECT";
        case CLIENT_STATE_STREAMING: return "STREAMING";
        case CLIENT_STATE_DISCONNECTING: return "DISCONNECTING";
    }

    return NULL;
}

static void client_ctx_get_address(struct ClientContext* ctx, char* buffer,
                                   size_t size) {
    char address[32];
    if (inet_ntop(AF_INET, &ctx->sin.sin_addr, address, sizeof(address)) ==
        NULL) {
        perror("inet_ntop failed");
        strcpy(address, "<unknown>");
    }

    snprintf(buffer, size, "%s:%hu", address, ntohs(ctx->sin.sin_port));
}

static void client_ctx_get_remote_address(struct ClientContext* ctx,
                                          char* buffer, size_t size) {
    char address[32];
    if (inet_ntop(AF_INET, &ctx->remote_sin.sin_addr, address,
                  sizeof(address)) == NULL) {
        perror("inet_ntop failed");
        strcpy(address, "<unknown>");
    }

    snprintf(buffer, size, "%s:%hu", address, ntohs(ctx->remote_sin.sin_port));
}

static int client_ctx_on_hup(struct ClientContext* ctx) {
    char address[64];
    client_ctx_get_address(ctx, address, sizeof(address));

    if (LOG_LEVEL >= LOG_LEVEL_INFO)
        printf("%-21s [%-13s]: Disconnected\n", address, client_ctx_state(ctx));

    return -1;
}

static int client_ctx_on_remote_hup(struct ClientContext* ctx) {
    char address[64];
    client_ctx_get_address(ctx, address, sizeof(address));

    if (LOG_LEVEL >= LOG_LEVEL_INFO)
        printf("%-21s [%-13s]: Remote disconnected\n", address,
               client_ctx_state(ctx));

    if (ctx->state == CLIENT_STATE_WAIT_CONNECT) {
        char response[4 + 4 + 2];
        response[0]                  = 0x05;                            //ver
        response[1]                  = 0x05;                            //status
        response[2]                  = 0x00;                            //rsv
        response[3]                  = 0x01;                            //ipv4
        *(uint32_t*)&response[4]     = ctx->remote_sin.sin_addr.s_addr; //addr
        *(uint16_t*)&response[4 + 4] = ctx->remote_sin.sin_port;        //port

        ring_buffer_fill(&ctx->in_queue, response, sizeof(response));

        ctx->state = CLIENT_STATE_DISCONNECTING;

        return 0;
    }

    return -1;
}

enum Socks5AuthMethod {
    AUTH_METHOD_NO_AUTH   = 0x00,
    AUTH_METHOD_USER_PASS = 0x02,
};

enum Socks5Command {
    SOCKS5_CMD_TCP_STREAM = 0x01,
    SOCKS5_CMD_TCP_ASSOC  = 0x02,
    SOCKS5_CMD_UDP_ASSOC  = 0x03
};

enum Socks5AddressType {
    SOCKS5_ADDR_IPV4   = 0x01,
    SOCKS5_ADDR_DOMAIN = 0x03,
    SOCKS5_ADDR_IPV6   = 0x04,
};

enum Socks5Status {
    SOCKS5_STATUS_REQUEST_GRANTED        = 0x00,
    SOCKS5_STATUS_GENERAL_FAILURE        = 0x01,
    SOCKS5_STATUS_CONNECTION_NOT_ALLOWED = 0x02,
    SOCKS5_STATUS_NETWORK_UNREACHABLE    = 0x03,
    SOCKS5_STATUS_HOST_UNREACHABLE       = 0x04,
    SOCKS5_STATUS_CONNECTION_REFUSED     = 0x05,
    SOCKS5_STATUS_TTL_EXPIRED            = 0x06,
    SOCKS5_STATUS_COMMAND_NOT_SUPPORTED  = 0x07,
    SOCKS5_STATUS_ADDRESS_NOT_SUPPORTED  = 0x08,
};

struct Socks5ConnRequestHeader {
    uint8_t version;
    uint8_t command;
    uint8_t reserved;
    uint8_t address_type;
};

static void client_ctx_free(struct ClientContext* ctx) {
    ring_buffer_free(&ctx->in_queue);
    ring_buffer_free(&ctx->out_queue);
}

static int client_ctx_on_recv(struct ClientContext* ctx, struct Vector* pollfds,
                              struct AuthenticationContext* auth_ctx,
                              struct pollfd*                pollfd,
                              struct pollfd*                remote_pollfd) {
    // Wait for remote connection first
    if (UNLIKELY(ctx->state == CLIENT_STATE_WAIT_CONNECT)) {
        // Stop accepting data until connection is made
        pollfd->events &= ~POLLIN;
        return 0;
    }

    size_t buffer_avail_size =
        ctx->out_queue.capacity - ring_buffer_size(&ctx->out_queue);
    if (UNLIKELY(buffer_avail_size <= 1)) {
        // Out buffer is full

        if (LOG_LEVEL >= LOG_LEVEL_DEBUG) {
            char address[64];
            client_ctx_get_address(ctx, address, sizeof(address));

            printf("%-21s [%-13s]: OUT buffer is full\n", address,
                   client_ctx_state(ctx));
        }

        // Don't accept more data from the client
        pollfd->events &= ~POLLIN;

        return 0;
    }

    char    buffer[CLIENT_BUFFER_SIZE];
    size_t  to_read = MIN(buffer_avail_size - 1, sizeof(buffer));

    ssize_t read;
    if (LIKELY(ctx->state == CLIENT_STATE_STREAMING)) {
        // Use ring buffer when streaming
        bool is_trivially_allocatable =
            ring_buffer_is_trivially_allocatable(&ctx->out_queue, to_read);
        if (is_trivially_allocatable) {
            // Recv directly to the ring buffer
            read = recv_all(ctx->sock,
                            (char*)ctx->out_queue.data + ctx->out_queue.tail,
                            to_read, 0);

            if (read > 0)
                ring_buffer_grow(&ctx->out_queue, read);
        } else {
            // Recv to the temp buffer
            read = recv_all(ctx->sock, buffer, to_read, 0);

            // Fill ring buffer with temp buffer
            if (read > 0)
                ring_buffer_fill(&ctx->out_queue, buffer, read);
        }
    } else {
        // Use stack buffer
        read = recv_all(ctx->sock, buffer, to_read, 0);
    }

    if (read < 0) {
        if (errno != EAGAIN && errno != EWOULDBLOCK) {
            perror("recv failed");
            return -1;
        }

        return 0;
    }

    if (read == 0)
        return client_ctx_on_hup(ctx);

    if (LIKELY(ctx->state == CLIENT_STATE_STREAMING)) {
        if (LOG_LEVEL >= LOG_LEVEL_DEBUG) {
            char address[64];
            client_ctx_get_address(ctx, address, sizeof(address));
            printf("%-21s [%-13s]: RECV << %zd | avail=%zu sz=%zu\n", address,
                   client_ctx_state(ctx), read, buffer_avail_size,
                   ring_buffer_size(&ctx->out_queue));
        }

        remote_pollfd->events |= POLLOUT;
        return 0;
    }

    if (ctx->state == CLIENT_STATE_WAIT_GREET) {
        char address[64];
        client_ctx_get_address(ctx, address, sizeof(address));

        ssize_t required_size = 2;
        if (read < required_size) {
            if (LOG_LEVEL >= LOG_LEVEL_WARNING)
                fprintf(stderr, "%-21s [%-13s]: Invalid size %zd\n", address,
                        client_ctx_state(ctx), read);
            return -1;
        }

        uint8_t version = buffer[0];
        if (version != 0x05) {
            if (LOG_LEVEL >= LOG_LEVEL_WARNING)
                fprintf(stderr, "%-21s [%-13s]: Invalid version %02x\n",
                        address, client_ctx_state(ctx), version);
            return -1;
        }

        uint8_t nauth = buffer[1];
        required_size += MIN(1, nauth);
        if (read < required_size) {
            if (LOG_LEVEL >= LOG_LEVEL_WARNING)
                fprintf(stderr,
                        "%-21s [%-13s]: Invalid size %zd for nauth %hhu\n",
                        address, client_ctx_state(ctx), read, nauth);
            return -1;
        }

        bool found = false;
        bool should_auth =
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
                fprintf(stderr, "%-21s [%-13s]: Auth %02x not supported\n",
                        address, client_ctx_state(ctx), buffer[2]);
            return -1;
        }

        if (should_auth) {
            if (LOG_LEVEL >= LOG_LEVEL_DEBUG)
                printf("%-21s [%-13s]: Waiting for auth\n", address,
                       client_ctx_state(ctx));

            uint8_t response[2] = {0x05, AUTH_METHOD_USER_PASS};
            ring_buffer_fill(&ctx->in_queue, response, sizeof(response));

            pollfd->events |= POLLOUT;
            ctx->state = CLIENT_STATE_WAIT_AUTH;
        } else {
            if (LOG_LEVEL >= LOG_LEVEL_DEBUG)
                printf("%-21s [%-13s]: Authenticated\n", address,
                       client_ctx_state(ctx));

            uint8_t response[2] = {0x05, AUTH_METHOD_NO_AUTH};
            ring_buffer_fill(&ctx->in_queue, response, sizeof(response));

            pollfd->events |= POLLOUT;
            ctx->state = CLIENT_STATE_WAIT_REQUEST;
        }
    } else if (ctx->state == CLIENT_STATE_WAIT_AUTH) {
        char address[64];
        client_ctx_get_address(ctx, address, sizeof(address));

        ssize_t required_size = 2;
        if (read < required_size) {
            if (LOG_LEVEL >= LOG_LEVEL_WARNING)
                fprintf(stderr, "%-21s [%-13s]: Invalid size %zd\n", address,
                        client_ctx_state(ctx), read);
            return -1;
        }

        size_t  offset  = 0;
        uint8_t version = buffer[offset++];
        if (version != 0x01) {
            if (LOG_LEVEL >= LOG_LEVEL_WARNING)
                fprintf(stderr, "%-21s [%-13s]: Invalid version %02x\n",
                        address, client_ctx_state(ctx), version);
            return -1;
        }

        uint8_t username_length = buffer[offset++];
        required_size += username_length;
        if (read < required_size) {
            if (LOG_LEVEL >= LOG_LEVEL_WARNING)
                fprintf(stderr, "%-21s [%-13s]: Invalid size %zd\n", address,
                        client_ctx_state(ctx), read);
            return -1;
        }

        char username[255];
        memcpy(username, buffer + offset, username_length);
        username[username_length] = '\0';
        offset += username_length;

        uint8_t password_length = buffer[offset++];
        required_size += password_length;
        if (read < required_size) {
            if (LOG_LEVEL >= LOG_LEVEL_WARNING)
                fprintf(stderr, "%-21s [%-13s]: Invalid size %zd\n", address,
                        client_ctx_state(ctx), read);
            return -1;
        }

        char password[255];
        memcpy(password, buffer + offset, password_length);
        password[password_length] = '\0';

        // TODO: Use hash
        if (strcmp(username, auth_ctx->username)) {
            if (LOG_LEVEL >= LOG_LEVEL_WARNING)
                fprintf(stderr, "%-21s [%-13s]: Invalid password\n", address,
                        client_ctx_state(ctx));
            return -1;
        }

        if (strcmp(password, auth_ctx->password)) {
            if (LOG_LEVEL >= LOG_LEVEL_WARNING)
                fprintf(stderr, "%-21s [%-13s]: Invalid password\n", address,
                        client_ctx_state(ctx));
            return -1;
        }

        if (LOG_LEVEL >= LOG_LEVEL_DEBUG)
            printf("%-21s [%-13s]: Authenticated\n", address,
                   client_ctx_state(ctx));

        // Send auth success
        uint8_t response[2] = {0x01, 0x00};
        ring_buffer_fill(&ctx->in_queue, response, sizeof(response));

        pollfd->events |= POLLOUT;
        ctx->state = CLIENT_STATE_WAIT_REQUEST;
    } else if (ctx->state == CLIENT_STATE_WAIT_REQUEST) {
        char address[64];
        client_ctx_get_address(ctx, address, sizeof(address));

        ssize_t required_size = sizeof(struct Socks5ConnRequestHeader);
        if (read < required_size) {
            if (LOG_LEVEL >= LOG_LEVEL_WARNING)
                fprintf(stderr, "%-21s [%-13s]: Invalid size %zd\n", address,
                        client_ctx_state(ctx), read);
            return -1;
        }

        struct Socks5ConnRequestHeader* req =
            (struct Socks5ConnRequestHeader*)buffer;

        uint8_t version = req->version;
        if (version != 0x05) {
            if (LOG_LEVEL >= LOG_LEVEL_WARNING)
                fprintf(stderr, "%-21s [%-13s]: Invalid version %02x\n",
                        address, client_ctx_state(ctx), version);
            return -1;
        }

        uint8_t cmd = req->command;
        if (cmd != SOCKS5_CMD_TCP_STREAM) {
            if (LOG_LEVEL >= LOG_LEVEL_WARNING)
                fprintf(stderr, "%-21s [%-13s]: Unsupported command %02x\n",
                        address, client_ctx_state(ctx), cmd);
            return -1;
        }

        uint8_t address_type = req->address_type;
        if (address_type == SOCKS5_ADDR_IPV6) {
            char response[4 + 4 + 2];
            response[0] = 0x05;                                //ver
            response[1] = SOCKS5_STATUS_ADDRESS_NOT_SUPPORTED; //status
            response[2] = 0x00;                                //rsv
            response[3] = 0x01;                                //ipv4
            *(uint32_t*)&response[4]     = 0;                  //addr
            *(uint16_t*)&response[4 + 4] = 0;                  //port
            ring_buffer_fill(&ctx->in_queue, response, sizeof(response));
            pollfd->events |= POLLOUT;
            ctx->state = CLIENT_STATE_DISCONNECTING;

            if (LOG_LEVEL >= LOG_LEVEL_WARNING)
                fprintf(stderr,
                        "%-21s [%-13s]: Unsupported address type %02x\n",
                        address, client_ctx_state(ctx), address_type);

            return 0;
        }

        size_t   offset         = sizeof(struct Socks5ConnRequestHeader);
        uint32_t remote_address = 0;
        uint16_t remote_port    = 0;
        if (address_type == SOCKS5_ADDR_IPV4) {
            required_size += 4 + 2;
            if (read < required_size) {
                if (LOG_LEVEL >= LOG_LEVEL_WARNING)
                    fprintf(stderr, "%-21s [%-13s]: Invalid size %zd\n",
                            address, client_ctx_state(ctx), read);
                return -1;
            }

            remote_address = *(uint32_t*)&buffer[offset];
            offset += 4;

            remote_port = *(uint16_t*)&buffer[offset];
        } else if (address_type == SOCKS5_ADDR_DOMAIN) {
            required_size += 1 + 2;
            if (read < required_size) {
                if (LOG_LEVEL >= LOG_LEVEL_WARNING)
                    fprintf(stderr, "%-21s [%-13s]: Invalid size %zd\n",
                            address, client_ctx_state(ctx), read);
                return -1;
            }

            uint8_t domain_size = buffer[offset++];
            required_size += domain_size;
            if (read < required_size) {
                if (LOG_LEVEL >= LOG_LEVEL_WARNING)
                    fprintf(stderr, "%-21s [%-13s]: Invalid size %zd\n",
                            address, client_ctx_state(ctx), read);
                return -1;
            }

            char domain[255];
            memcpy(domain, buffer + offset, domain_size);
            domain[domain_size] = '\0';
            offset += domain_size;

            remote_port = *(const uint16_t*)&buffer[offset];
            if (LOG_LEVEL >= LOG_LEVEL_DEBUG)
                printf("%-21s [%-13s]: Resolving domain %s\n", address,
                       client_ctx_state(ctx), domain);

            // Resolve ipv4
            struct addrinfo* addr_info = NULL;
            if (getaddrinfo(domain, NULL, NULL, &addr_info) < 0) {
                char response[4 + 4 + 2];
                response[0] = 0x05;                                //ver
                response[1] = SOCKS5_STATUS_GENERAL_FAILURE;       //status
                response[2] = 0x00;                                //rsv
                response[3] = 0x01;                                //ipv4
                *(uint32_t*)&response[4]     = remote_address;     //addr
                *(uint16_t*)&response[4 + 4] = htons(remote_port); //port

                ring_buffer_fill(&ctx->in_queue, response, sizeof(response));

                pollfd->events |= POLLOUT;
                ctx->state = CLIENT_STATE_DISCONNECTING;

                perror("getaddrinfo failed");
                return 0;
            }

            for (struct addrinfo* info = addr_info; info != NULL;
                 info                  = info->ai_next) {
                if (info->ai_family == AF_INET) {
                    struct sockaddr_in* sin =
                        (struct sockaddr_in*)info->ai_addr;
                    remote_address = sin->sin_addr.s_addr;
                    break;
                }
            }

            freeaddrinfo(addr_info);

            if (remote_address == 0) {
                // No available address found
                char response[4 + 4 + 2];
                response[0] = 0x05;                                //ver
                response[1] = SOCKS5_STATUS_GENERAL_FAILURE;       //status
                response[2] = 0x00;                                //rsv
                response[3] = 0x01;                                //ipv4
                *(uint32_t*)&response[4]     = remote_address;     //addr
                *(uint16_t*)&response[4 + 4] = htons(remote_port); //port

                ring_buffer_fill(&ctx->in_queue, response, sizeof(response));

                pollfd->events |= POLLOUT;
                ctx->state = CLIENT_STATE_DISCONNECTING;

                if (LOG_LEVEL >= LOG_LEVEL_DEBUG)
                    printf("%-21s [%-13s]: Failed to resolve %s\n", address,
                           client_ctx_state(ctx), domain);

                return 0;
            }
        }

        ctx->remote_sin.sin_family      = AF_INET;
        ctx->remote_sin.sin_addr.s_addr = remote_address;
        ctx->remote_sin.sin_port        = remote_port;

        if (LOG_LEVEL >= LOG_LEVEL_DEBUG) {
            char remote_address_str[64];
            client_ctx_get_remote_address(ctx, remote_address_str,
                                          sizeof(remote_address_str));

            printf("%-21s [%-13s]: Connecting to %s\n", address,
                   client_ctx_state(ctx), remote_address_str);
        }

        int remote_sock = socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK, 0);
        if (remote_sock < 0) {
            perror("Failed to create a remote socket");
            return -1;
        }

        int status =
            connect(remote_sock, (const struct sockaddr*)&ctx->remote_sin,
                    sizeof(ctx->remote_sin));
        if (status < 0 && errno != EINPROGRESS && errno != EWOULDBLOCK) {
            perror("connect failed");
            return -1;
        }

        struct pollfd pollfd;
        pollfd.fd = remote_sock;

        // POLLOUT should be on until connection is made
        pollfd.events  = POLLIN | POLLOUT;
        pollfd.revents = 0;

        ctx->remote_sock       = remote_sock;
        ctx->remote_pollfd_idx = pollfds->length;
        if (vector_push(pollfds, &pollfd, sizeof(pollfd)) < 0) {
            perror("Remote socket pollfd allocation failed");
            return -1;
        }

        ctx->state = CLIENT_STATE_WAIT_CONNECT;
    }

    return 0;
}

static int client_ctx_on_remote_recv(struct ClientContext* ctx,
                                     struct pollfd*        pollfd,
                                     struct pollfd*        remote_pollfd) {
    size_t buffer_avail_size =
        ctx->in_queue.capacity - ring_buffer_size(&ctx->in_queue);
    if (UNLIKELY(buffer_avail_size <= 1)) {
        // In buffer is full
        if (LOG_LEVEL >= LOG_LEVEL_DEBUG) {
            char address[64];
            client_ctx_get_address(ctx, address, sizeof(address));

            printf("%-21s [%-13s]: IN buffer is full\n", address,
                   client_ctx_state(ctx));
        }

        // Don't accept more data from the remote
        remote_pollfd->events &= ~POLLIN;

        return 0;
    }

    char    buffer[CLIENT_BUFFER_SIZE];
    size_t  to_recv = MIN(buffer_avail_size - 1, sizeof(buffer));

    ssize_t read;
    bool    is_trivially_allocatable =
        ring_buffer_is_trivially_allocatable(&ctx->in_queue, to_recv);
    if (is_trivially_allocatable) {
        // Recv directly to the ring buffer
        read = recv_all(ctx->remote_sock,
                        (char*)ctx->in_queue.data + ctx->in_queue.tail, to_recv,
                        0);
        if (read > 0)
            ring_buffer_grow(&ctx->in_queue, read);
    } else {
        // Recv to the temp buffer
        read = recv_all(ctx->remote_sock, buffer, to_recv, 0);
        if (read > 0)
            ring_buffer_fill(&ctx->in_queue, buffer, read);
    }

    if (read < 0) {
        if (errno != EAGAIN && errno != EWOULDBLOCK) {
            perror("Remote recv failed");
            return -1;
        }

        return 0;
    }

    if (read == 0)
        return client_ctx_on_remote_hup(ctx);

    if (LOG_LEVEL >= LOG_LEVEL_DEBUG) {
        char address[64];
        client_ctx_get_address(ctx, address, sizeof(address));

        printf("%-21s [%-13s]: RECV (REMOTE) << %zd |  avail=%zu sz=%zu\n",
               address, client_ctx_state(ctx), read, buffer_avail_size,
               ring_buffer_size(&ctx->in_queue));
    }

    pollfd->events |= POLLOUT;

    return 0;
}

static int client_ctx_on_send(struct ClientContext* ctx, struct pollfd* pollfd,
                              struct pollfd* remote_pollfd) {
    char   buffer[CLIENT_BUFFER_SIZE];
    size_t buffer_size = ring_buffer_size(&ctx->in_queue);
    if (UNLIKELY(buffer_size == 0)) {
        // Wait for everything to be sent, then disconnect
        if (ctx->state == CLIENT_STATE_DISCONNECTING) {
            char address[64];
            client_ctx_get_address(ctx, address, sizeof(address));

            if (LOG_LEVEL >= LOG_LEVEL_INFO)
                printf("%s [DISCONNECTING]: Disconnecting\n", address);

            return -1;
        }

        // There is nothing to send to the client
        pollfd->events &= ~POLLOUT;

        return 0;
    }

    size_t  to_send = MIN(buffer_size, sizeof(buffer));

    ssize_t sent;
    if (ring_buffer_is_trivially_copyable(&ctx->in_queue, buffer_size)) {
        // Send directly from the ring buffer
        sent = send_all(ctx->sock,
                        (const char*)ctx->in_queue.data + ctx->in_queue.head,
                        buffer_size, 0);
    } else {
        // Copy to the temp buffer
        ring_buffer_copy(&ctx->in_queue, buffer, to_send);
        sent = send_all(ctx->sock, buffer, to_send, 0);
    }

    if (sent < 0) {
        if (errno != EAGAIN && errno != EWOULDBLOCK) {
            perror("send failed");
            return -1;
        }

        return 0;
    }

    if (LOG_LEVEL >= LOG_LEVEL_DEBUG) {
        char address[64];
        client_ctx_get_address(ctx, address, sizeof(address));

        printf("%-21s [%-13s]: SEND >> %zu | sent=%zd\n", address,
               client_ctx_state(ctx), to_send, sent);
    }

    ring_buffer_shrink(&ctx->in_queue, sent);

    // We sent all data in the buffer
    if ((size_t)sent == buffer_size)
        pollfd->events &= ~POLLOUT;

    // We freed some space in the buffer
    if (remote_pollfd != NULL)
        remote_pollfd->events |= POLLIN;

    return 0;
}

static int client_ctx_on_remote_send(struct ClientContext* ctx,
                                     struct pollfd*        pollfd,
                                     struct pollfd*        remote_pollfd) {
    if (UNLIKELY(ctx->state == CLIENT_STATE_WAIT_CONNECT)) {
        char response[4 + 4 + 2];
        response[0]                  = 0x05;                            //ver
        response[1]                  = SOCKS5_STATUS_REQUEST_GRANTED;   //status
        response[2]                  = 0x00;                            //rsv
        response[3]                  = 0x01;                            //ipv4
        *(uint32_t*)&response[4]     = ctx->remote_sin.sin_addr.s_addr; //addr
        *(uint16_t*)&response[4 + 4] = ctx->remote_sin.sin_port;        //port
        ring_buffer_fill(&ctx->in_queue, response, sizeof(response));

        pollfd->events |= POLLIN | POLLOUT;

        char address[64];
        client_ctx_get_address(ctx, address, sizeof(address));

        if (LOG_LEVEL >= LOG_LEVEL_DEBUG)
            printf("%-21s [%-13s]: Connected to remote\n", address,
                   client_ctx_state(ctx));

        ctx->state = CLIENT_STATE_STREAMING;
    }

    size_t buffer_size = ring_buffer_size(&ctx->out_queue);
    if (UNLIKELY(buffer_size == 0)) {
        // There is nothing to send to the remote
        if (ctx->state == CLIENT_STATE_STREAMING)
            remote_pollfd->events &= ~POLLOUT;

        return 0;
    }

    char    buffer[CLIENT_BUFFER_SIZE];
    size_t  to_send = MIN(buffer_size, sizeof(buffer));

    ssize_t sent;
    if (ring_buffer_is_trivially_copyable(&ctx->out_queue, to_send)) {
        sent = send_all(ctx->remote_sock,
                        (const char*)ctx->out_queue.data + ctx->out_queue.head,
                        to_send, 0);
    } else {
        ring_buffer_copy(&ctx->out_queue, buffer, to_send);
        sent = send_all(ctx->remote_sock, buffer, to_send, 0);
    }

    if (sent < 0) {
        if (errno != EAGAIN && errno != EWOULDBLOCK) {
            perror("Remote send failed");
            return -1;
        }

        return 0;
    }

    if (LOG_LEVEL >= LOG_LEVEL_DEBUG) {
        char address[64];
        client_ctx_get_address(ctx, address, sizeof(address));

        printf("%-21s [%-13s]: SEND (REMOTE) >> %zu | sent=%zd\n", address,
               client_ctx_state(ctx), to_send, sent);
    }

    ring_buffer_shrink(&ctx->out_queue, to_send);

    // We sent all data in the buffer
    if ((size_t)sent == buffer_size)
        remote_pollfd->events &= ~POLLOUT;

    // We freed some space in the buffer
    pollfd->events |= POLLIN;

    return 0;
}

struct ServerContext {
    int           server_sock;
    struct Vector pollfds;
    struct Vector clients;
};

static int server_ctx_init(struct ServerContext* ctx, uint16_t port) {
    int server_sock = ctx->server_sock =
        socket(AF_INET, SOCK_STREAM | O_NONBLOCK, 0);
    if (server_sock < 0) {
        perror("Failed to create server socket");
        return -1;
    }

    {
        struct sockaddr_in sin;
        sin.sin_family      = AF_INET;
        sin.sin_addr.s_addr = INADDR_ANY;
        sin.sin_port        = htons(port);
        if (bind(server_sock, (const struct sockaddr*)&sin, sizeof(sin)) < 0) {
            perror("Bind failed");
            return -1;
        }

        if (listen(server_sock, 1) < 0) {
            perror("Listen failed");
            return -1;
        }
    }

    vector_init(&ctx->pollfds, 0, 0);
    vector_init(&ctx->clients, 0, 0);

    // Create server pollfd
    struct pollfd pollfd;
    pollfd.fd     = server_sock;
    pollfd.events = POLLIN;
    if (vector_push(&ctx->pollfds, &pollfd, sizeof(struct pollfd)) < 0) {
        perror("Failed to push server pollfd");
        return -1;
    }

    return 0;
}

static int server_ctx_accept(struct ServerContext* ctx) {
    // Allocate a new client
    struct ClientContext* client =
        vector_alloc(&ctx->clients, sizeof(struct ClientContext));
    if (client == NULL) {
        perror("Failed to allocate a ClientContext");
        return -1;
    }

    client_ctx_init(client);

    // Accept socket
    socklen_t sin_length = sizeof(client->sin);
    int       client_sock =
        accept(ctx->server_sock, (struct sockaddr*)&client->sin, &sin_length);
    client->sock = client_sock;
    if (client_sock < 0) {
        perror("Accept failed");
        return -1;
    }

    // Make it non-blocking
    int flags = fcntl(client_sock, F_GETFL);
    if (flags < 0) {
        perror("F_GETFL failed");
        return -1;
    }

    if (fcntl(client_sock, F_SETFL, flags | O_NONBLOCK) < 0) {
        perror("F_SETFL O_NONBLOCK failed");
        return -1;
    }

    // Disable nagle algorithm
    int value = 1;
    if (setsockopt(client_sock, IPPROTO_TCP, TCP_NODELAY, &value,
                   sizeof(value)) < 0) {
        perror("setsockopt TCP_NODELAY");
        return -1;
    }

    if (LOG_LEVEL >= LOG_LEVEL_INFO) {
        char address[64];
        client_ctx_get_address(client, address, sizeof(address));

        printf("%-21s [%-13s]: Connected\n", address, client_ctx_state(client));
    }

    // Allocate a new pollfd
    client->pollfd_idx    = ctx->pollfds.length;
    struct pollfd* pollfd = vector_alloc(&ctx->pollfds, sizeof(struct pollfd));
    if (pollfd == NULL) {
        perror("Failed to push a new pollfd");
        return -1;
    }

    pollfd->fd     = client_sock;
    pollfd->events = POLLIN;

    return 0;
}

static int server_free_client(struct ServerContext* ctx, size_t index) {
    struct ClientContext* client =
        vector_get(&ctx->clients, index, sizeof(struct ClientContext));

    if (LOG_LEVEL >= LOG_LEVEL_DEBUG) {
        char address[64];
        client_ctx_get_address(client, address, sizeof(address));

        printf("%-21s [%-13s]: Freeing client #%zu\n", address,
               client_ctx_state(client), index);
    }

    // Free remote socket & pollfd
    if (client->remote_sock != INVALID_SOCKFD) {
        struct pollfd* pollfd = vector_get(
            &ctx->pollfds, client->remote_pollfd_idx, sizeof(struct pollfd));
        close(pollfd->fd);

        size_t end_pollfd_idx = ctx->pollfds.length - 1;
        if (client->remote_pollfd_idx != end_pollfd_idx) {
            for (size_t idx = 0; idx < ctx->clients.length; idx++) {
                struct ClientContext* other_client = vector_get(
                    &ctx->clients, idx, sizeof(struct ClientContext));
                if (other_client->pollfd_idx == end_pollfd_idx) {
                    other_client->pollfd_idx = client->remote_pollfd_idx;
                    break;
                } else if (other_client->remote_pollfd_idx == end_pollfd_idx) {
                    other_client->remote_pollfd_idx = client->remote_pollfd_idx;
                    break;
                }
            }
        }

        if (vector_swap_remove(&ctx->pollfds, client->remote_pollfd_idx,
                               sizeof(struct pollfd)) < 0) {
            return -1;
        }
    }

    // Free client socket & pollfd
    {
        struct pollfd* pollfd = vector_get(&ctx->pollfds, client->pollfd_idx,
                                           sizeof(struct pollfd));
        close(pollfd->fd);

        size_t end_pollfd_idx = ctx->pollfds.length - 1;
        if (client->pollfd_idx != end_pollfd_idx) {
            // Update potentially swapped pollfd indexes
            for (size_t idx = 0; idx < ctx->clients.length; idx++) {
                struct ClientContext* other_client = vector_get(
                    &ctx->clients, idx, sizeof(struct ClientContext));
                if (other_client->pollfd_idx == end_pollfd_idx) {
                    other_client->pollfd_idx = client->pollfd_idx;
                    break;
                } else if (other_client->remote_pollfd_idx == end_pollfd_idx) {
                    other_client->remote_pollfd_idx = client->pollfd_idx;
                    break;
                }
            }
        }

        if (vector_swap_remove(&ctx->pollfds, client->pollfd_idx,
                               sizeof(struct pollfd)) < 0)
            return -1;
    }

    client_ctx_free(client);
    if (vector_swap_remove(&ctx->clients, index, sizeof(struct ClientContext)) <
        0)
        return -1;

    return 0;
}

static void server_ctx_free(struct ServerContext* ctx) {
    for (size_t idx = 0; idx < ctx->clients.length; idx++) {
        struct ClientContext* client =
            vector_get(&ctx->clients, idx, sizeof(struct ClientContext));
        client_ctx_free(client);
    }

    vector_free(&ctx->clients);
    vector_free(&ctx->pollfds);
    close(ctx->server_sock);
}

static volatile bool g_should_stop = false;
static void          on_sigint(int sig) {
    fprintf(stderr, "Caught SIGINT\n");
    signal(sig, SIG_IGN);
    g_should_stop = true;
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
            case 'P': server_port = strtoul(optarg, NULL, 10); break;
            case 'u':
                auth_ctx.username    = malloc(strlen(optarg) + 1);
                auth_ctx.username[0] = '\0';

                strcpy(auth_ctx.username, optarg);
                break;
            case 'p':
                auth_ctx.password    = malloc(strlen(optarg) + 1);
                auth_ctx.password[0] = '\0';

                strcpy(auth_ctx.password, optarg);
                break;
            default: return 1;
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

    signal(SIGPIPE, SIG_IGN);
    signal(SIGINT, on_sigint);

    struct ServerContext server;
    if (server_ctx_init(&server, server_port) < 0)
        return 1;

    if (LOG_LEVEL >= LOG_LEVEL_INFO)
        printf("Starting on port %hu\n", server_port);

    while (!g_should_stop) {
        struct pollfd* pollfds = (struct pollfd*)server.pollfds.data;
        int            ready   = poll(pollfds, server.pollfds.length, 1000);
        if (UNLIKELY(ready == 0))
            continue;
        if (UNLIKELY(ready < 0)) {
            perror("poll failed");
            break;
        }

        // Poll server
        {

            struct pollfd* pollfd = &pollfds[0];
            if (pollfd->revents & POLLIN) {
                server_ctx_accept(&server);
                ready--;
            }
        }

        for (size_t idx = server.clients.length; idx-- > 0 && ready > 0;) {
            struct ClientContext* client =
                vector_get(&server.clients, idx, sizeof(struct ClientContext));

            struct pollfd* pollfd = vector_get(
                &server.pollfds, client->pollfd_idx, sizeof(struct pollfd));

            struct pollfd* remote_pollfd = NULL;
            if (client->remote_pollfd_idx != INVALID_POLLFD)
                remote_pollfd =
                    vector_get(&server.pollfds, client->remote_pollfd_idx,
                               sizeof(struct pollfd));

            short remote_revents =
                remote_pollfd != NULL ? remote_pollfd->revents : 0;
            if (pollfd->revents)
                ready--;
            if (remote_revents)
                ready--;

            if (UNLIKELY(pollfd->revents & (POLLHUP | POLLERR) &&
                         client_ctx_on_hup(client) < 0)) {
                if (LOG_LEVEL >= LOG_LEVEL_DEBUG)
                    printf("Freeing client: on_hup failed\n");
                server_free_client(&server, idx);
                continue;
            }

            if (pollfd->revents & POLLIN) {
                if (client_ctx_on_recv(client, &server.pollfds, &auth_ctx,
                                       pollfd, remote_pollfd) < 0) {
                    if (LOG_LEVEL >= LOG_LEVEL_DEBUG)
                        printf("Freeing client: on_recv failed\n");
                    server_free_client(&server, idx);
                    continue;
                }

                // client_ctx_on_recv may realloc server_ctx->pollfds
                if (client->state == CLIENT_STATE_WAIT_CONNECT) {
                    pollfd = vector_get(&server.pollfds, client->pollfd_idx,
                                        sizeof(struct pollfd));

                    remote_pollfd =
                        vector_get(&server.pollfds, client->remote_pollfd_idx,
                                   sizeof(struct pollfd));
                }
            }

            if (remote_revents & POLLOUT &&
                client_ctx_on_remote_send(client, pollfd, remote_pollfd) < 0) {
                if (LOG_LEVEL >= LOG_LEVEL_DEBUG)
                    printf("Freeing client: on_send_remote failed\n");
                server_free_client(&server, idx);
                continue;
            }

            if (remote_revents & POLLIN &&
                client_ctx_on_remote_recv(client, pollfd, remote_pollfd) < 0) {
                if (LOG_LEVEL >= LOG_LEVEL_DEBUG)
                    printf("Freeing client: on_recv_remote failed\n");
                server_free_client(&server, idx);
                continue;
            }

            if (pollfd->revents & POLLOUT &&
                client_ctx_on_send(client, pollfd, remote_pollfd) < 0) {
                if (LOG_LEVEL >= LOG_LEVEL_DEBUG)
                    printf("Freeing client: on_send failed\n");
                server_free_client(&server, idx);
                continue;
            }

            if (UNLIKELY(remote_revents & (POLLHUP | POLLERR) &&
                         client_ctx_on_remote_hup(client) < 0)) {
                if (LOG_LEVEL >= LOG_LEVEL_DEBUG)
                    printf("Freeing client: on_remote_hup failed\n");
                server_free_client(&server, idx);
                continue;
            }
        }
    }

    if (LOG_LEVEL >= LOG_LEVEL_INFO)
        printf("Cleaning up\n");

    server_ctx_free(&server);

    if (auth_ctx.username != NULL && auth_ctx.password != NULL) {
        free(auth_ctx.username);
        free(auth_ctx.password);
    }

    if (LOG_LEVEL >= LOG_LEVEL_DEBUG)
        printf("Exiting\n");

    return 0;
}
