#ifndef NANOSOCKS_CLIENT_H
#define NANOSOCKS_CLIENT_H

#include <stdbool.h>

#include <ares.h>

static const size_t CLIENT_BUFFER_SIZE = 1 << 20;

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

int         client_ctx_init(struct ClientContext* client, int sock,
                            struct SharedClientContext* shared_ctx);
const char* client_ctx_state(struct ClientContext* client);
void        client_ctx_get_address(struct ClientContext* client, char* buffer,
                                   size_t size);
void client_ctx_get_remote_address(struct ClientContext* client, char* buffer,
                                   size_t size);
void client_ctx_free(struct ClientContext* client);

int  client_ctx_on_recv(struct ClientContext* client, int epoll_fd,
                        struct AuthenticationContext* auth_ctx);
int  client_ctx_on_remote_recv(struct ClientContext* client);
int  client_ctx_on_send(struct ClientContext* client);
int  client_ctx_on_remote_send(struct ClientContext* client);

#endif
