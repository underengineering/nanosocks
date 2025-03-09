#ifndef NANOSOCKS_SERVER_H
#define NANOSOCKS_SERVER_H

#include <ares.h>

#include "list.h"
#include "client.h"

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

int  server_ctx_init(struct ServerContext* server, uint16_t port,
                     ares_channel_t* ares_channel);

int  server_ctx_setup_signal_handler(const struct ServerContext* server,
                                     sigset_t                    mask);

int  server_ctx_accept(struct ServerContext* server);

int  server_free_client(struct ServerContext* server,
                        struct ListNode*      client_node);

void server_ctx_free(struct ServerContext* server);

#endif
