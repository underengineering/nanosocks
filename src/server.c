#include <arpa/inet.h>
#include <errno.h>
#include <netinet/tcp.h>
#include <stdio.h>
#include <string.h>
#include <sys/epoll.h>
#include <sys/fcntl.h>
#include <sys/signalfd.h>
#include <unistd.h>

#include "log.h"
#include "server.h"

int server_ctx_init(struct ServerContext* server, uint16_t port,
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

int server_ctx_setup_signal_handler(const struct ServerContext* server,
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

int server_ctx_accept(struct ServerContext* server) {
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

int server_free_client(struct ServerContext* server,
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

void server_ctx_free(struct ServerContext* server) {
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
