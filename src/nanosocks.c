#include <arpa/inet.h>
#include <signal.h>
#include <stdbool.h>
#include <sys/epoll.h>

#include <ares.h>

#include "client.h"
#include "list.h"
#include "log.h"
#include "server.h"
#include "util.h"

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
