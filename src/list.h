#ifndef NANOSOCKS_LIST_H
#define NANOSOCKS_LIST_H

#include <stdlib.h>

struct ListNode {
    struct ListNode* next;
    struct ListNode* prev;
    void*            data;
};

static void* list_node_data(struct ListNode* node) {
    return &node->data;
}

static struct ListNode* list_node_from_data(void* data) {
    return (struct ListNode*)((char*)data - sizeof(struct ListNode*) * 2);
}

struct List {
    struct ListNode* head;
    struct ListNode* tail;
};

static void list_init(struct List* list) {
    list->head = NULL;
    list->tail = NULL;
}

static struct ListNode* list_alloc(struct List* list, size_t size) {
    (void)list;

    size_t           node_size = sizeof(struct ListNode) - sizeof(void*) + size;
    struct ListNode* node      = (struct ListNode*)malloc(node_size);

    node->prev = node->next = NULL;

    return node;
}

static void list_append(struct List* list, struct ListNode* node) {
    if (list->head != NULL) {
        // Add to the tail
        list->tail->next = node;
        node->prev       = list->tail;
        node->next       = NULL;
        list->tail       = node;
    } else {
        // List is empty
        list->head = node;
        list->tail = node;
    }
}

static void list_remove(struct List* list, struct ListNode* node) {
    if (node->prev != NULL)
        node->prev->next = node->next;
    if (node->next != NULL)
        node->next->prev = node->prev;
    if (node == list->head)
        list->head = node->next;
    if (node == list->tail)
        list->tail = node->prev;

    node->prev = node->next = NULL;
}

#endif
