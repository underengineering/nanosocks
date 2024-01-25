#include <errno.h>
#include <netinet/in.h>
#include <poll.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define MIN(a, b) ((a) < (b) ? (a) : (b))
#define MAX(a, b) ((a) > (b) ? (a) : (b))

#define LIKELY(x)   __builtin_expect(!!(x), 1)
#define UNLIKELY(x) __builtin_expect(!!(x), 0)

static const int    INVALID_SOCKFD = -1;
static const size_t INVALID_POLLFD = (size_t)-1;

static ssize_t      recv_all(int sock, void* buffer, size_t size, int flags) {
    ssize_t read_total = 0;
    do {
        ssize_t read =
            recv(sock, (char*)buffer + read_total, size - read_total, flags);
        if (read <= 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK)
                break;

            return read;
        }

        read_total += read;
    } while ((size_t)read_total < size);

    return read_total;
}

static ssize_t send_all(int sock, const void* buffer, size_t size, int flags) {
    ssize_t sent_total = 0;
    do {
        ssize_t sent = send(sock, (const char*)buffer + sent_total,
                            size - sent_total, flags);
        if (sent <= 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK)
                break;

            return sent;
        }

        sent_total += sent;
    } while ((size_t)sent_total < size);

    return sent_total;
}

static void memswap(void* data1, void* data2, size_t size) {
    char* d1 = data1;
    char* d2 = data2;
    while (size--) {
        char tmp = *d1;
        *d1++    = *d2;
        *d2++    = tmp;
    }
}

struct Vector {
    size_t length;
    void*  data;
};

static int vector_init(struct Vector* vec, size_t length, size_t size) {
    vec->length = length;
    if (length == 0) {
        vec->data = NULL;
        return 0;
    }

    if ((vec->data = calloc(length, size)) == NULL)
        return -1;

    return 0;
}

static void* vector_get(struct Vector* vec, size_t index, size_t size) {
    return (char*)vec->data + index * size;
}

static int vector_resize(struct Vector* vec, size_t length, size_t size) {
    if (UNLIKELY(length == 0)) {
        if (vec->data != NULL)
            free(vec->data);

        vec->length = 0;
        vec->data   = NULL;
        return 0;
    }

    if (UNLIKELY(vec->data == NULL))
        return vector_init(vec, length, size);

    void* data = realloc(vec->data, length * size);
    if (UNLIKELY(data == NULL))
        return -1;

    vec->length = length;
    vec->data   = data;

    return 0;
}

static void* vector_alloc(struct Vector* vec, size_t size) {
    size_t offset = vec->length;
    if (UNLIKELY(vector_resize(vec, vec->length + 1, size) < 0))
        return NULL;

    return (char*)vec->data + size * offset;
}

static int vector_push(struct Vector* vec, const void* data, size_t size) {
    void* dest = vector_alloc(vec, size);
    memcpy(dest, data, size);

    return 0;
}

static int vector_remove(struct Vector* vec, size_t index, size_t size) {
    if (index < vec->length - 1) {
        // Copy data after remove_offset over removed item
        size_t remove_offset = index * size;
        size_t items_to_copy = vec->length - index - 1;
        memcpy((char*)vec->data + remove_offset,
               (const char*)vec->data + remove_offset + size,
               items_to_copy * size);
    }

    return vector_resize(vec, vec->length - 1, size);
}

static int vector_swap_remove(struct Vector* vec, size_t index, size_t size) {
    char* data   = vec->data;
    int   status = 0;
    if (index < vec->length - 1) {
        // Swap with the last item
        size_t remove_offset = index * size;
        size_t end_offset    = vec->length * size - size;
        memswap(data + remove_offset, data + end_offset, size);
        status = 1;
    }

    if (UNLIKELY(vector_resize(vec, vec->length - 1, size) < 0))
        return -1;

    return status;
}

static void vector_free(struct Vector* vec) {
    free(vec->data);
}

struct RingBuffer {
    size_t head;
    size_t tail;
    size_t capacity;
    void*  data;
};

static void ring_buffer_init(struct RingBuffer* buf, size_t capacity) {
    buf->head     = 0;
    buf->tail     = 0;
    buf->capacity = capacity;
    buf->data     = malloc(capacity);
}

static size_t ring_buffer_size(struct RingBuffer* buf) {
    if (buf->tail >= buf->head) {
        return buf->tail - buf->head;
    }

    size_t to_end     = buf->capacity - buf->head;
    size_t from_start = buf->tail;
    return to_end + from_start;
}

static bool ring_buffer_is_trivially_allocatable(struct RingBuffer* buf,
                                                 size_t             size) {
    if (buf->tail >= buf->head) {
        // >= [HEAD<---->TAIL====]
        // <  [====HEAD<---->TAIL]
        return buf->capacity - buf->tail >= size;
    }

    // >= [<--->TAIL====HEAD]
    // <  [<-->TAIL=HEAD<-->]
    return buf->head - buf->tail >= size;
}

static bool ring_buffer_is_trivially_copyable(struct RingBuffer* buf,
                                              size_t             size) {
    if (buf->tail >= buf->head)
        return true;

    size_t to_end = buf->capacity - buf->head;
    return to_end >= size;
}

static void ring_buffer_grow(struct RingBuffer* buf, size_t size) {
    if (buf->tail >= buf->head) {
        size_t end_len = buf->capacity - buf->tail;
        if (size < end_len) {
            // Move to the end
            buf->tail += size;
            return;
        }

        // Start over
        buf->tail = size - end_len;
    } else {
        buf->tail += size;
    }
}

static void ring_buffer_shrink(struct RingBuffer* buf, size_t size) {
    if (buf->tail >= buf->head) {
        // Move to tail
        buf->head += size;
    } else {
        size_t to_end = buf->capacity - buf->head;
        if (size < to_end) {
            // Move to the end
            buf->head += size;
            return;
        }

        // Start over
        buf->head = size - to_end;
    }

    if (buf->head == buf->tail) {
        // Reset head&tail to increase trivial copy&alloc rate
        buf->head = buf->tail = 0;
    }
}

static void ring_buffer_fill(struct RingBuffer* buf, const void* src,
                             size_t size) {
    char* dest = buf->data;
    if (buf->tail >= buf->head) {
        size_t to_end = buf->capacity - buf->tail;
        if (size < to_end) {
            memcpy(dest + buf->tail, src, size);
        } else {
            memcpy(dest + buf->tail, src, to_end);

            size_t from_start = MIN(buf->head, size - to_end);
            memcpy(dest, (const char*)src + to_end, from_start);
        }
    } else {
        memcpy(dest + buf->tail, src, size);
    }

    ring_buffer_grow(buf, size);
}

static void ring_buffer_copy(struct RingBuffer* buf, void* dest, size_t size) {
    const char* src = buf->data;
    if (buf->tail >= buf->head) {
        memcpy(dest, src + buf->head, size);
    } else {
        size_t to_end = buf->capacity - buf->head;
        if (size < to_end) {
            memcpy(dest, src + buf->head, size);
        } else {
            memcpy(dest, src + buf->head, to_end);

            size_t from_start = MIN(buf->tail, size - to_end);
            memcpy((char*)dest + to_end, src, from_start);
        }
    }
}

static void ring_buffer_free(struct RingBuffer* buf) {
    free(buf->data);
}

struct DenseMapEntry {
    size_t key;
    size_t next_idx;
    void*  data;
};

static const size_t INVALID_ENTRY_IDX = (size_t)-1;
struct DenseMap {
    struct Vector buckets;
    struct Vector entries;
};

static void dense_map_init(struct DenseMap* map, size_t bucket_count) {
    vector_init(&map->buckets, bucket_count, sizeof(size_t));
    vector_init(&map->entries, 0, 0);

    memset(map->buckets.data, -1, bucket_count * sizeof(size_t));
}

static size_t dense_map_hash(size_t key) {
    return key;
}

static void dense_map_add(struct DenseMap* map, size_t key, void* data) {
    size_t  bucket_idx = dense_map_hash(key) % map->buckets.length;
    size_t* entry_idx_ptr =
        vector_get(&map->buckets, bucket_idx, sizeof(size_t));
    size_t entry_idx = *entry_idx_ptr;
    if (entry_idx == INVALID_ENTRY_IDX) {
        // Allocate a new entry
        *entry_idx_ptr = map->entries.length;
        struct DenseMapEntry* entry =
            vector_alloc(&map->entries, sizeof(struct DenseMapEntry));
        entry->key      = key;
        entry->next_idx = INVALID_ENTRY_IDX;
        entry->data     = data;
    } else {
        // Traverse to the tail
        struct DenseMapEntry* tail = NULL;
        while (1) {
            tail = vector_get(&map->entries, entry_idx,
                              sizeof(struct DenseMapEntry));
            if (tail->next_idx == INVALID_ENTRY_IDX) {
                entry_idx = tail->next_idx;
                break;
            }

            entry_idx = tail->next_idx;
        }

        // Link new entry with tail
        tail->next_idx = map->entries.length;

        // Allocate a new entry
        struct DenseMapEntry* entry =
            vector_alloc(&map->entries, sizeof(struct DenseMapEntry));
        entry->key      = key;
        entry->next_idx = INVALID_ENTRY_IDX;
        entry->data     = data;
    }
}

static struct DenseMapEntry* dense_map_find(struct DenseMap* map, size_t key) {
    size_t bucket_idx = dense_map_hash(key) % map->buckets.length;
    size_t entry_idx =
        *(size_t*)vector_get(&map->buckets, bucket_idx, sizeof(size_t));
    if (entry_idx == INVALID_ENTRY_IDX)
        return NULL;

    // Traverse entries
    struct DenseMapEntry* entry = NULL;
    while (1) {
        entry =
            vector_get(&map->entries, entry_idx, sizeof(struct DenseMapEntry));
        if (entry->key == key)
            return entry;

        if (entry->next_idx == INVALID_ENTRY_IDX)
            break;

        entry_idx = entry->next_idx;
    }

    return NULL;
}

static void* dense_map_get(struct DenseMap* map, size_t key) {
    struct DenseMapEntry* entry = dense_map_find(map, key);
    if (entry == NULL)
        return NULL;

    return entry->data;
}

static void* dense_map_remove(struct DenseMap* map, size_t key) {
    size_t bucket_idx = dense_map_hash(key) % map->buckets.length;
    size_t head_entry_idx =
        *(size_t*)vector_get(&map->buckets, bucket_idx, sizeof(size_t));
    if (head_entry_idx == INVALID_ENTRY_IDX)
        return NULL;

    // Traverse entries
    struct DenseMapEntry* entry           = NULL;
    size_t                found_entry_idx = head_entry_idx;
    size_t                prev_entry_idx  = INVALID_ENTRY_IDX;
    while (1) {
        entry = vector_get(&map->entries, found_entry_idx,
                           sizeof(struct DenseMapEntry));
        if (entry->key == key)
            break;

        if (entry->next_idx == INVALID_ENTRY_IDX)
            return NULL;

        prev_entry_idx  = found_entry_idx;
        found_entry_idx = entry->next_idx;
    }

    // Save data
    size_t next_idx = entry->next_idx;
    void*  data     = entry->data;

    // Remove this entry
    size_t old_end_idx = map->entries.length - 1;
    vector_swap_remove(&map->entries, found_entry_idx,
                       sizeof(struct DenseMapEntry));

    // If not on the end
    if (found_entry_idx != old_end_idx) {
        // Fix swapped next_idx
        bool found = false;
        for (size_t idx = 0; idx < map->entries.length; idx++) {
            struct DenseMapEntry* entry =
                vector_get(&map->entries, idx, sizeof(struct DenseMapEntry));
            if (entry->next_idx == old_end_idx) {
                entry->next_idx = found_entry_idx;
                found           = true;
                break;
            }
        }

        if (!found) {
            for (size_t idx = 0; idx < map->buckets.length; idx++) {
                size_t* entry_idx_ptr =
                    (size_t*)vector_get(&map->buckets, idx, sizeof(size_t));
                if (*entry_idx_ptr == old_end_idx) {
                    *entry_idx_ptr = found_entry_idx;
                    break;
                }
            }
        }

        if (next_idx == old_end_idx)
            next_idx = found_entry_idx;
    }

    if (prev_entry_idx != INVALID_ENTRY_IDX) {
        // Link previous entry with next
        struct DenseMapEntry* prev_entry = vector_get(
            &map->entries, prev_entry_idx, sizeof(struct DenseMapEntry));
        prev_entry->next_idx = next_idx;
    } else if (found_entry_idx == head_entry_idx) {
        // Link next entry to bucket
        *(size_t*)vector_get(&map->buckets, bucket_idx,
                             sizeof(struct DenseMapEntry)) = next_idx;
    }

    return data;
}

static void dense_map_free(struct DenseMap* map) {
    vector_free(&map->buckets);
    vector_free(&map->entries);
}
