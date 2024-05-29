#pragma once

#include <assert.h>
#include <dirent.h>
#include <fcntl.h>
#include <linux/fs.h>
#include <linux/io_uring.h>
#include <linux/types.h>
#include <linux/unistd.h>
#include <stdatomic.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/uio.h>
#include <sys/wait.h>
#include <unistd.h>

#define _hring_read_once(var) \
    atomic_load_explicit((_Atomic typeof(var)*)&(var), memory_order_relaxed)

#define _hring_smp_load_acquire(p) \
    atomic_load_explicit((_Atomic typeof(*(p))*)(p), memory_order_acquire)

#define _hring_smp_store_release(p, v) \
    atomic_store_explicit((_Atomic typeof(*(p))*)(p), (v), memory_order_release)

#define hring_addr_off(addr) (0xFFFFFFFF & (addr))
#define hring_addr_len(addr) ((addr) >> 32)

typedef __u64 hring_addr_t;

struct hring_mpool {
    __u32 blocks;
    __u8* bitmap;
    void* map;
};

struct sring {
    __u32* khead;
    __u32* ktail;
    __u32 ring_mask;
    __u32 ring_entries;
    __u32* kflags;
    struct io_uring_sqe* sqes;

    __u32 head;
    __u32 tail;
};

struct cring {
    __u32* khead;
    __u32* ktail;
    __u32 ring_mask;
    __u32 ring_entries;
    typeof(__u32*) __pad;
    struct io_uring_cqe* cqes;
};

struct hring {
    int fd;
    __u32 features;

    struct hring_mpool pool;

    union {
        struct sring sr;
        struct cring cr;
    };

    char* id;
};

[[gnu::always_inline]]
static inline ssize_t file_size(int fd) {
    struct stat s;

    if (fstat(fd, &s) < 0) return -1;

    return s.st_size;
}

[[gnu::always_inline]]
inline __s32 __io_uring_setup(__u32 entries, struct io_uring_params* p) {
    return (__s32)syscall(__NR_io_uring_setup, entries, p);
}

[[gnu::always_inline]]
inline __s32 __io_uring_enter(int fd, unsigned int to_submit,
                              unsigned int min_complete, unsigned int flags) {
    return (__s32)syscall(__NR_io_uring_enter, fd, to_submit, min_complete,
                          flags, NULL, 0);
}

[[gnu::always_inline]]
inline __s32 pidfd_getfd(__s32 pidfd, __s32 fd) {
    return (__s32)syscall(SYS_pidfd_getfd, pidfd, fd, 0);
}

[[gnu::always_inline]]
inline __s32 pidfd_open(__s32 ppid) {
    return (__s32)syscall(SYS_pidfd_open, ppid, 0);
}

[[gnu::always_inline]]
inline bool __bitmap_index_used(__u8* bitmap, __u32 i) {
    return bitmap[i / 8] & (0x01 << (i & 0x07));
}

[[gnu::always_inline]]
static inline void __bitmap_alloc(__u8* bitmap, __u32 i) {
    assert(!__bitmap_index_used(bitmap, i));

    __atomic_fetch_or(&bitmap[i / 8], (0x01 << (i & 0x07)), 0);
}

[[gnu::always_inline]]
inline void __bitmap_free(__u8* bitmap, __u32 i) {
    assert(__bitmap_index_used(bitmap, i));

    __atomic_fetch_and(&bitmap[i / 8], ~(0x01 << (i & 0x07)), 0);
}

[[gnu::always_inline]]
static inline __u32 blocks(size_t size) {
    return size / BLOCK_SIZE + (size % BLOCK_SIZE != 0);
}

[[gnu::always_inline]]
static inline __u32 __hring_bitmap_blocks(struct hring const* const h) {
    return h->pool.blocks / 8192 + (h->pool.blocks % 8192 != 0);
}

hring_addr_t hring_mpool_alloc(struct hring* h, size_t size) {
    if (size > BLOCK_SIZE) return 0;

    for (size_t i = 0; i < h->pool.blocks; i++) {
        if (!__bitmap_index_used(h->pool.bitmap, i)) {
            __bitmap_alloc(h->pool.bitmap, i);

            return size << 32 | i;
        }
    }

    return 0;
}

[[gnu::always_inline]]
inline void hring_mpool_free(struct hring* h, hring_addr_t addr) {
    __bitmap_free(h->pool.bitmap, hring_addr_off(addr));
}

[[gnu::always_inline]]
static inline void* hring_deref(struct hring const* h, hring_addr_t addr) {
    return h->pool.map + hring_addr_off(addr) * BLOCK_SIZE;
}

[[gnu::always_inline]]
static inline void __hring_fill_sqe(struct io_uring_sqe* sqe,
                                    hring_addr_t addr) {
    sqe->flags = 0;
    sqe->ioprio = 0;
    sqe->rw_flags = 0;
    sqe->buf_index = 0;
    sqe->personality = 0;
    sqe->file_index = 0;
    sqe->addr3 = 0;
    sqe->__pad2[0] = 0;
    sqe->fd = -1;
    sqe->flags = 0;
    sqe->opcode = IORING_OP_NOP;
    sqe->addr = 0;
    sqe->len = 0;
    sqe->off = 0;
    sqe->user_data = (__u64)addr;
}

// Try to queue addr and return the number of entries in the queue. If the queue
// is full, returns 0.
int hring_try_que(struct hring* h, hring_addr_t addr) {
    struct sring* sr = &h->sr;

    __u32 head = *sr->khead;
    __u32 next = sr->tail + 1;

    __u32 qed = next - head;

    if (qed > sr->ring_entries) return 0;

    struct io_uring_sqe* sqe = &sr->sqes[sr->tail & sr->ring_mask];

    __hring_fill_sqe(sqe, addr);

    sr->tail = next;

    return qed;
}

static __u32 __hring_flush_sr(struct hring* h) {
    struct sring* sr = &h->sr;

    unsigned tail = sr->tail;

    if (sr->head != tail) {
        sr->head = tail;
        *sr->ktail = tail;
    }

    return tail - _hring_read_once(*sr->khead);
}

int hring_submit(struct hring* h, bool force) {
    bool enter = force || _hring_read_once(*h->sr.kflags) &
                              (IORING_SQ_CQ_OVERFLOW | IORING_SQ_TASKRUN);

    if (enter)
        return __io_uring_enter(h->fd, __hring_flush_sr(h), 0,
                                IORING_ENTER_GETEVENTS);
    else
        return 0;
}

void hring_deque(struct hring* h,
                 void (*cb)(struct hring*, struct io_uring_cqe const* const)) {
    struct cring* cr = &h->cr;

    __u32 head = *cr->khead;
    __u32 tail = _hring_smp_load_acquire(cr->ktail);
    __u32 nr = 0;

    do {
        if (head == tail) break;

        struct io_uring_cqe* cqe = &h->cr.cqes[head & h->cr.ring_mask];

        cb(h, cqe);

        head++;
        nr++;

    } while (true);

    if (nr) _hring_smp_store_release(cr->khead, *cr->khead + nr);
}

static int __hring_map_sring(struct hring* h, struct io_uring_params* p) {
    struct sring* sr = &h->sr;

    size_t rsize = p->sq_off.array + p->sq_entries * sizeof(__u32);

    void* sq_ptr = mmap(0, rsize, PROT_READ | PROT_WRITE,
                        MAP_SHARED | MAP_POPULATE, h->fd, IORING_OFF_SQ_RING);

    if (sq_ptr == MAP_FAILED) return -1;

    sr->khead = sq_ptr + p->sq_off.head;
    sr->ktail = sq_ptr + p->sq_off.tail;
    sr->kflags = sq_ptr + p->sq_off.flags;
    sr->ring_mask = *(__u32*)(sq_ptr + p->sq_off.ring_mask);
    sr->ring_entries = *(__u32*)(sq_ptr + p->sq_off.ring_entries);

    if ((sr->sqes = mmap(0, p->sq_entries * sizeof(struct io_uring_sqe),
                         PROT_READ | PROT_WRITE, MAP_SHARED | MAP_POPULATE,
                         h->fd, IORING_OFF_SQES)) == MAP_FAILED) {
        munmap(sq_ptr, rsize);
        return -1;
    };

    return 0;
}

static int _hring_map_cring(struct hring* h, struct io_uring_params* params,
                            __s32 wq_fd) {
    size_t ring_size =
        params->cq_off.cqes + params->cq_entries * sizeof(struct io_uring_cqe);

    void* cq_ptr = mmap(0, ring_size, PROT_READ | PROT_WRITE,
                        MAP_SHARED | MAP_POPULATE, wq_fd, IORING_OFF_CQ_RING);

    if (cq_ptr == MAP_FAILED) return -1;

    h->cr.khead = cq_ptr + params->cq_off.head;
    h->cr.ktail = cq_ptr + params->cq_off.tail;
    h->cr.ring_mask = *(__u32*)(cq_ptr + params->cq_off.ring_mask);
    h->cr.ring_entries = *(__u32*)(cq_ptr + params->cq_off.ring_entries);
    h->cr.cqes = cq_ptr + params->cq_off.cqes;

    return 0;
}

struct __hring_mpool_parts {
    int fd;
    pid_t pid;
    char* name;
};

inline static void __hring_mpool_parts_from_id(
    struct __hring_mpool_parts* parts, char const* const id) {
    sscanf(id, "%*[^:]:%d:%d", &parts->fd,
           &parts->pid);  // trust thy all might parser
}

static inline char* _hring_id_from_mpool_parts(
    struct __hring_mpool_parts const* const parts) {
    int size =
        snprintf(NULL, 0, "%s:%d:%d", parts->name, parts->fd, parts->pid) + 1;

    char* id = malloc(size);  // assume it's good

#ifndef NDEBUG
    assert(snprintf(id, size, "%s:%d:%d", parts->name, parts->fd, parts->pid) ==
           size - 1);
#else
    snprintf(id, size, "%s:%d:%d", parts->name, parts->fd, parts->pid);
#endif

    return id;
}

static inline int _hring_get_mpool_parts_from_name(
    struct __hring_mpool_parts* parts) {
    assert(parts->name != NULL);

    struct dirent* dent;

    DIR* dir = opendir("/dev/shm");

    if (dir == NULL) return -1;

    while ((dent = readdir(dir)) != NULL) {
        if (strstr(dent->d_name, parts->name) != NULL) {
            __hring_mpool_parts_from_id(parts, dent->d_name);
            goto end;
        }
    }

end:
    closedir(dir);

    return 0;
}

static int _hring_mpool_init(struct hring* h, size_t blocks) {
    assert(h->id != NULL);

    struct hring_mpool* pool = &h->pool;

    __s32 shm = shm_open(h->id, O_CREAT | O_TRUNC | O_RDWR, S_IRWXU);

    if (shm < 0) return -1;

    if (ftruncate(shm, BLOCK_SIZE * (blocks + 1)) == -1) goto cleanup;

    if ((h->pool.bitmap =
             mmap(0, BLOCK_SIZE * (blocks + 1), PROT_READ | PROT_WRITE,
                  MAP_SHARED | MAP_POPULATE, shm, 0)) == MAP_FAILED) {
    cleanup:
        shm_unlink(h->id);
        return -1;
    }

    pool->blocks = blocks;
    pool->map = pool->bitmap + BLOCK_SIZE;

    return 0;
}

static int _hring_mpool_attach(struct hring* h) {
    struct hring_mpool* pool = &h->pool;

    __s32 memfd = shm_open(h->id, O_RDWR, 0);  // submitter will unlink
    if (memfd == -1) return -1;

    size_t size = file_size(memfd);

    pool->blocks = blocks(size) - 1;

    if ((pool->bitmap = mmap(NULL, size, PROT_READ | PROT_WRITE, MAP_SHARED,
                             memfd, 0)) == MAP_FAILED) {
        return -1;
    };

    pool->map = pool->bitmap + BLOCK_SIZE;

    return 0;
}

[[gnu::always_inline]]
static inline int _hring_setup(struct hring* h, struct io_uring_params* params,
                               struct __hring_mpool_parts* parts,
                               size_t const blocks) {
    assert(parts->name != NULL);

    if ((h->fd = __io_uring_setup(blocks, params)) < 0) return h->fd;

    parts->pid = getpid();
    parts->fd = h->fd;

    h->id = _hring_id_from_mpool_parts(parts);
    h->features = params->features;

    return 0;
}

int hring_init(struct hring* h, char* name, size_t blocks) {
    struct io_uring_params params = { .flags = IORING_SETUP_SINGLE_ISSUER |
                                               IORING_SETUP_NO_SQARRAY };
    struct __hring_mpool_parts parts = {
        .name = name,
    };

    int ret;

    if ((ret = _hring_setup(h, &params, &parts, blocks)) < 0) goto end;
    if ((ret = _hring_mpool_init(h, blocks)) == -1) goto end;

    ret = __hring_map_sring(h, &params);

end:
    return ret;
}

static inline char* _hring_parts_and_id_from_name(
    struct __hring_mpool_parts* parts) {
    if (_hring_get_mpool_parts_from_name(parts) == -1)
        return NULL;  // FIXME: can fail

    return _hring_id_from_mpool_parts(parts);
}

static inline int _hring_pidfd_get_wq_fd(pid_t pid, __s32 fd) {
    __s32 pid_fd, wq_fd;

    if ((pid_fd = pidfd_open(pid)) == -1) return -1;

    wq_fd = pidfd_getfd(pid_fd, fd);

    close(pid_fd);

    return wq_fd;
}

static inline int _hring_attach_setup(struct hring* h,
                                      struct io_uring_params* p, int wq_fd) {
    int ret;

    p->flags |= IORING_SETUP_ATTACH_WQ;
    p->wq_fd = wq_fd;

    h->fd = ret = __io_uring_setup(h->pool.blocks, p);
    if (ret < 0) return ret;

    h->features = p->features;

    return 0;
}

int hring_attach(struct hring* h, char* name) {
    struct io_uring_params params = { 0 };
    struct __hring_mpool_parts parts = { .name = name };

    __s32 ret;

    if ((h->id = _hring_parts_and_id_from_name(&parts)) == NULL) return -1;

    __s32 wq_fd = ret = _hring_pidfd_get_wq_fd(parts.pid, parts.fd);
    if (ret == -1) {
    cleanup:
        free(h->id);

        return ret;
    }

    if ((ret = _hring_mpool_attach(h)) < 0) goto cleanup;

    if ((ret = _hring_attach_setup(h, &params, wq_fd)) < 0) goto cleanup;

    if ((ret = _hring_map_cring(h, &params, wq_fd)) < 0) goto cleanup;

    return ret;
}

void __pp_bitmap(struct hring const* const h) {
    for (size_t i = 0; i < (BLOCK_SIZE * __hring_bitmap_blocks(h)) >> 5; i++) {
        printf("0x%.8zX:", i);

        for (size_t j = 0; j < 32; j++)
            printf(" %.2X", h->pool.bitmap[j + i * 32]);

        printf("\n");
    }
}

void __pp_addr(struct hring const* const h, hring_addr_t addr) {
    __u32 off = hring_addr_off(addr);

    __u8* data = hring_deref(h, addr);

    for (size_t i = 0; i < BLOCK_SIZE >> 5; i++) {
        printf("0x%.8zX:", off * BLOCK_SIZE + 32 * i);

        for (size_t j = 0; j < 32; j++) printf(" %.2X", data[j + i * 32]);

        printf("\n");
    }
}
