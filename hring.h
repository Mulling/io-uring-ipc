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

#define HRING_SQ 1
#define HRING_CQ 0

#define HRING_IDMAX 256

#define HRING_READ_ONCE(var) \
    atomic_load_explicit((_Atomic __typeof__(var)*)&(var), memory_order_relaxed)

#define __hring_smp_load_acquire(p) \
    atomic_load_explicit((_Atomic __typeof__(*(p))*)(p), memory_order_acquire)

#define __hring_smp_store_release(p, v)                        \
    atomic_store_explicit((_Atomic __typeof__(*(p))*)(p), (v), \
                          memory_order_release)

#define fence() __asm__ __volatile__("" ::: "memory")

#define hring_addr_off(addr) (0xFFFFFFFF & (addr))
#define hring_addr_len(addr) ((addr) >> 32)

typedef __u64 hring_addr_t;

struct smm {
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
    bool kind;
    __u32 features;

    struct smm sm;

    union {
        struct sring sr;
        struct cring cr;
    };

    char id[HRING_IDMAX];
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
static inline bool bitmap_index_used(__u8* bitmap, __u32 i) {
    return bitmap[i / 8] & (0x01 << (i & 0x07));
}

[[gnu::always_inline]]
static inline void bitmap_alloc(__u8* bitmap, __u32 i) {
    assert(!bitmap_index_used(bitmap, i));

    __atomic_fetch_or(&bitmap[i / 8], (0x01 << (i & 0x07)), 0);
}

[[gnu::always_inline]]
static inline void bitmap_free(__u8* bitmap, __u32 i) {
    assert(bitmap_index_used(bitmap, i));

    __atomic_fetch_and(&bitmap[i / 8], ~(0x01 << (i & 0x07)), 0);
}

[[gnu::always_inline]]
static inline __u32 blocks(size_t size) {
    return size / BLOCK_SIZE + (size % BLOCK_SIZE != 0);
}

[[gnu::always_inline]]
static inline __u32 hring_bitmap_blocks(struct hring const* const h) {
    return h->sm.blocks / 8192 + (h->sm.blocks % 8192 != 0);
}

hring_addr_t hring_alloc(struct hring* h, size_t size) {
    if (size > BLOCK_SIZE) return 0;

    for (size_t i = 0; i < h->sm.blocks; i++) {
        if (!bitmap_index_used(h->sm.bitmap, i)) {
            bitmap_alloc(h->sm.bitmap, i);

            return size << 32 | i;
        }
    }

    return 0;
}

void hring_free(struct hring* h, hring_addr_t addr) {
    bitmap_free(h->sm.bitmap, hring_addr_off(addr));
}

[[gnu::always_inline]]
static inline void* hring_deref(struct hring const* h, hring_addr_t addr) {
    return h->sm.map + hring_addr_off(addr) * BLOCK_SIZE;
}

int hring_try_que(struct hring* h, hring_addr_t addr) {
    struct sring* sr = &h->sr;

    __u32 head = *sr->khead;
    __u32 next = sr->tail + 1;

    __u32 qed = next - head;

    if (qed > sr->ring_entries) return 0;

    struct io_uring_sqe* sqe = &sr->sqes[sr->tail & sr->ring_mask];

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

    return tail - HRING_READ_ONCE(*sr->khead);
}

int hring_submit(struct hring* h, bool force) {
    bool enter = force || HRING_READ_ONCE(*h->sr.kflags) &
                              (IORING_SQ_CQ_OVERFLOW | IORING_SQ_TASKRUN);

    if (enter)
        return __io_uring_enter(h->fd, __hring_flush_sr(h), 0,
                                IORING_ENTER_GETEVENTS);
    else
        return 0;
}

int hring_queue(struct hring* h, hring_addr_t e) {
    __u32 tail = 0;
    __u32 index = 0;

    tail = *h->sr.ktail;

    fence();

    index = tail & h->sr.ring_mask;

    h->sr.sqes[index].fd = -1;
    h->sr.sqes[index].flags = 0;
    h->sr.sqes[index].opcode = IORING_OP_NOP;
    h->sr.sqes[index].addr = 0;
    h->sr.sqes[index].len = 0;
    h->sr.sqes[index].off = 0;
    h->sr.sqes[index].user_data = e;

    tail++;

    if (*h->sr.ktail != tail) {
        *h->sr.ktail = tail;
        fence();
    }

    __u32 qed = tail - *h->sr.khead;

    if (qed < 32) return 0;

    return __io_uring_enter(h->fd, qed, 0, IORING_ENTER_GETEVENTS);
}

void hring_deque(struct hring* h,
                 void (*cb)(struct hring*, struct io_uring_cqe const* const)) {
    struct cring* cr = &h->cr;

    __u32 head = *cr->khead;
    __u32 tail = __hring_smp_load_acquire(cr->ktail);
    __u32 nr = 0;

    do {
        fence();

        if (head == tail) break;

        struct io_uring_cqe* cqe = &h->cr.cqes[head & h->cr.ring_mask];

        cb(h, cqe);

        head++;
        nr++;

    } while (true);

    if (nr) __hring_smp_store_release(cr->khead, *cr->khead + nr);
}

static int mmap_sq(struct hring* h, struct io_uring_params* p) {
    assert(h->kind == HRING_SQ);

    struct sring* sr = &h->sr;

    size_t rsize = p->sq_off.array + p->sq_entries * sizeof(__u32);

    void* sq_ptr = mmap(0, rsize, PROT_READ | PROT_WRITE,
                        MAP_SHARED | MAP_POPULATE, h->fd, IORING_OFF_SQ_RING);

    if (sq_ptr == MAP_FAILED) return -1;

    sr->khead = sq_ptr + p->sq_off.head;
    sr->ktail = sq_ptr + p->sq_off.tail;

    sr->ring_mask = *(__u32*)(sq_ptr + p->sq_off.ring_mask);
    sr->ring_entries = *(__u32*)(sq_ptr + p->sq_off.ring_entries);

    sr->kflags = sq_ptr + p->sq_off.flags;

    if ((sr->sqes = mmap(0, p->sq_entries * sizeof(struct io_uring_sqe),
                         PROT_READ | PROT_WRITE, MAP_SHARED | MAP_POPULATE,
                         h->fd, IORING_OFF_SQES)) == MAP_FAILED)
        return -1;

    return 0;
}

static int mmap_cq(struct hring* h, struct io_uring_params* params, __s32 fd) {
    if (fd != 0) {
        params->flags |= IORING_SETUP_ATTACH_WQ;
        params->wq_fd = fd;

        int ret = __io_uring_setup(h->sm.blocks, params);

        if (ret < -1) return ret;

        h->fd = ret;
        h->features = params->features;
    }

    size_t ring_size =
        params->cq_off.cqes + params->cq_entries * sizeof(struct io_uring_cqe);

    void* cq_ptr = mmap(0, ring_size, PROT_READ | PROT_WRITE,
                        MAP_SHARED | MAP_POPULATE, fd, IORING_OFF_CQ_RING);

    if (cq_ptr == MAP_FAILED) return -1;

    h->cr.khead = cq_ptr + params->cq_off.head;
    h->cr.ktail = cq_ptr + params->cq_off.tail;
    h->cr.ring_mask = *(__u32*)(cq_ptr + params->cq_off.ring_mask);
    h->cr.ring_entries = *(__u32*)(cq_ptr + params->cq_off.ring_entries);
    h->cr.cqes = cq_ptr + params->cq_off.cqes;

    return 0;
}

struct hring_smm_parts {
    int uring_fd;
    pid_t pid;
    char name[32];
};

static int hring_parts_from_id(struct hring_smm_parts* parts,
                               char const* const id) {
    // Trust thy all might parser
    sscanf(id, "%[^:]:%d:%d", parts->name, &parts->uring_fd, &parts->pid);

    return 0;
}

static int hring_make_id(struct hring_smm_parts const* const parts, char* dst,
                         size_t size) {
    return snprintf(dst, size, "%s:%d:%d", parts->name, parts->uring_fd,
                    parts->pid);
}

int hring_get_id_parts_mathing_name(struct hring_smm_parts* parts,
                                    char const* const name) {
    struct dirent* dent;

    DIR* dir = opendir("/dev/shm");

    if (dir == NULL) return -1;

    while ((dent = readdir(dir)) != NULL) {
        if (strstr(dent->d_name, name) != NULL) {
            hring_parts_from_id(parts, dent->d_name);
            goto end;
        }
    }

end:
    closedir(dir);

    return 0;
}

static int smm_init(struct smm* sm, char const* const id, size_t blocks) {
    sm->blocks = blocks;

    __s32 memfd = shm_open(id, O_CREAT | O_TRUNC | O_RDWR, S_IRWXU);

    if (memfd == -1) return -1;

    if (ftruncate(memfd, BLOCK_SIZE * (blocks + 1)) == -1) return -1;

    if ((sm->bitmap = mmap(0, BLOCK_SIZE * (blocks + 1), PROT_READ | PROT_WRITE,
                           MAP_SHARED | MAP_POPULATE, memfd, 0)) == MAP_FAILED)
        return -1;

    if (!memset(sm->bitmap, 0, BLOCK_SIZE * blocks)) return -1;

    sm->map = sm->bitmap + BLOCK_SIZE;

    return 0;
}

static int smm_from_file(char const* const file, struct smm* sm) {
    __s32 memfd = shm_open(file, O_RDWR, 0);

    if (memfd == -1) return -1;

    size_t size = file_size(memfd);

    sm->blocks = blocks(size) - 1;

    if (memfd == -1) return -1;

    sm->bitmap = mmap(NULL, file_size(memfd), PROT_READ | PROT_WRITE,
                      MAP_SHARED, memfd, 0);

    if (sm->bitmap == MAP_FAILED) return -1;

    sm->map = sm->bitmap + BLOCK_SIZE;

    return 0;
}

int hring_init(struct hring* h, char const* const name, size_t blocks) {
    struct io_uring_params params = { .flags = IORING_SETUP_SINGLE_ISSUER |
                                               IORING_SETUP_NO_SQARRAY };

    int ret = h->fd = __io_uring_setup(blocks, &params);

    if (ret < 0) return ret;

    h->kind = HRING_SQ;
    h->features = params.features;

    struct hring_smm_parts parts = {
        .pid = getpid(),
        .uring_fd = h->fd,
    };

    memcpy(parts.name, name, strlen(name) + 1);

    hring_make_id(&parts, h->id, HRING_IDMAX);

    smm_init(&h->sm, h->id, blocks);
    mmap_sq(h, &params);

    return 0;
}

int hring_attatch(struct hring* h, char const* const name) {
    struct io_uring_params params = { 0 };
    struct hring_smm_parts parts = { 0 };

    hring_get_id_parts_mathing_name(&parts, name);

    hring_make_id(&parts, h->id, HRING_IDMAX);

    __s32 pidfd = pidfd_open(parts.pid);
    if (pidfd == -1) return -1;

    __s32 wq_fd = pidfd_getfd(pidfd, parts.uring_fd);
    if (wq_fd == -1) return -1;

    h->kind = HRING_CQ;

    if (smm_from_file(h->id, &h->sm) == -1) return 1;

    return mmap_cq(h, &params, wq_fd);
}

void pp_bitmap(struct hring const* const h) {
    for (size_t i = 0; i < (BLOCK_SIZE * hring_bitmap_blocks(h)) >> 5; i++) {
        printf("0x%.8zX:", i);

        for (size_t j = 0; j < 32; j++) {
            printf(" %.2X", h->sm.bitmap[j + i * 32]);
        }

        printf("\n");
    }
}

void pp_addr(struct hring const* const h, hring_addr_t addr) {
    __u32 off = hring_addr_off(addr);

    __u8* data = hring_deref(h, addr);

    for (size_t i = 0; i < BLOCK_SIZE >> 5; i++) {
        printf("0x%.8zX:", off * BLOCK_SIZE + 32 * i);

        for (size_t j = 0; j < 32; j++) {
            printf(" %.2X", data[j + i * 32]);
        }

        printf("\n");
    }
}
