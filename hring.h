#pragma once

#include <assert.h>
#include <fcntl.h>
#include <linux/fs.h>
#include <linux/io_uring.h>
#include <linux/types.h>
#include <linux/unistd.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/uio.h>
#include <sys/wait.h>
#include <unistd.h>

#define HRING_SQ 1
#define HRING_CQ 0

#define fence() __asm__ __volatile__("" ::: "memory")

#define hring_addr_off(addr) (0xFFFFFFFF & (addr))
#define hring_addr_len(addr) ((addr) >> 32)

#define die(s) (printf(__FILE__ ":%d: ", __LINE__), perror(s), exit(1))

typedef __u64 hring_addr_t;

struct smm {
    __u32 blocks;
    __u8* bitmap;
    void* map;
};

struct sring {
    __u32* head;
    __u32* tail;
    __u32* ring_mask;
    __u32* ring_entries;
    __u32* flags;
    __u32* array;
    struct io_uring_sqe* sqes;
};

struct cring {
    __u32* head;
    __u32* tail;
    __u32* ring_mask;
    __u32* ring_entries;
    struct io_uring_cqe* cqes;
};

struct hring {
    int fd;
    bool kind;

    struct smm sm;

    union {
        struct sring sr;
        struct cring cr;
    };
};

[[gnu::always_inline]]
static inline size_t file_size(int fd) {
    struct stat s;

    if (fstat(fd, &s) < 0) die("stat");

    return s.st_size;
}

[[gnu::always_inline]]
inline __s32 io_uring_setup(__u32 entries, struct io_uring_params* p) {
    return (__s32)syscall(__NR_io_uring_setup, entries, p);
}

[[gnu::always_inline]]
inline __s32 io_uring_enter(int fd, unsigned int to_submit,
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
    return bitmap[i / 8] & (0x01 << (0x07 ^ (i & 0x07)));
}

[[gnu::always_inline]]
static inline void bitmap_alloc(__u8* bitmap, __u32 i) {
    assert(!bitmap_index_used(bitmap, i));

    __atomic_fetch_or(&bitmap[i / 8], (0x01 << (0x07 ^ (i & 0x07))), 0);
}

[[gnu::always_inline]]
static inline void bitmap_free(__u8* bitmap, __u32 i) {
    assert(bitmap_index_used(bitmap, i));

    __atomic_fetch_and(&bitmap[i / 8], ~(0x01 << (0x07 ^ (i & 0x07))), 0);
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

int hring_queue(struct hring* h, hring_addr_t e) {
    register __u32 tail = 0;
    register __u32 index = 0;

    tail = *h->sr.tail;

    fence();

    index = tail & *h->sr.ring_mask;

    // h->sr.sqes[index].fd = 0;
    // h->sr.sqes[index].flags = 0;
    h->sr.sqes[index].opcode = IORING_OP_NOP;
    // h->sr.sqes[index].addr = 0;
    // h->sr.sqes[index].len = 0;
    // h->sr.sqes[index].off = 0;
    h->sr.sqes[index].user_data = e;

    h->sr.array[index] = index;

    tail++;

    if (*h->sr.tail != tail) {
        *h->sr.tail = tail;
        fence();
    }

    __s64 qed = llabs((__s64)*h->sr.head - (__s64)tail);

    if (qed < 32) return 0;

    if (io_uring_enter(h->fd, qed, 0, IORING_ENTER_GETEVENTS) == -1)
        die("io_uring_enter");

    return 0;
}

void hring_deque(struct hring* h, void (*cb)(struct hring*, hring_addr_t)) {
    register __u32 head = *h->cr.head;

    do {
        fence();

        if (head == *h->cr.tail) break;

        struct io_uring_cqe* cqe = &h->cr.cqes[head & *h->cr.ring_mask];

        cb(h, cqe->user_data);

        head++;

    } while (true);

    *h->cr.head = head;

    fence();
}

static void mmap_sq(struct hring* h, struct io_uring_params* params) {
    assert(h->kind == HRING_SQ);

    __s32 ring_size = params->sq_off.array + params->sq_entries * sizeof(__u32);

    void* sq_ptr = mmap(0, ring_size, PROT_READ | PROT_WRITE,
                        MAP_SHARED | MAP_POPULATE, h->fd, IORING_OFF_SQ_RING);

    if (sq_ptr == MAP_FAILED) die("mmap");

    h->sr.head = sq_ptr + params->sq_off.head;
    h->sr.tail = sq_ptr + params->sq_off.tail;

    h->sr.ring_mask = sq_ptr + params->sq_off.ring_mask;
    h->sr.ring_entries = sq_ptr + params->sq_off.ring_entries;

    h->sr.flags = sq_ptr + params->sq_off.flags;
    h->sr.array = sq_ptr + params->sq_off.array;

    if ((h->sr.sqes = mmap(0, params->sq_entries * sizeof(struct io_uring_sqe),
                           PROT_READ | PROT_WRITE, MAP_SHARED | MAP_POPULATE,
                           h->fd, IORING_OFF_SQES)) == MAP_FAILED)
        die("mmap");
}

static void mmap_cq(struct hring* h, struct io_uring_params* params, __s32 fd) {
    if (fd != 0) {
        params->flags |= IORING_SETUP_ATTACH_WQ;
        params->wq_fd = fd;

        if ((h->fd = io_uring_setup(h->sm.blocks, params)) == -1)
            die("io_uring_setup");
    }

    size_t ring_size =
        params->cq_off.cqes + params->cq_entries * sizeof(struct io_uring_cqe);

    void* cq_ptr = mmap(0, ring_size, PROT_READ | PROT_WRITE,
                        MAP_SHARED | MAP_POPULATE, fd, IORING_OFF_CQ_RING);

    if (cq_ptr == MAP_FAILED) die("mmap");

    h->cr.head = cq_ptr + params->cq_off.head;
    h->cr.tail = cq_ptr + params->cq_off.tail;
    h->cr.ring_mask = cq_ptr + params->cq_off.ring_mask;
    h->cr.ring_entries = cq_ptr + params->cq_off.ring_entries;
    h->cr.cqes = cq_ptr + params->cq_off.cqes;
}

static struct smm smm_init(size_t blocks) {
    struct smm sm = { .blocks = blocks };

    __s32 memfd = shm_open("uring_shm", O_CREAT | O_TRUNC | O_RDWR, S_IRWXU);

    if (memfd == -1) die("shm_open");

    if (ftruncate(memfd, BLOCK_SIZE * (blocks + 1)) == -1) die("ftruncate");

    if ((sm.bitmap = mmap(0, BLOCK_SIZE * (blocks + 1), PROT_READ | PROT_WRITE,
                          MAP_SHARED | MAP_POPULATE, memfd, 0)) == MAP_FAILED)
        die("mmap");

    if (!memset(sm.bitmap, 0, BLOCK_SIZE * blocks)) die("memset");

    sm.map = sm.bitmap + BLOCK_SIZE;

    return sm;
}

static struct smm smm_from_file(char const* const file) {
    struct smm sm = { 0 };

    __s32 memfd = shm_open(file, O_RDWR, 0);

    size_t size = file_size(memfd);

    sm.blocks = blocks(size) - 1;

    if (memfd == -1) die("shm_open");

    sm.bitmap = mmap(NULL, file_size(memfd), PROT_READ | PROT_WRITE, MAP_SHARED,
                     memfd, 0);

    if (sm.bitmap == MAP_FAILED) die("mmap");

    sm.map = sm.bitmap + BLOCK_SIZE;

    return sm;
}

void hring_init(struct hring* h, size_t blocks) {
    struct io_uring_params params = { .flags = IORING_SETUP_SINGLE_ISSUER };

    if ((h->fd = io_uring_setup(blocks, &params)) == -1) die("io_uring_setup");

    h->kind = HRING_SQ;
    h->sm = smm_init(blocks);

    mmap_sq(h, &params);
}

void hring_attatch(struct hring* h, char const* const file, __s32 fd) {
    struct io_uring_params params = { 0 };

    h->kind = HRING_CQ;
    h->sm = smm_from_file(file);

    mmap_cq(h, &params, fd);
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
