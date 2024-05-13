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

#define mem_barrier() __asm__ __volatile__("" ::: "memory")

#define die(s) (printf(__FILE__ ":%d: ", __LINE__), perror(s), exit(1))

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

struct entry {
    size_t off;
    size_t len;
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
static inline bool bitmap_index_used(__u8* bitmap, size_t i) {
    mem_barrier();  // XXX: Assert if needed
    return bitmap[i / 8] & (0x01 << (0x07 ^ (i & 0x07)));
}

[[gnu::always_inline]]
static inline void bitmap_alloc(__u8* bitmap, size_t i) {
    bitmap[i / 8] |= (0x01 << (0x07 ^ (i & 0x07)));
    mem_barrier();  // XXX: Assert if needed
}

[[gnu::always_inline]]
static inline void bitmap_free(__u8* bitmap, size_t i) {
    bitmap[i / 8] &= ~(0x01 << (0x07 ^ (i & 0x07)));

    mem_barrier();  // XXX: Assert if needed
}

[[gnu::always_inline]]
inline size_t blocks(size_t size) {
    return size / BLOCK_SIZE + (size % BLOCK_SIZE != 0);
}

struct entry hring_alloc(struct hring* h, size_t size) {
    struct entry e = { 0 };

    if (size > h->sm.blocks * BLOCK_SIZE) {
        return e;
    }

    size_t t = blocks(size);

    for (size_t i = 0, f = 0; i < h->sm.blocks; i++) {
        if (bitmap_index_used(h->sm.bitmap, i)) {
            f = 0;
            continue;
        }

        f += 1;

        if (f == t) {
            for (size_t j = ((i + 1) - f); j < (i + 1); j++)
                bitmap_alloc(h->sm.bitmap, j);

            e.len = size;
            e.off = ((i + 1) - f);
            return e;
        }
    }

    return e;
}

void hring_free(struct hring* h, struct entry e) {
    printf("free entry .off = %lu\n", e.off);

    size_t size = blocks(e.len);

    for (size_t i = 0; i < size; i++) {
        bitmap_free(h->sm.bitmap, e.off + i);
    }
}

[[gnu::always_inline]]
static inline void* hring_deref(struct hring const* h,
                                struct entry const* const e) {
    return h->sm.map + e->off * BLOCK_SIZE;
}

int hring_queue(struct hring* h, struct entry const* const e) {
    size_t next_tail = 0;
    size_t tail = 0;
    size_t index = 0;

    next_tail = tail = *h->sr.tail;
    next_tail++;

    mem_barrier();

    index = tail & *h->sr.ring_mask;

    h->sr.sqes[index].fd = 0;
    h->sr.sqes[index].flags = 0;
    h->sr.sqes[index].opcode = IORING_OP_NOP;
    h->sr.sqes[index].addr = 0;
    h->sr.sqes[index].len = 0;
    h->sr.sqes[index].off = 0;
    h->sr.sqes[index].user_data = (__u64)e->off;

    h->sr.array[index] = index;

    tail = next_tail;

    if (*h->sr.tail != tail) {
        *h->sr.tail = tail;
        mem_barrier();
    }

    if (io_uring_enter(h->fd, 1, 1, IORING_ENTER_GETEVENTS) == -1)
        die("io_uring_enter");

    return 0;
}

void hring_deque(struct hring* h, void (*cb)(struct hring*, size_t, void*)) {
    __u32 head = *h->cr.head;

    do {
        mem_barrier();

        if (head == *h->cr.tail) break;

        struct io_uring_cqe* cqe = &h->cr.cqes[head & *h->cr.ring_mask];

        cb(h, cqe->user_data, h->sm.map + ((__u64)cqe->user_data * BLOCK_SIZE));

        head++;

    } while (true);

    *h->cr.head = head;

    mem_barrier();
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

    __s32 memfd = shm_open("uring_shm", O_CREAT | O_RDWR, S_IRWXU);

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

void pp_bitmap(__u8 const* const bitmap, __u32 blocks) {
    for (__u32 i = 0; i < 1024 * blocks; i++) {
        printf("%.2X", bitmap[i]);

        if (((i + 1) % 32 == 0) || i == (1024 * blocks) - 1) {
            printf("\n");
        } else {
            printf(" ");
        }
    }
}
