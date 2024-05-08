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

#define die(s) (perror(s), exit(1))

struct mm {
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

    struct mm shm;

    union {
        struct sring sr;
        struct cring cr;
    };
};

struct msg {
    __u16 len;
    __u8 msg[];
};

[[gnu::always_inline]]
inline size_t file_size(int fd) {
    struct stat s;

    if (fstat(fd, &s) < 0) die("stat");

    return s.st_size;
}

[[gnu::always_inline]]
inline __s32 io_uring_setup(__u32 entries, struct io_uring_params* p) {
    return (int)syscall(__NR_io_uring_setup, entries, p);
}

[[gnu::always_inline]]
inline __s32 io_uring_enter(int fd, unsigned int to_submit,
                            unsigned int min_complete, unsigned int flags) {
    return (int)syscall(__NR_io_uring_enter, fd, to_submit, min_complete, flags,
                        NULL, 0);
}

[[gnu::always_inline]]
inline __s32 pidfd_getfd(__s32 pidfd, __s32 fd) {
    return (__s32)syscall(SYS_pidfd_getfd, pidfd, fd, 0);
}

[[gnu::always_inline]]
inline __s32 pidfd_open(__s32 ppid) {
    return (__s32)syscall(SYS_pidfd_open, ppid, 0);
}

struct entry {
    size_t off;
    size_t len;
};

[[gnu::always_inline]]
inline bool bitmap_index_used(struct mm* shm, size_t i) {
    __u8* bitmap = shm->bitmap;

    mem_barrier();
    return bitmap[i / 8] & (0x01 << (0x07 ^ (i & 0x07)));
}

[[gnu::always_inline]]
inline void bitmap_alloc(struct mm* shm, size_t i) {
    __u8* bitmap = shm->bitmap;

    mem_barrier();
    bitmap[i / 8] |= (0x01 << (0x07 ^ (i & 0x07)));
}

[[gnu::always_inline]]
inline void bitmap_free(struct mm* shm, struct entry e) {
    __u8* bitmap = shm->bitmap;

    size_t size = e.len / BLOCK_SIZE;
    if (size % BLOCK_SIZE) size++;

    // TODO: Cleanup

    for (size_t i = e.off / BLOCK_SIZE; i < size + e.off / BLOCK_SIZE; i++) {
        bitmap[i / 8] &= ~(0x01 << (0x07 ^ (i - 1 & 0x07)));
    }
}

struct entry shmalloc(struct mm* shm, size_t size) {
    struct entry e = { 0 };

    if (size > shm->blocks * BLOCK_SIZE) {
        return e;
    }

    size_t t = size / BLOCK_SIZE;
    if (size % BLOCK_SIZE) t++;

    for (size_t i = 0, f = 0; i < shm->blocks; i++) {
        if (f == t) {
            for (size_t j = (i - f); j < i; j++) bitmap_alloc(shm, j);

            e.len = size;
            e.off = (i - f + 1) * BLOCK_SIZE;
            return e;
        }

        if (bitmap_index_used(shm, i)) {
            f = 0;
            continue;
        }

        ++f;
    }

    return e;
}

void shfree(struct entry e) {}

int queue(struct hring* h, char const* msg, size_t len, off_t off) {
    struct msg* payload = h->shm.map + off;
    payload->len = len;

    if (!memcpy(payload->msg, msg, len + 1)) die("memcpy");

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
    h->sr.sqes[index].len = len;
    h->sr.sqes[index].off = 0;
    h->sr.sqes[index].user_data = (__u64)off;

    h->sr.array[index] = index;

    tail = next_tail;

    if (*h->sr.tail != tail) {
        *h->sr.tail = tail;
        mem_barrier();
    }

    int ret = io_uring_enter(h->fd, 1, 1, IORING_ENTER_GETEVENTS);

    if (ret < 0) die("io_uring_enter");

    printf("queued on pid = %d\n", getpid());

    return 0;
}

void dequeue(struct hring* h) {
    __u32 head = *h->cr.head;

    do {
        mem_barrier();

        if (head == *h->cr.tail) break;

        [[maybe_unused]] struct io_uring_cqe* cqe =
            &h->cr.cqes[head & *h->cr.ring_mask];

        struct msg* payload = h->shm.map + cqe->user_data;

        printf("msg len %u\n", payload->len);

        printf("%s\n", payload->msg);

        head++;

    } while (true);

    *h->cr.head = head;

    mem_barrier();
}

void mmap_sq(struct hring* h, struct io_uring_params* params) {
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

    h->sr.sqes = mmap(0, params->sq_entries * sizeof(struct io_uring_sqe),
                      PROT_READ | PROT_WRITE, MAP_SHARED | MAP_POPULATE, h->fd,
                      IORING_OFF_SQES);

    if (h->sr.sqes == MAP_FAILED) die("mmap");
}

void mmap_cq(struct hring* h, struct io_uring_params* params, __s32 fd) {
    if (fd != 0) {
        params->flags |= IORING_SETUP_ATTACH_WQ;
        params->wq_fd = fd;

        h->fd = io_uring_setup(1, params);

        if (h->fd == -1) die("io_uring_setup");
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

void* shm_init(size_t blocks);

void hring_init(struct hring* h, size_t blocks) {
    struct io_uring_params params = { 0 };

    h->fd = io_uring_setup(10, &params);
    h->kind = HRING_SQ;

    if (h->fd < 0) die("io_uring_setup");

    mmap_sq(h, &params);

    void* mem = shm_init(blocks + 1);

    h->shm.blocks = blocks;
    h->shm.bitmap = mem;
    h->shm.map = mem + BLOCK_SIZE;
}

void* shm_from_file(char const* const file);

void hring_attatch(struct hring* h, char const* const file, __s32 fd) {
    struct io_uring_params params = { 0 };

    h->kind = HRING_CQ;

    mmap_cq(h, &params, fd);

    void* map = shm_from_file(file);

    h->shm.blocks = 10;
    h->shm.bitmap = map;
    h->shm.map = map + BLOCK_SIZE;
}

void* shm_init(size_t blocks) {
    __s32 memfd = shm_open("uring_shm", O_CREAT | O_RDWR, S_IRWXU);

    if (memfd == -1) die("shm_open");

    if (ftruncate(memfd, BLOCK_SIZE * blocks) == -1) die("ftruncate");

    void* map = mmap(0, file_size(memfd), PROT_READ | PROT_WRITE,
                     MAP_SHARED | MAP_POPULATE, memfd, 0);

    if (map == MAP_FAILED) die("mmap");

    return map;
}

void* shm_from_file(char const* const file) {
    __s32 memfd = shm_open(file, O_RDONLY, 0);

    if (memfd == -1) die("shm_open");

    void* map = mmap(NULL, file_size(memfd), PROT_READ, MAP_SHARED, memfd, 0);

    if (map == MAP_FAILED) die("mmap");

    return map;
}
