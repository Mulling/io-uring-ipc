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

#define mem_barrier() __asm__ __volatile__("" ::: "memory")

#define die(s) (perror(s), exit(1))

struct uring {
    int fd;

    struct {
        __u32* head;
        __u32* tail;
        __u32* ring_mask;
        __u32* ring_entries;
        __u32* flags;
        __u32* array;

    } sr;

    struct io_uring_sqe* sqes;

    struct {
        __u32* head;
        __u32* tail;
        __u32* ring_mask;
        __u32* ring_entries;
        struct io_uring_cqe* cqes;

    } cr;
};

struct msg {
    size_t len;
    char msg[];
};

size_t file_size(int fd) {
    struct stat s;

    if (fstat(fd, &s) < 0) die("stat");

    return s.st_size;
}

__s32 io_uring_setup(__u32 entries, struct io_uring_params* p) {
    return (int)syscall(__NR_io_uring_setup, entries, p);
}

__s32 io_uring_enter(int fd, unsigned int to_submit, unsigned int min_complete,
                     unsigned int flags) {
    return (int)syscall(__NR_io_uring_enter, fd, to_submit, min_complete, flags,
                        NULL, 0);
}

__s32 pidfd_getfd(__s32 pidfd, __s32 fd) {
    return (__s32)syscall(SYS_pidfd_getfd, pidfd, fd, 0);
}

__s32 pidfd_open(__s32 ppid) { return (__s32)syscall(SYS_pidfd_open, ppid, 0); }

int queue_cat(struct uring* u, char const* msg, size_t len) {
    __s32 memfd = shm_open("uring_shm", O_CREAT | O_RDWR, S_IRWXU);

    if (memfd == -1) die("shm_open");

    if (ftruncate(memfd, sizeof(struct msg) + len) == -1) die("ftruncate");

    struct msg* payload = mmap(0, sizeof(struct msg) + len,
                               PROT_READ | PROT_WRITE, MAP_SHARED, memfd, 0);

    if (payload == MAP_FAILED) die("malloc 1");

    payload->len = len;

    if (!memcpy(payload->msg, msg, len)) die("memcpy");

    size_t next_tail = 0;
    size_t tail = 0;
    size_t index = 0;

    next_tail = tail = *u->sr.tail;
    next_tail++;

    mem_barrier();

    index = tail & *u->sr.ring_mask;
    u->sqes[index].fd = 0;
    u->sqes[index].flags = 0;
    u->sqes[index].opcode = IORING_OP_NOP;
    u->sqes[index].addr = 0;
    u->sqes[index].len = len;
    u->sqes[index].off = 0;
    u->sqes[index].user_data = (__u64)payload;

    u->sr.array[index] = index;

    tail = next_tail;

    if (*u->sr.tail != tail) {
        *u->sr.tail = tail;
        mem_barrier();
    }

    int ret = io_uring_enter(u->fd, 1, 1, IORING_ENTER_GETEVENTS);

    if (ret < 0) die("io_uring_enter");

    printf("queued on pid = %d\n", getpid());

    return 0;
}

void dequeue_cat(struct uring* u) {
    __s32 memfd = shm_open("uring_shm", O_RDONLY, 0);

    if (memfd == -1) die("shm_open");

    struct msg* payload =
        mmap(NULL, file_size(memfd), PROT_READ, MAP_SHARED, memfd, 0);

    if (payload == MAP_FAILED) die("mmap");

    __u32 head = *u->cr.head;

    do {
        mem_barrier();

        if (head == *u->cr.tail) break;

        [[maybe_unused]] struct io_uring_cqe* cqe =
            &u->cr.cqes[head & *u->cr.ring_mask];

        printf("%s\n", payload->msg);

        head++;

    } while (true);

    *u->cr.head = head;

    mem_barrier();
}

void mmap_sq(struct uring* u, struct io_uring_params* params) {
    __s32 ring_size = params->sq_off.array + params->sq_entries * sizeof(__u32);

    void* sq_ptr = mmap(0, ring_size, PROT_READ | PROT_WRITE,
                        MAP_SHARED | MAP_POPULATE, u->fd, IORING_OFF_SQ_RING);

    if (sq_ptr == MAP_FAILED) die("mmap");

    u->sr.head = sq_ptr + params->sq_off.head;
    u->sr.tail = sq_ptr + params->sq_off.tail;

    u->sr.ring_mask = sq_ptr + params->sq_off.ring_mask;
    u->sr.ring_entries = sq_ptr + params->sq_off.ring_entries;

    u->sr.flags = sq_ptr + params->sq_off.flags;
    u->sr.array = sq_ptr + params->sq_off.array;

    u->sqes = mmap(0, params->sq_entries * sizeof(struct io_uring_sqe),
                   PROT_READ | PROT_WRITE, MAP_SHARED | MAP_POPULATE, u->fd,
                   IORING_OFF_SQES);

    if (u->sqes == MAP_FAILED) die("mmap");
}

void mmap_cq(struct uring* u, struct io_uring_params* params, __s32 fd) {
    if (fd != 0) {
        params->flags |= IORING_SETUP_ATTACH_WQ;
        params->wq_fd = fd;

        u->fd = io_uring_setup(1, params);

        if (u->fd == -1) die("io_uring_setup");
    }

    size_t ring_size =
        params->cq_off.cqes + params->cq_entries * sizeof(struct io_uring_cqe);

    void* cq_ptr = mmap(0, ring_size, PROT_READ | PROT_WRITE,
                        MAP_SHARED | MAP_POPULATE, fd, IORING_OFF_CQ_RING);

    if (cq_ptr == MAP_FAILED) die("mmap");

    u->cr.head = cq_ptr + params->cq_off.head;
    u->cr.tail = cq_ptr + params->cq_off.tail;
    u->cr.ring_mask = cq_ptr + params->cq_off.ring_mask;
    u->cr.ring_entries = cq_ptr + params->cq_off.ring_entries;
    u->cr.cqes = cq_ptr + params->cq_off.cqes;
}

struct uring* uring_new() {
    struct uring* u = calloc(1, sizeof(struct uring));

    if (!u) die("calloc");

    struct io_uring_params params = { 0 };

    u->fd = io_uring_setup(1, &params);

    if (u->fd < 0) die("io_uring_setup");

    mmap_sq(u, &params);

    return u;
}

int main(int argc, char** argv) {
    if (argc == 3) {
        __s32 fd = atoi(argv[1]);

        __s32 pidfd = pidfd_open(getppid());

        if (pidfd == -1) die("pidfd_getfd");

        __s32 wq_fd = pidfd_getfd(pidfd, fd);

        if (wq_fd == -1) die("pidfd_getfd");

        printf("reading on child, pid = %d\n", getpid());

        struct io_uring_params params = { 0 };
        struct uring u;

        mmap_cq(&u, &params, wq_fd);

        dequeue_cat(&u);

        return 0;
    }

    struct uring* u = uring_new();

    int pid = fork();

    if (pid == -1) {
        die("fork");
    } else if (pid == 0) {
        char fd_str[256];

        snprintf(fd_str, 256, "%d", u->fd);

        char pid_str[256];
        snprintf(pid_str, 256, "%d", getpid());

        const char* path = argv[0];

        char* argv[] = { "child", fd_str, pid_str, 0 };

        if (execv(path, argv) == -1) die("execv");
    } else {
        const char* msg = "msg from parent";

        queue_cat(u, msg, strlen(msg));

        int status;

        waitpid(pid, &status, 0);

        printf("child exited with status = %d\n", status);
    }

    return 0;
}
