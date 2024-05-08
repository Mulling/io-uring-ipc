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

#include "half_uring.h"

#define mem_barrier() __asm__ __volatile__("" ::: "memory")

#define die(s) (perror(s), exit(1))

int main(int argc, char** argv) {
    __u8 bitmap[BLOCK_SIZE] = { 0 };

    bitmap[0] = 0b11010001;

    struct mm shm = {
        .blocks = 8,
        .bitmap = bitmap,
        .map = NULL,
    };

    assert(bitmap_index_used(shm.bitmap, 0) == true);
    assert(bitmap_index_used(shm.bitmap, 1) == true);
    assert(bitmap_index_used(shm.bitmap, 7) == true);
    assert(bitmap_index_used(shm.bitmap, 8) == false);

    struct entry e = shmalloc(&shm, 1025);

    printf("e.off %lu\n", e.off);
    printf("e.len %lu\n", e.len);

    printf("bitmap %X\n", bitmap[0]);

    shmfree(&shm, e);

    printf("bitmap %X\n", bitmap[0]);

    if (argc == 3) {
        __s32 fd = atoi(argv[1]);

        __s32 pidfd = pidfd_open(getppid());

        if (pidfd == -1) die("pidfd_getfd");

        __s32 wq_fd = pidfd_getfd(pidfd, fd);

        if (wq_fd == -1) die("pidfd_getfd");

        struct hring h;

        hring_attatch(&h, "uring_shm", wq_fd);

        for (size_t i = 0; i < 10; i++) {
            dequeue(&h);
        }

        return 0;
    }

    struct hring h = { 0 };

    hring_init(&h, 10);

    int pid = fork();

    if (pid == -1) {
        die("fork");
    } else if (pid == 0) {
        char fd_str[256];

        snprintf(fd_str, 256, "%d", h.fd);

        char pid_str[256];
        snprintf(pid_str, 256, "%d", getpid());

        const char* path = argv[0];

        char* argv[] = { "child", fd_str, pid_str, 0 };

        if (execv(path, argv) == -1) die("execv");
    } else {
        const char* msg[] = {
            "message from parent 0", "message from parent 1",
            "message from parent 2", "message from parent 3",
            "message from parent 4", "message from parent 5",
            "message from parent 6", "message from parent 7",
            "message from parent 8", "message from parent 9",
        };

        for (size_t i = 0; i < 10; i++) {
            queue(&h, msg[i], strlen(msg[i]), BLOCK_SIZE * i);
        }

        int status;

        waitpid(pid, &status, 0);

        printf("child exited with status = %d\n", status);
    }

    return 0;
}
