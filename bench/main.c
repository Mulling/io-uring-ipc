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

        void* mem = shm_from_file("uring_shm");

        for (size_t i = 0; i < 10; i++) {
            dequeue(&u, mem);
        }

        return 0;
    }

    struct uring u = { 0 };

    uring_init(&u);

    int pid = fork();

    if (pid == -1) {
        die("fork");
    } else if (pid == 0) {
        char fd_str[256];

        snprintf(fd_str, 256, "%d", u.fd);

        char pid_str[256];
        snprintf(pid_str, 256, "%d", getpid());

        const char* path = argv[0];

        char* argv[] = { "child", fd_str, pid_str, 0 };

        if (execv(path, argv) == -1) die("execv");
    } else {
        const char* msg[] = {
            "message 0", "message 1", "message 2", "message 3", "message 4",
            "message 5", "message 6", "message 7", "message 8", "message 9",
        };

        void* mem = shm_init(10);

        for (size_t i = 0; i < 10; i++) {
            queue(&u, msg[i], strlen(msg[i]), mem + BLOCK_SIZE * i,
                  BLOCK_SIZE * i);
        }

        int status;

        waitpid(pid, &status, 0);

        printf("child exited with status = %d\n", status);
    }

    return 0;
}
