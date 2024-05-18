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
#include <time.h>
#include <unistd.h>

#include "hring.h"

size_t target = 1024 * 100000;
size_t c = 0;

void print_msg_cb(struct hring* h, hring_addr_t addr) {
    target--;
    c++;

    // __u8* data = hring_deref(h, addr);

    // printf("%u\n", data[0]);

    // if (c++ == 0) pp_addr(h, addr);

    hring_free(h, addr);
}

int main(int argc, char** argv) {
    if (argc == 3) {
        __s32 fd = atoi(argv[1]);

        __s32 pidfd = pidfd_open(getppid());

        if (pidfd == -1) die("pidfd_getfd");

        __s32 wq_fd = pidfd_getfd(pidfd, fd);

        if (wq_fd == -1) die("pidfd_getfd");

        struct hring h;

        hring_attatch(&h, "uring_shm", wq_fd);

        size_t total = target;

        time_t last = time(NULL);

        while (target) {
            if (time(NULL) - last >= 1) {
                printf("deque %lu(%2.2F%%) messages, %1.2F Gib/s\n", c,
                       c / (double)total * 100,
                       (double)(c * BLOCK_SIZE) / (1024 * 1024 * 1024));
                last = time(NULL);
                c = 0;
            }

            hring_deque(&h, print_msg_cb);
        }

        return 0;
    }

    struct hring h = { 0 };

    hring_init(&h, 4096);

    printf("bitmap blocks = %u\n", hring_bitmap_blocks(&h));

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
        for (register size_t i = 0; i < target; i++) {
        try_again:;

            register hring_addr_t addr = hring_alloc(&h, 1);

            if (!addr) goto try_again;

            __u8* msg = hring_deref(&h, addr);

            // if (!memset(msg, i % 10, BLOCK_SIZE)) die("memset");

            hring_queue(&h, addr);
        }

        printf("wait for child, sent %lu msgs\n", target);

        int status;
        waitpid(pid, &status, 0);

        pp_bitmap(&h);
        shm_unlink("uring_shm");

        printf("child exited with status = %d\n", status);
    }

    return 0;
}
