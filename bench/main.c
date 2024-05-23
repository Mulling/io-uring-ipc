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
#include <sys/time.h>
#include <sys/uio.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#include "hring.h"

#define TSIZE 1024 * 100000

#define die(s) (printf(__FILE__ ":%d: ", __LINE__), perror(s), exit(1))

size_t target = TSIZE;
size_t c = 0;

void print_msg_cb(struct hring* h, hring_addr_t addr) {
    target--;
    c++;

    // size_t* val = hring_deref(h, addr);

    // printf("%lu\n", *val);

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

        hring_attatch(&h, "uring_shm");

        size_t total = target;

        time_t last = time(NULL);

        while (target) {
            if (time(NULL) - last >= 1) {
                printf("deque %lu(%2.2F%%) messages, %1.2F GiB/s\n", c,
                       c / (double)total * 100,
                       (double)(c * sizeof(size_t)) / (1024 * 1024 * 1024));
                last = time(NULL);
                c = 0;
            }

            hring_deque(&h, print_msg_cb);
        }

        return 0;
    }

    struct hring h = { 0 };

    if (hring_init(&h, "uring_shm", 4096) < 0) die("hring_init");

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
        struct timeval start = { 0 };
        struct timeval end = { 0 };

        if (gettimeofday(&start, NULL) == -1) die("gettimeofday");

        char* msgs[] = {
            "message number 0", "message number 1", "message number 2",
            "message number 3", "message number 4", "message number 5",
            "message number 6", "message number 7", "message number 8",
            "message number 9",
        };

        for (register size_t i = 0; i < target; i++) {
        try_again:;

            register hring_addr_t addr = hring_alloc(&h, 1);

            if (!addr) goto try_again;

            size_t* msg = hring_deref(&h, addr);

            *msg = i;

            hring_queue(&h, addr);
        }

        if (gettimeofday(&end, NULL) == -1) die("gettimeofday");

        __u64 diff = (end.tv_sec - start.tv_sec) * 1000000 -
                     (end.tv_usec - start.tv_usec);

        double msgs_usec = (double)TSIZE / diff;

        printf(
            "wait for child, sent an average of %.2F msgs/usec, average "
            "latency "
            "of %.2F ns\n",
            msgs_usec, 1000.0 / msgs_usec);

        int status;
        waitpid(pid, &status, 0);

        pp_bitmap(&h);
        shm_unlink(h.id);

        printf("child exited with status = %d\n", status);
    }

    return 0;
}
