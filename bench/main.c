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

#include "hring.h"

#define die(s) (perror(s), exit(1))

struct msg {
    __u16 len;
    __u8 msg[];
};

void print_msg_cb(size_t off, void* data) {
    struct msg* payload = data;

    printf("off = %zu\n", off);
    printf("len = %d\n", payload->len);
    printf("msg = %s\n", payload->msg);
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

        for (size_t i = 0; i < 10; i++) hring_deque(&h, print_msg_cb);

        return 0;
    }

    struct hring h = { 0 };

    hring_init(&h, 100);

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
            struct entry e = hring_alloc(&h, 1);

            struct msg* payload = (struct msg*)hring_entry_addr(&h, &e);

            payload->len = strlen(msg[i]);

            if (!memcpy(payload->msg, msg[i], payload->len)) die("memcpy");

            hring_queue(&h, &e);
        }

        int status;

        waitpid(pid, &status, 0);

        printf("child exited with status = %d\n", status);
    }

    return 0;
}
