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

void callback(struct hring* h, struct io_uring_cqe const* const cqe) {
    target--;
    c++;

    // usleep(100);

    // printf("%X %s\n", cqe->flags, "test, this is a test");

    hring_mpool_free(h, cqe->user_data);
}

int child_main() {
    struct hring h;

    if (hring_attach(&h, "uring_shm") < 0)
        die("hring_attach");

    size_t total = target;

    time_t last = time(NULL);

    while (target) {
        if (time(NULL) - last >= 1) {
            printf("left = %lu, deque %lu(%2.2F%%) messages, %1.2F GiB/s\n",
                   target, c, c / (double)total * 100,
                   (double)(c * sizeof(size_t)) / (1024 * 1024 * 1024));
            last = time(NULL);
            c = 0;
        }

        hring_deque(&h, callback);
    }

    return 0;
}

int main([[maybe_unused]] int argc, char** argv) {
    // run the completion side
    if (strcmp("child", argv[0]) == 0)
        return child_main();

    struct hring h = { 0 };

    if (hring_init(&h, "uring_shm", 4096) < 0)
        die("hring_init");

    pid_t pid = fork();

    switch (pid) {
        default: {  // parent, run the submission side
            struct timeval start = { 0 };
            struct timeval end = { 0 };

            if (gettimeofday(&start, NULL) == -1)
                die("gettimeofday");

            for (size_t i = 0, qed = 0; i < target; i++) {
                hring_addr_t addr;

                do {
                    addr = hring_mpool_alloc(&h, 1);
                } while (!addr);

                size_t* msg = hring_deref(&h, addr);

                *msg = i;

                qed = hring_try_que(&h, addr);

                if (!qed)
                    printf("fail to que\n");

                if (hring_submit(&h, qed == 32) < 0) {
                    printf("fail to submit");
                };
            }

            // send any remaining
            hring_submit(&h, true);

            if (gettimeofday(&end, NULL) == -1)
                die("gettimeofday");
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

            // pp_bitmap(&h);
            shm_unlink(h.id);

            printf("child exited with status = %d\n", status);
        } break;
        case 0: {  // child
            char* args[] = { "child", NULL };

            if (execv(argv[0], args) == -1)
                die("execv");
        } break;

        case -1:
            die("fork");
    }

    return 0;
}
