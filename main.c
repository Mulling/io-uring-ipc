// SPDX-License-Identifier: MIT

#include <bits/types/struct_timeval.h>
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

#define TSIZE (1024 * 100000)

#define warn(s) (printf(__FILE__ ":%d: ", __LINE__), perror(s))
#define die(s) (warn(s), exit(1))

size_t target = TSIZE;

void callback(struct hring* h, struct io_uring_cqe const* const cqe) {
    target--;

    // printf("%llu, %lu\n", hring_addr_off(cqe->user_data),
    //        *(size_t*)hring_deref(h, cqe->user_data));

    hring_mpool_free(h, cqe->user_data);
}

double time_diff(struct timeval const* const a, struct timeval const* const b) {
    return ((a->tv_sec - b->tv_sec) * 1000000) + (a->tv_usec - b->tv_usec);
}

int child_main() {
    struct timeval start = { 0 };
    struct timeval end = { 0 };

    struct hring h = { 0 };

    if (hring_attach(&h, "uring_shm") < 0)
        die("hring_attach");

    if (gettimeofday(&start, NULL) == -1)
        die("gettimeofday");

    while (target) {
        // hring_addr_t addr;

        // if (hring_deque_once(&h, &addr) < 0)
        //     warn("hring_deque_once");

        // target--;
        // c++;

        hring_deque_with_callback(&h, callback);
    }

    if (gettimeofday(&end, NULL) == -1)
        die("gettimeofday");

    double diff_secs = (double)time_diff(&end, &start) / 1000000.0;

    printf("deque %d messages in %1.2Fs (%1.2F GiB/s)\n", TSIZE, diff_secs,
           (double)(TSIZE * sizeof(size_t)) / (1024 * 1024 * 1024) / diff_secs);

    free(h.id);

    return 0;
}

int main([[maybe_unused]] int argc, char** argv) {
    // run the completion side
    if (strcmp("child", argv[0]) == 0)
        return child_main();

    struct hring h = { 0 };

    if (hring_init(&h, "uring_shm", 4096, 32, 32 << 8) < 0)
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

                    // if (!addr) {
                    //     warn("hring_mpool_alloc: could not allocate");

                    //     usleep(1);
                    // }

                } while (!addr);

                size_t* msg = hring_deref(&h, addr);

                *msg = i;

                if ((qed = hring_try_que(&h, addr)) == 0)
                    warn("hring_try_que: fail to queue addr");

                if (hring_submit(&h, qed == 32) < 0)
                    warn("hring_submit: fail to submit");
            }

            // send any remaining
            if (hring_submit(&h, true) < 0)
                warn("hring_submit: fail to submit remaining entries");

            if (gettimeofday(&end, NULL) == -1)
                die("gettimeofday");

            // _pp_bitmap(&h);

            double msgs_usec = (double)TSIZE / time_diff(&end, &start);

            printf(
                "wait for child, sent an average of %.2F msgs/usec, average "
                "latency "
                "of %.2Fns\n",
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

    free(h.id);

    return 0;
}
