# io_uring IPC

*Not stable yet, don't use for anything serious.*

Using `IORING_OP_NOP` it's possible to send arbitrary data (up to 64 bits) to another process, consequently, it's also possible to share memory-pool entries (address); meaning, you can send data to another process with very low-latency and high throughput.

All the synchronization machinery is already provided -- for free -- by io_uring. You only need a shared memory-pool allocator.

### Using:

One of the limitations of this approach is that the yama security model prevents us from obtaining the file descriptor of the uring, you need either root privileges or PTRACE_MODE_ATTACH_REALCREDS, see `pidfd_getfd(2)`.

Another option is to disable it completely.

```sh
echo 0 | sudo tee /proc/sys/kernel/yama/ptrace_scope
```

To send a message:
```C
#include "hring.h"

struct hring h;
hring_init(&h, "ipc-name/id", 4096)
/*              ^
                |
                +-- will be used to search /dev/shm (must be unique) */

hring_addr_t addr = hring_alloc(&h, sizeof(int));

size_t* msg = hring_deref(&h, addr);

*msg = 123;

hring_try_que(&h, addr);

hring_submit(&h, true);
```

To receive a message:
```C
#include "hring.h"

// consumer:
struct hring h;
hring_attach(&h, "ipc-name/id");

hring_deque(&h, callback);
/*              ^
                |
                |
                |
                v
*/         void callback(struct hring* h, struct io_uring_cqe const* const cqe) {
               hring_addr_t addr = cqe->user_data;

               int* val = hring_deref(h, addr);

               // do something with val;

               hring_free(h, addr);
           }
```

### Building:
Just include `hring.h`.

```sh
make test

# or

make bench
```

### Results
With a payload size of 8 bytes, sending 102400000 messages.

```
left = 94497280, deque   7902720(7.72%) messages, 0.06 GiB/s
left = 68429792, deque 26067488(25.46%) messages, 0.19 GiB/s
left = 42355424, deque 26074368(25.46%) messages, 0.19 GiB/s
left = 16253600, deque 26101824(25.49%) messages, 0.19 GiB/s
wait for child, sent an average of 25.15 msgs/usec, average latency of 39.76 ns
child exited with status = 0
```
