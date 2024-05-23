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

// producer:
struct hring h;
hring_init(&h, "ipc-name/id", 4096)

hring_deque(&h, callback);
//              ^
//              |
//   +----------+
//   |
//   v
void callback(struct hring* h, hring_addr_t addr) {
    int* val = hring_deref(h, addr);

    // do something with val;

    hring_free(h, addr)
}
```

To receive a message:
```C
#include "hring.h"

struct hring h;
hring_attatch(&h, "ipc-name/id");
//                 ^
//                 |
//                 +-- will be used to search /dev/shm (must be unique)

hring_addr_t addr = hring_alloc(&h, sizeof(int));

int* val = hring_deref(&h, addr);

*val = 123;

hring_free(&h, addr);
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
deque   4053888(3.96%) messages, 0.03 GiB/s
deque 15033952(14.68%) messages, 0.11 GiB/s
deque 15065728(14.71%) messages, 0.11 GiB/s
deque 15074784(14.72%) messages, 0.11 GiB/s
deque 15058624(14.71%) messages, 0.11 GiB/s
deque 15058432(14.71%) messages, 0.11 GiB/s
deque 15073024(14.72%) messages, 0.11 GiB/s
wait for child, sent an average of 14.23 msgs/usec, average latency of 70.28 ns per msg
```
