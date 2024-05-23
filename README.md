# io_uring IPC

Using `IORING_OP_NOP` it's possible to send arbitrary data to another process, consequently, it's also possible shared memory-pool entries, meaning, you can send data to another process with very low-latency and high throughput.

All the synchronization machinery is already provided -- for free -- by io_uring. You only need a shared memory-pool allocator.

## Using:

One of the limitations of this approach is that the yama security model prevents us from obtaining the file descriptor of the uring, you need either root privileges or PTRACE_MODE_ATTACH_REALCREDS, see `pidfd_getfd(2)`.

Another option is to disable it completely.

```sh
echo 0 | sudo tee /proc/sys/kernel/yama/ptrace_scope
```

```C
#include "hring.h"

// Producer:
struct hring h;
hring_init("shared_memory_pool_id", &h);

hring_deque(&h, callback); // The callback is defined bellow

void callback(struct hring* h, hring_addr_t addr) {
    int* val = hring_deref(h, addr);

    // Do something with val;

    hring_free(h, addr)
}


// Consumer:
struct hring h;
hring_attatch(&h, "shared_memory_pool_id", uring_fd);

hring_addr_t addr = hring_alloc(&h, sizeof(int));

int* val = hring_deref(&h, addr);

*val = 123;

hring_queue(&h, addr);
```

### Building:

```sh
make test

# or

make bench
```


