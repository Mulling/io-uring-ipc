# io_uring IPC

Using IORING_OP_NOP it's possible to send arbitrary data to another process, as long as they both share mmaped memory. All the synchronization machinery is already provided by -- for free -- io_uring

## using:

```shell
make
```
