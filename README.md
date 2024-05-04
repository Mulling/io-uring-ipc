# io_uring IPC

Using IORING_OP_NOP it's possible to send arbitrary data to another process, as long as they both share mmaped memory. All the synchronization machinery is already provided by -- for free -- io_uring

## Using:

One of the limitations of this approach is that the yama security model prevents us from obtaining the file descriptor of the uring, you need to either root privileges or PTRACE_MODE_ATTACH_REALCREDS, see: pidfd_getfd(2).

Another option is to disable it completely.

```shell
# echo 0 | sudo tee /proc/sys/kernel/yama/ptrace_scope
```

### Building:

```shell
$ make test
```
