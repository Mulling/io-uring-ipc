include config.mk

all: main

main.o: bench/main.c hring.h
	$(QUIET_CC)$(CC) ${HRING_FLAGS} -I./ bench/main.c -o $@ -c

main: main.o
	$(QUIET_CC)$(CC) ${HRING_FLAGS} $^ -o $@

t: test
test: main cleanup
	$(QUIET_TEST) ./main

p: perf
perf: HRING_FLAGS = -std=gnu2x -flto -O3 -g ${CFLAGS} -DNDEBUG
perf: main cleanup
	$(QUIET_PERF) perf record -e ${HRING_PERF_EVENTS} ./main
	perf report -v

disable-ptrace-scope:
	@if [ "$$(cat /proc/sys/kernel/yama/ptrace_scope)" -ne 0 ]; then \
		echo 0 > /proc/sys/kernel/yama/ptrace_scope; \
	fi

compile_commands.json: Makefile
	$(QUIET_BEAR) bear -- $(MAKE) --no-print-directory

cleanup:
	$(RM) /dev/shm/uring_shm*

clean:
	$(QUIET_RM)$(RM) main *.o *.s perf.data.old perf.data compile_commands.json

.PHONY: t test clean compile_commands.json
.EXTRA_PREREQS := $(abspath $(lastword $(MAKEFILE_LIST)))
