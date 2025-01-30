include config.mk

all: main one-way

main.o: main.c hring.h
	$(QUIET_CC)$(CC) ${HRING_FLAGS} -I./ main.c -o $@ -c

main: main.o
	$(QUIET_CC)$(CC) ${HRING_FLAGS} $^ -o $@

one-way.o: one-way.c hring.h
	$(QUIET_CC)$(CC) ${HRING_FLAGS} -I./ one-way.c -o $@ -c

one-way: one-way.o
	$(QUIET_CC)$(CC) ${HRING_FLAGS} $^ -o $@

test: main cleanup
	$(QUIET_TEST) ./main

bench-one-way: HRING_FLAGS = -std=gnu2x -flto -O3 -g ${CFLAGS} -DNDEBUG
bench-one-way: one-way cleanup
	$(QUIET_PERF) perf record -e ${HRING_PERF_EVENTS} ./one-way
	perf report -v

bench: HRING_FLAGS = -std=gnu2x -flto -O3 -g ${CFLAGS} -DNDEBUG
bench: one-way
	./one-way

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
	$(QUIET_RM)$(RM) main one-way *.o *.s perf.data.old perf.data compile_commands.json

.PHONY: bench test clean cleanup compile_commands.json
.EXTRA_PREREQS := $(abspath $(lastword $(MAKEFILE_LIST)))
