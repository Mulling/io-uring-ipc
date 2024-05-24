HRING_FLAGS := -std=gnu2x -Wall -Wextra -Wpedantic -fanalyzer -fsanitize=address,undefined -Wno-pointer-arith -g ${CFLAGS}

all: main

main.o: bench/main.c hring.h
	$(CC) ${HRING_FLAGS} -I./ bench/main.c -o $@ -c

main: main.o
	$(CC) ${HRING_FLAGS} $^ -o $@

t: test
test: main cleanup_shm
	./main

p: perf
perf: HRING_FLAGS = -std=gnu2x -flto -O3 -g ${CFLAGS} -DNDEBUG
perf: main cleanup_shm
	perf record -e cache-references,cache-misses,cycles,instructions,branches,faults,migrations ./main
	perf report -v

compile_commands.json: Makefile
	bear -- $(MAKE)

cleanup_shm:
	$(RM) /dev/shm/uring_shm*


clean:
	$(RM) main *.o *.s perf.data.old perf.data compile_commands.json

.PHONY: t test clean compile_commands.json
.EXTRA_PREREQS := $(abspath $(lastword $(MAKEFILE_LIST)))
