HRING_FLAGS := -std=gnu2x -Wall -Wextra -Wpedantic -fanalyzer -fsanitize=address,undefined -Wno-pointer-arith -g ${CFLAGS}

all: main

main.o: bench/main.c hring.h
	$(CC) ${HRING_FLAGS} -I./ bench/main.c -o $@ -c

main: main.o
	$(CC) ${HRING_FLAGS} $^ -o $@

t: test
test: main
	./main

p: perf
perf: HRING_FLAGS = -std=gnu2x -flto -O3 -g ${CFLAGS}
perf: main
	perf record -g sh -c ./main
	perf report

compile_commands.json: Makefile
	bear -- $(MAKE)

clean:
	$(RM) main *.o *.s perf.data.old perf.data compile_commands.json

.PHONY: t test clean compile_commands.json
.EXTRA_PREREQS := $(abspath $(lastword $(MAKEFILE_LIST)))
