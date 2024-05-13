HRING_FLAGS := -std=gnu2x -Wall -Wextra -Wpedantic -fanalyzer -fsanitize=address,undefined -Wno-pointer-arith -g ${CFLAGS}

all:

main.o: bench/main.c hring.h
	$(CC) ${HRING_FLAGS} -I./ bench/main.c -o $@ -c

main: main.o
	$(CC) ${HRING_FLAGS} $^ -o $@

t: test
test: main
	./main

compile_commands.json: Makefile
	@touch $@
	bear -- $(MAKE) main

p: perf
perf: HRING_FLAGS = -std=gnu23 -flto -O3 ${CFLAGS}
perf: main
	./main

clean:
	$(RM) main *.o compile_commands.json

.PHONY: t test clean
.EXTRA_PREREQS := compile_commands.json
