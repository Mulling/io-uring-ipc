HRING_FLAGS := -std=gnu23 -Wall -Wextra -Wpedantic -fanalyzer -fsanitize=address,undefined -Wno-pointer-arith -g ${CFLAGS}

all: main

main.o: bench/main.c hring.h
	$(CC) ${HRING_FLAGS} -I./ bench/main.c -o $@ -c

main: main.o
	$(CC) ${HRING_FLAGS} $^ -o $@

t: test
test: all
	./main

bear: clean
	bear -- $(MAKE)

clean:
	$(RM) main *.o compile_commands.json

.PHONY: t test clean bear
.EXTRA_PREREQS := $(abspath $(lastword $(MAKEFILE_LIST)))
