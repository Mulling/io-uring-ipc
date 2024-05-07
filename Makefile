HRING_FLAGS := -std=gnu2x -Wall -Wextra -Werror -fsanitize=address,undefined -g ${CFLAGS}

all: main

main.o: bench/main.c half_uring.h
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
