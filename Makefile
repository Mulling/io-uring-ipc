IOUIPC_FLAGS := -std=gnu2x -Wall -Wextra -Werror -fsanitize=address,undefined -g ${CFLAGS}

all: main

main.o: main.c
	$(CC) ${IOUIPC_FLAGS} $^ -o $@ -c

main: main.o
	$(CC) ${IOUIPC_FLAGS} $^ -o $@

test: all
	./main

clean:
	$(RM) main *.o compile_commands.json

.PHONY: test clean
