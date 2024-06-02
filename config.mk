HRING_FLAGS := -std=gnu2x                   \
			   -Wall                        \
			   -Wextra                      \
			   -Wpedantic                   \
			   -fanalyzer                   \
			   -fsanitize=address,undefined \
			   -Wno-pointer-arith           \
			   -g ${CFLAGS}

HRING_PERF_EVENTS :=cache-references,cache-misses,cycles,instructions,branches,faults,migrations

ifndef VERBOSE
.SILENT:

QUIET_CC	    = @echo 'CC     ' $@;
QUIET_LINK	    = @echo 'LINK   ' $@;
QUIET_AR	    = @echo 'AR     ' $@;
QUIET_RANLIB	= @echo 'RANLIB ' $@;
QUIET_PERF      = @echo 'PERF   ' $(firstword $^);
QUIET_BEAR      = @echo 'BEAR   ' $@;
QUIET_RM        = @echo 'CLEAN  ' $(shell pwd);
QUITE_TEST      = @echo 'TEST   ' $^;
endif
