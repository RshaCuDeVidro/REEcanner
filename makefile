CC      = gcc

# -march=native produces binaries that may crash with illegal instructions on
# other CPUs, so it is opt-in via REECANNER_NATIVE=1 (e.g. local builds).
ifeq ($(REECANNER_NATIVE),1)
ARCH_FLAGS = -march=native
else
ARCH_FLAGS = -mtune=generic
endif

CFLAGS  = -O2 $(ARCH_FLAGS) -flto -fPIC -shared -Wall -Wextra
SRC     = reecanner/worker.c
OUT     = reecanner/worker.so

all: $(OUT)

$(OUT): $(SRC)
	$(CC) $(CFLAGS) -o $@ $<

clean:
	rm -f $(OUT)

.PHONY: all clean
