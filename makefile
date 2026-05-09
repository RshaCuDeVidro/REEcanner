CC      = gcc
CFLAGS  = -O3 -march=native -flto -fPIC -shared
SRC     = reecanner/worker.c
OUT     = reecanner/worker.so

all: $(OUT)

$(OUT): $(SRC)
	$(CC) $(CFLAGS) -o $@ $<

clean:
	rm -f $(OUT)

.PHONY: all clean
