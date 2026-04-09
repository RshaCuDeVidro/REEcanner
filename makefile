CC      = gcc
CFLAGS  = -O3 -march=native -flto -fPIC -shared
SRC     = REEcanner/worker.c
OUT     = REEcanner/worker.so

all: $(OUT)

$(OUT): $(SRC)
	$(CC) $(CFLAGS) -o $@ $<

clean:
	rm -f $(OUT)

.PHONY: all clean
