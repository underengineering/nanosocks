CC = gcc

CFLAGS ?= -O3

.PHONY: all
all: src/nanosocks.c src/protocol.h src/util.h
	mkdir -p build
	$(CC) $(CFLAGS) -std=c99 -lcares src/nanosocks.c -o build/nanosocks

.PHONY: clean
clean: build
	rm -r build
