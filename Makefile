CC = gcc

CFLAGS ?= -O3

.PHONY: all
all: src/nanosocks.c src/nanosocks.h
	mkdir -p build
	$(CC) $(CFLAGS) -std=c99 src/nanosocks.c -o build/nanosocks

.PHONY: clean
clean: build
	rm -r build
