CC = gcc

.PHONY: all
all: src/nanosocks.c src/nanosocks.h
	mkdir -p build
	$(CC) -O3 -std=c99 src/nanosocks.c -o build/nanosocks

.PHONY: clean
clean: build
	rm -r build
