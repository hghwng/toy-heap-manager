CFLAGS=-c -g -Wall -Wextra -fPIC
APP=/bin/ls

lib: bin/libheap.so

run: bin/libheap.so
	LD_PRELOAD=$< $(APP)

gdb: bin/libheap.so
	gdb -ex "set exec-wrapper env LD_PRELOAD=$<" $(APP)

clean:
	rm ./bin/*

bin/libheap.so: bin/heap.o
	$(CC) -shared -g $< -o $@

bin/heap.o: heap.c heap.h list.h
	$(CC) $(CFLAGS) $< -o $@

.PHONY: lib run gdb clean
