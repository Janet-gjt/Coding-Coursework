CC=gcc
CFLAGS=-Wall -Wextra -g -fPIC

all: liballocator.so runme

allocator.o: allocator.c allocator.h
	$(CC) $(CFLAGS) -c allocator.c

liballocator.so: allocator.o
	$(CC) -shared -o liballocator.so allocator.o

runme: runme.c allocator.h liballocator.so
	$(CC) $(CFLAGS) -o runme runme.c -L. -lallocator -Wl,-rpath=.

test: all
	./runme --seed 123 --storm 1 --size 8192

clean:
	rm -f *.o liballocator.so runme

