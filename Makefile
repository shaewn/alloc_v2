CCFLAGS := -g -Wall -Wextra -O0

.PHONY: all clean
all: alloc

clean:
	rm *.o
	rm alloc

alloc: alloc.o
	gcc -o alloc alloc.o

alloc.o: alloc.c
	gcc -o alloc.o -c $(CCFLAGS) alloc.c
