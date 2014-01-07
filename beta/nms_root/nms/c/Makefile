all:
	gcc -c -Wall -Werror -fpic shmlib.c
	gcc -shared -o shmlib.so shmlib.o
clean:
	rm shmlib.so
	rm shmlib.o
