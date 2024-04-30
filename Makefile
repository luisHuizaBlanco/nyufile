CC=gcc
CFLAGS=-g -pedantic -std=gnu17 -Wall -Werror -Wextra

# Target 'all' should build the executable
.PHONY: all
all: nyufile

# The executable 'nyufile' depends on 'nyufile.o'
nyufile: nyufile.o
	$(CC) $(CFLAGS) nyufile.o -o nyufile -lcrypto

# The object file 'nyufile.o' depends on 'nyufile.c'
nyufile.o: nyufile.c
	$(CC) $(CFLAGS) -c nyufile.c

# Clean the build directory
.PHONY: clean
clean:
	rm -f *.o nyufile
