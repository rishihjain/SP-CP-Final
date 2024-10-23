CC     = gcc
CFLAGS = -Wall -Wextra -Werror -g

all:
	$(CC) $(CFLAGS) -c test_utils.c
	$(CC) $(CFLAGS) test_reader.c test_utils.o -o reader
	$(CC) $(CFLAGS) test_writer.c test_utils.o -o writer

clean:
	rm -rf *.o

fclean: clean
	rm -f reader writer

re: clean all