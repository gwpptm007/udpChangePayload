CC := gcc
CFLAGS := -Wall -O2 -pthread
LDLIBS := -lnetfilter_queue

all: changepayload

changepayload: src/changepayload.c src/logging.c include/logging.h
	$(CC) $(CFLAGS) -Iinclude src/changepayload.c src/logging.c -o changepayload $(LDLIBS)

clean:
	rm -f changepayload