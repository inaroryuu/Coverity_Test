.PHONY: all test

CFLAGS += -I../include

all: test

test: %:%.o
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $^ -lssl -lcrypto

clean:
	rm -rf *.o test
