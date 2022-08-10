CC = gcc
CFLAGS = -lpthread
ELF = phantomv3_connect phantomv3_tcp_client

all: $(ELF)

$(ELF): %: %.c
	$(CC) $(CFLAGS) -o $@ $< $(CFLAGS)

.PHONY: clean
clean:
	rm -f $(ELF)
