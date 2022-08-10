CC = gcc
CFLAGS = 
ELF = tcp_server

all: $(ELF)

$(ELF): %: %.c
	$(CC) $(CFLAGS) -o $@ $< $(CFLAGS)

.PHONY: clean
clean:
	rm -f $(ELF)
