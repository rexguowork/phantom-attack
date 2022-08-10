CC = gcc
CFLAGS = -lpthread
ELF = phantomv3_openat

all: $(ELF)

$(ELF): %: %.c
	$(CC) $(CFLAGS) -o $@ $< $(CFLAGS)

.PHONY: clean
clean:
	rm -f $(ELF)
