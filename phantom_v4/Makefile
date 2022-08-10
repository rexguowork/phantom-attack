CC = gcc
CFLAGS = -lpthread
ELF = phantomv4 ptracer

all: $(ELF)

$(ELF): %: %.c
	$(CC) $(CFLAGS) -o $@ $< $(CFLAGS)

.PHONY: clean
clean:
	rm -f $(ELF)
