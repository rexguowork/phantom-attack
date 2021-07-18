CC=gcc
CFLAGS=-lpthread

all: attack_connect attack_openat

attack_connect: attack_connect.c
	  ${CC} -o $@ $< ${CFLAGS}

attack_openat: attack_openat.c
	  ${CC} -o $@ $< ${CFLAGS}


.PHONY:
clean:
	  rm -f attack_connect attack_openat
