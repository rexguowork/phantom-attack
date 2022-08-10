#define _GNU_SOURCE
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>

#include <sys/ptrace.h>
#include <sys/reg.h>
#include <signal.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>
#include <sys/user.h>
#include <fcntl.h>
#include <linux/limits.h>

static void redirect_file(pid_t child, const char *file)
{
    char *stack_addr, *file_addr;

    stack_addr = (char *) ptrace(PTRACE_PEEKUSER, child, sizeof(long)*RSP, 0);
    /* Move further of red zone and make sure we have space for the file name */
    stack_addr -= 128 + PATH_MAX;
    file_addr = stack_addr;

    /* Write new file in lower part of the stack */
    do {
        int i;
        char val[sizeof (long)];

        for (i = 0; i < sizeof (long); ++i, ++file) {
            val[i] = *file;
            if (*file == '\0') break;
        }

        ptrace(PTRACE_POKETEXT, child, stack_addr, *(long *) val);
        stack_addr += sizeof (long);
    } while (*file);

    /* Change argument to open */
    // open/creat syscall
    ptrace(PTRACE_POKEUSER, child, sizeof(long)*RDI, file_addr);
    // openat syscall
    //ptrace(PTRACE_POKEUSER, child, sizeof(long)*RSI, file_addr);
}

static int wait_for_open(pid_t child)
{
  int status;

  while (1) {
    ptrace(PTRACE_SYSCALL, child, 0, 0);
    waitpid(child, &status, 0);
    /* Is it the open syscall (sycall number 2 in x86_64)? */
    if (WIFSTOPPED(status) && WSTOPSIG(status) & 0x80 &&
      // open syscall
      //ptrace(PTRACE_PEEKUSER, child, sizeof(long)*ORIG_RAX, 0) == 2)
      // creat syscall
      ptrace(PTRACE_PEEKUSER, child, sizeof(long)*ORIG_RAX, 0) == 85)
      // openat syscall
      //ptrace(PTRACE_PEEKUSER, child, sizeof(long)*ORIG_RAX, 0) == 257)
      return 0;

    if (WIFEXITED(status))
      return 1;
  }
}

static void read_file(pid_t child, char *file)
{
  char *child_addr;
  int i;
  // open/creat syscall
  child_addr = (char *) ptrace(PTRACE_PEEKUSER, child, sizeof(long)*RDI, 0);
  // openat syscall
  //child_addr = (char *) ptrace(PTRACE_PEEKUSER, child, sizeof(long)*RSI, 0);

  do {
    long val;
    char *p;

    val = ptrace(PTRACE_PEEKTEXT, child, child_addr, NULL);
    if (val == -1) {
        fprintf(stderr, "PTRACE_PEEKTEXT error: %s", strerror(errno));
        exit(1);
    }
    child_addr += sizeof (long);

    p = (char *) &val;
    for (i = 0; i < sizeof (long); ++i, ++file) {
        *file = *p++;
        if (*file == '\0') break;
    }
  } while (i == sizeof (long));
}



static void process_signals(pid_t child)
{
    const char *file_to_redirect = "ONE.txt";
    const char *file_to_avoid = "TWO.txt";

    while(1) {
        char orig_file[PATH_MAX];

        /* Wait for open syscall start */
        if (wait_for_open(child) != 0) break;

        /* Find out file and re-direct if it is the target */

        read_file(child, orig_file);
        printf("orig_file = %s\n", orig_file);

        if (strcmp(file_to_avoid, orig_file) == 0)
            redirect_file(child, file_to_redirect);

        /* Wait for open syscall exit */
        if (wait_for_open(child) != 0) break;
    }
}

int main(int argc, char **argv)
{
    pid_t pid;
    int status;

    if (argc < 2) {
        fprintf(stderr, "Usage: %s <prog> <arg1> ... <argN>\n", argv[0]);
        return 1;
    }

    if ((pid = fork()) == 0) {
        ptrace(PTRACE_TRACEME, 0, 0, 0);
        kill(getpid(), SIGSTOP);
        return execvp(argv[1], argv + 1);
    } else {
        waitpid(pid, &status, 0);
        ptrace(PTRACE_SETOPTIONS, pid, 0, PTRACE_O_TRACESYSGOOD);
        process_signals(pid);
        return 0;
    }
}
