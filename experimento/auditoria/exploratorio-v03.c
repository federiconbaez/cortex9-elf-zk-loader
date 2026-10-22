#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sched.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <unistd.h>
#include <errno.h>
#include <signal.h>
#include <sys/wait.h>
static unsigned char CODE[]={0xb8,0x2a,0,0,0,0xc3};
static char stk[1<<16];
static int thr(void*a){
  void*m=mmap(0,4096,PROT_READ|PROT_WRITE,MAP_PRIVATE|MAP_ANONYMOUS,-1,0);
  memcpy(m,CODE,6);
  if(mprotect(m,4096,PROT_READ|PROT_EXEC)==0){int v=((int(*)(void))m)();printf("THREAD mprotect RX BYPASS ret=%d\n",v);_exit(9);}
  printf("thread mprotect bloqueado errno=%d\n",errno);_exit(0);
}
int main(){
  // 1) memfd + mmap PROT_EXEC
  int fd=syscall(SYS_memfd_create,"x",0U);
  write(fd,CODE,6);
  void*m=mmap(0,4096,PROT_READ|PROT_EXEC,MAP_SHARED,fd,0);
  if(m!=MAP_FAILED){int v=((int(*)(void))m)();printf("memfd-mmap-exec BYPASS ret=%d\n",v);return 9;}
  printf("memfd mmap exec bloqueado errno=%d\n",errno);
  // 2) thread via clone (inherits filter?)
  pid_t p=clone(thr,stk+sizeof stk,CLONE_VM|CLONE_FILES|SIGCHLD,0);
  if(p>0){int st;waitpid(p,&st,0);}
  return 0;
}
