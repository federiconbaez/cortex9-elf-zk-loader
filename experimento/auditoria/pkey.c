#define _GNU_SOURCE
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <sys/mman.h>
#include <unistd.h>
#include <sys/syscall.h>
static unsigned char code[]={0xb8,0x2a,0,0,0,0xc3}; /* mov eax,42; ret */
int main(){
  void*m=mmap(0,4096,PROT_READ|PROT_WRITE,MAP_PRIVATE|MAP_ANONYMOUS,-1,0);
  memcpy(m,code,sizeof code);
  if(mprotect(m,4096,PROT_READ|PROT_EXEC)==0){printf("mprotect RX PASO\n");}
  else printf("mprotect RX errno=%d\n",errno);
  long r=syscall(SYS_pkey_mprotect,m,4096,PROT_READ|PROT_EXEC,-1);
  if(r!=0){printf("pkey_mprotect errno=%d\n",errno);return 0;}
  int v=((int(*)(void))m)();
  printf("pkey_mprotect anon RX -> ejecuto, ret=%d (BYPASS)\n",v);return 9;
}
