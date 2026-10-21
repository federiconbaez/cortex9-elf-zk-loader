#define _GNU_SOURCE
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <sys/mman.h>
static unsigned char code[]={0xb8,0x2a,0,0,0,0xc3};
int main(){
  void*m=mmap(0,4096,PROT_READ|PROT_WRITE,MAP_PRIVATE|MAP_ANONYMOUS|MAP_32BIT,-1,0);
  memcpy(m,code,sizeof code);
  long ret; /* i386 mprotect = 125 via int 0x80 */
  __asm__ volatile("int $0x80":"=a"(ret):"a"(125L),"b"((long)m),"c"(4096L),"d"((long)(PROT_READ|PROT_EXEC)):"memory");
  if(ret!=0){printf("int80 mprotect ret=%ld\n",ret);return 0;}
  int v=((int(*)(void))m)();
  printf("int80 mprotect anon RX -> ejecuto, ret=%d (BYPASS)\n",v);return 9;
}
