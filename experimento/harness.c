/* Harness de ataques para el experimento VALOR del #9 (supervisor seccomp), v0.2.
 * Corre BAJO fnbr-supervise como binario FIRMADO (el supervisor solo lanza
 * programas firmados). Cada modo intenta ejecutar/mapear/inyectar codigo NO
 * firmado por una via distinta, desde dentro del proceso confinado.
 *   exit 0  = ataque BLOQUEADO (el codigo no firmado NO corrio)
 *   exit 9  = BYPASS (codigo no firmado llego a ejecutarse)
 *   otros   = error de armado (se trata como no-bypass)
 * Si el filtro MATA el proceso (i386/x32) el padre ve SIGSYS: eso es bloqueo.
 */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <sched.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/ptrace.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/uio.h>
#include <sys/wait.h>
#include <unistd.h>
#include <linux/userfaultfd.h>

#define PAGE 4096UL
#define DOWN(x) ((x) & ~(PAGE - 1))
#define UP(x) (((x) + PAGE - 1) & ~(PAGE - 1))
__attribute__((noinline)) int procmem_target(void){ return 42; }
static unsigned char CODE[] = {0xb8, 0x2a, 0, 0, 0, 0xc3}; /* mov eax,42; ret */

static int do_memfd(const char *path){
    int src=open(path,O_RDONLY); if(src<0){perror("open");return 1;}
    struct stat st; fstat(src,&st);
    char *buf=malloc(st.st_size); if(read(src,buf,st.st_size)!=st.st_size){return 1;}
    int fd=syscall(SYS_memfd_create,"x",0U);
    if(fd<0){printf("memfd: errno=%d\n",errno);return 0;}
    if(write(fd,buf,st.st_size)!=st.st_size){return 1;}
    char *av[]={(char*)"x",NULL}, *ev[]={NULL};
    syscall(SYS_execveat,fd,"",av,ev,AT_EMPTY_PATH);
    printf("fexecve memfd: errno=%d (bloqueado)\n",errno);
    return 0;
}

static int do_toctou(const char *uns,const char *sgn){
    int fd=open(uns,O_RDONLY); if(fd<0){perror("open uns");return 1;}
    unsigned char hdr[64]; pread(fd,hdr,64,0);
    unsigned long entry=*(unsigned long*)(hdr+24);
    unsigned short phnum=*(unsigned short*)(hdr+56);
    unsigned long phoff=*(unsigned long*)(hdr+32);
    unsigned short phentsize=*(unsigned short*)(hdr+54);
    for(int i=0;i<phnum;i++){
        unsigned char ph[56]; pread(fd,ph,56,phoff+(unsigned long)i*phentsize);
        if(*(unsigned int*)(ph+0)!=1) continue;
        if(!(*(unsigned int*)(ph+4)&1)) continue;
        unsigned long vaddr=*(unsigned long*)(ph+16), off=*(unsigned long*)(ph+8), memsz=*(unsigned long*)(ph+40);
        unsigned long a=DOWN(vaddr), len=UP(vaddr+memsz)-a;
        void *m=mmap((void*)a,len,PROT_READ|PROT_WRITE,MAP_PRIVATE|MAP_FIXED_NOREPLACE,fd,DOWN(off));
        if(m==MAP_FAILED){printf("mmap RW: errno=%d\n",errno);return 3;}
        if(rename(sgn,uns)!=0){perror("rename");}
        if(mprotect((void*)a,len,PROT_READ|PROT_EXEC)!=0){printf("mprotect RX: errno=%d (bloqueado)\n",errno);return 0;}
        long (*e)(void)=(long(*)(void))entry; long r=e();
        printf("TOCTOU entry=%ld (BYPASS)\n",r); return 9;
    }
    printf("sin segmento X\n"); return 1;
}

#include <sys/personality.h>
static int do_rie(const char *uns){
    if(personality(READ_IMPLIES_EXEC)==-1){printf("personality: errno=%d (bloqueado)\n",errno);return 0;}
    int fd=open(uns,O_RDONLY); if(fd<0){perror("open");return 1;}
    unsigned char hdr[64]; pread(fd,hdr,64,0);
    unsigned long entry=*(unsigned long*)(hdr+24);
    unsigned short phnum=*(unsigned short*)(hdr+56);
    unsigned long phoff=*(unsigned long*)(hdr+32);
    unsigned short phentsize=*(unsigned short*)(hdr+54);
    for(int i=0;i<phnum;i++){
        unsigned char ph[56]; pread(fd,ph,56,phoff+(unsigned long)i*phentsize);
        if(*(unsigned int*)(ph+0)!=1) continue;
        unsigned long vaddr=*(unsigned long*)(ph+16), off=*(unsigned long*)(ph+8), memsz=*(unsigned long*)(ph+40);
        unsigned long a=DOWN(vaddr), len=UP(vaddr+memsz)-a;
        int prot=PROT_READ | ((*(unsigned int*)(ph+4)&2)?PROT_WRITE:0);
        void *m=mmap((void*)a,len,prot,MAP_PRIVATE|MAP_FIXED_NOREPLACE,fd,DOWN(off));
        if(m==MAP_FAILED){printf("mmap: errno=%d\n",errno);return 3;}
    }
    long (*e)(void)=(long(*)(void))entry; long r=e();
    printf("READ_IMPLIES_EXEC entry=%ld (BYPASS)\n",r); return 9;
}

/* pkey_mprotect RX sobre pagina anonima */
static int do_pkey(void){
    void*m=mmap(0,PAGE,PROT_READ|PROT_WRITE,MAP_PRIVATE|MAP_ANONYMOUS,-1,0);
    if(m==MAP_FAILED){perror("mmap");return 1;}
    memcpy(m,CODE,sizeof CODE);
    long r=syscall(SYS_pkey_mprotect,m,PAGE,PROT_READ|PROT_EXEC,-1);
    if(r!=0){printf("pkey_mprotect errno=%d (bloqueado)\n",errno);return 0;}
    int v=((int(*)(void))m)();
    printf("pkey anon RX ejecuto ret=%d (BYPASS)\n",v); return 9;
}

/* mprotect RX via int 0x80 (i386). El filtro debe MATAR el proceso. */
static int do_i386(void){
    void*m=mmap(0,PAGE,PROT_READ|PROT_WRITE,MAP_PRIVATE|MAP_ANONYMOUS|MAP_32BIT,-1,0);
    if(m==MAP_FAILED){perror("mmap32");return 1;}
    memcpy(m,CODE,sizeof CODE);
    long ret;
    __asm__ volatile("int $0x80":"=a"(ret):"a"(125L),"b"((long)m),"c"(PAGE),"d"((long)(PROT_READ|PROT_EXEC)):"memory");
    if(ret!=0){printf("int80 mprotect ret=%ld (bloqueado)\n",ret);return 0;}
    int v=((int(*)(void))m)();
    printf("int80 anon RX ejecuto ret=%d (BYPASS)\n",v); return 9;
}

/* mprotect RX via x32 (bit 0x40000000). El filtro debe MATAR el proceso. */
static int do_x32(void){
    void*m=mmap(0,PAGE,PROT_READ|PROT_WRITE,MAP_PRIVATE|MAP_ANONYMOUS,-1,0);
    if(m==MAP_FAILED){perror("mmap");return 1;}
    memcpy(m,CODE,sizeof CODE);
    long r=syscall(0x40000000UL | 10UL, (long)m, PAGE, PROT_READ|PROT_EXEC); /* x32 mprotect */
    if(r!=0){printf("x32 mprotect r=%ld errno=%d (bloqueado)\n",r,errno);return 0;}
    int v=((int(*)(void))m)();
    printf("x32 anon RX ejecuto ret=%d (BYPASS)\n",v); return 9;
}

/* ptrace POKETEXT: el padre hace PTRACE_ATTACH a un hijo e intenta escribir su .text */
static int do_ptrace(void){
    pid_t c=fork();
    if(c==0){ for(;;) pause(); _exit(0); }
    int st;
    long a=ptrace(PTRACE_ATTACH,c,0,0);
    if(a!=0){printf("ptrace ATTACH errno=%d (bloqueado)\n",errno); kill(c,SIGKILL); waitpid(c,&st,0); return 0;}
    waitpid(c,&st,WUNTRACED);
    long r=ptrace(PTRACE_POKETEXT,c,(void*)0x400000,(void*)0x9090909090909090UL);
    ptrace(PTRACE_KILL,c,0,0); kill(c,SIGKILL); waitpid(c,&st,0);
    if(r!=0){printf("ptrace POKETEXT errno=%d (bloqueado)\n",errno);return 0;}
    printf("ptrace POKETEXT paso (BYPASS)\n"); return 9;
}

/* process_vm_writev sobre .text de un hijo */
static int do_vmwritev(void){
    pid_t c=fork();
    if(c==0){ for(;;) pause(); _exit(0); }
    unsigned char payload[6]; memcpy(payload,CODE,6);
    struct iovec local={payload,6}, remote={(void*)0x400000,6};
    long r=process_vm_writev(c,&local,1,&remote,1,0);
    int st; kill(c,SIGKILL); waitpid(c,&st,0);
    if(r<0){printf("process_vm_writev errno=%d (bloqueado)\n",errno);return 0;}
    printf("process_vm_writev escribio %ld (BYPASS)\n",r); return 9;
}

/* userfaultfd: handle de fallos sobre un mmap verificado -> TOCTOU de contenido */
static int do_uffd(void){
    long u=syscall(SYS_userfaultfd,O_CLOEXEC|O_NONBLOCK);
    if(u<0){printf("userfaultfd errno=%d (bloqueado)\n",errno);return 0;}
    printf("userfaultfd fd=%ld (BYPASS potencial)\n",u); return 9;
}

/* MAP_SHARED + PROT_EXEC de un archivo escribible, re-escrito despues del verify */
static int do_mapshared(const char *sgn){
    int fd=open(sgn,O_RDONLY); if(fd<0){perror("open");return 1;}
    void*m=mmap(0,PAGE,PROT_READ|PROT_EXEC,MAP_SHARED,fd,0);
    if(m==MAP_FAILED){printf("mmap SHARED exec: errno=%d (bloqueado)\n",errno);return 0;}
    printf("mmap SHARED exec paso (BYPASS potencial)\n"); return 9;
}


/* /proc/self/mem: escribir codigo no firmado sobre una pagina r-x propia (FOLL_FORCE). */
static int do_procmem(void){
    /* pagina ejecutable propia: la funcion target vive en .text firmado */
    extern int procmem_target(void);
    unsigned long a=(unsigned long)procmem_target;
    int fd=open("/proc/self/mem",O_RDWR);
    if(fd<0){printf("open /proc/self/mem errno=%d (bloqueado)\n",errno);return 0;}
    unsigned char code[]={0xb8,0x9a,0x02,0,0,0xc3}; /* mov eax,666; ret */
    if(pwrite(fd,code,sizeof code,(off_t)a)!=(ssize_t)sizeof code){printf("pwrite /proc/self/mem errno=%d (bloqueado)\n",errno);return 0;}
    int v=procmem_target();
    if(v==666){printf("/proc/self/mem reescribio .text ret=%d (BYPASS)\n",v);return 9;}
    printf("/proc/self/mem sin efecto ret=%d\n",v); return 0;
}

/* CoW sucio: mapear un archivo FIRMADO privado R|W, reescribir el entry con
 * codigo no firmado, bajar a R y luego pedir R|X. El inodo sigue siendo el
 * firmado, pero las paginas privadas ya no lo son. */
static int do_cowdirty(const char *sgn){
    int fd=open(sgn,O_RDONLY); if(fd<0){perror("open");return 1;}
    unsigned char hdr[64]; pread(fd,hdr,64,0);
    unsigned long entry=*(unsigned long*)(hdr+24);
    unsigned short phnum=*(unsigned short*)(hdr+56);
    unsigned long phoff=*(unsigned long*)(hdr+32);
    unsigned short phentsize=*(unsigned short*)(hdr+54);
    for(int i=0;i<phnum;i++){
        unsigned char ph[56]; pread(fd,ph,56,phoff+(unsigned long)i*phentsize);
        if(*(unsigned int*)(ph+0)!=1) continue;
        if(!(*(unsigned int*)(ph+4)&1)) continue;
        unsigned long vaddr=*(unsigned long*)(ph+16), off=*(unsigned long*)(ph+8), memsz=*(unsigned long*)(ph+40);
        unsigned long a=DOWN(vaddr), len=UP(vaddr+memsz)-a;
        void *m=mmap((void*)a,len,PROT_READ|PROT_WRITE,MAP_PRIVATE|MAP_FIXED_NOREPLACE,fd,DOWN(off));
        if(m==MAP_FAILED){printf("mmap RW: errno=%d\n",errno);return 3;}
        unsigned char code[]={0xb8,0x9a,0x02,0,0,0xc3}; /* mov eax,666; ret */
        memcpy((void*)entry,code,sizeof code);           /* CoW: pagina privada sucia */
        if(mprotect((void*)a,len,PROT_READ)!=0){printf("mprotect R errno=%d\n",errno);return 1;}
        if(mprotect((void*)a,len,PROT_READ|PROT_EXEC)!=0){printf("mprotect RX: errno=%d (bloqueado)\n",errno);return 0;}
        long r=((long(*)(void))entry)();
        printf("CoW-dirty entry=%ld (BYPASS)\n",r); return r==666?9:2;
    }
    return 1;
}

int main(int argc,char**argv){
    setvbuf(stdout,NULL,_IONBF,0);
    if(argc<2){fprintf(stderr,"uso: harness modo args\n");return 1;}
    const char*m=argv[1];
    if(!strcmp(m,"memfd-fexecve")&&argc==3) return do_memfd(argv[2]);
    if(!strcmp(m,"mprotect-toctou")&&argc==4) return do_toctou(argv[2],argv[3]);
    if(!strcmp(m,"read-implies-exec")&&argc==3) return do_rie(argv[2]);
    if(!strcmp(m,"pkey")) return do_pkey();
    if(!strcmp(m,"i386")) return do_i386();
    if(!strcmp(m,"x32")) return do_x32();
    if(!strcmp(m,"ptrace")) return do_ptrace();
    if(!strcmp(m,"vmwritev")) return do_vmwritev();
    if(!strcmp(m,"uffd")) return do_uffd();
    if(!strcmp(m,"mapshared")&&argc==3) return do_mapshared(argv[2]);
    if(!strcmp(m,"procmem")) return do_procmem();
    if(!strcmp(m,"cow-dirty")&&argc==3) return do_cowdirty(argv[2]);
    fprintf(stderr,"modo desconocido\n"); return 1;
}
