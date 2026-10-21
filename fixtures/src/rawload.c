/* rawload: cargador "hostil" para probar el supervisor seccomp del #9.
 *
 * NO verifica nada: mapea código con PROT_EXEC por su cuenta, como haría un
 * proceso que quiere saltearse el cargador de usuario. Si el supervisor
 * funciona, solo prospera cuando el archivo tiene una .fnbr.sig válida.
 *
 * Estático (glibc), así el kernel no carga ningún ld.so sin verificar.
 *
 * Modos y códigos de salida:
 *   mmap-exec <elf>  mmap de cada PT_LOAD con su prot final     0=corrió(296) 3=mmap negado
 *   mprotect  <elf>  mmap sin X y después mprotect(R|X)         0=corrió(296) 4=mprotect negado
 *   anon-jit         mmap anónimo RW + mprotect(R|X), y RWX      0=ambos negados 5=alguno pasó
 *   exec <ruta>      execve de otro binario                      0=negado      6=pasó
 *   personality      personality(READ_IMPLIES_EXEC)              0=negado      7=pasó
 *   thread           clone(CLONE_VM|CLONE_THREAD...)             0=negado      8=pasó
 *   1=uso/E/S  2=entry devolvió otro valor
 */
#define _GNU_SOURCE
#include <elf.h>
#include <errno.h>
#include <fcntl.h>
#include <sched.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/personality.h>
#include <sys/syscall.h>
#include <unistd.h>

#define PAGE 4096UL
#define DOWN(x) ((x) & ~(PAGE - 1))
#define UP(x) (((x) + PAGE - 1) & ~(PAGE - 1))

static int prot_of(Elf64_Word f)
{
    return ((f & PF_R) ? PROT_READ : 0) | ((f & PF_W) ? PROT_WRITE : 0) | ((f & PF_X) ? PROT_EXEC : 0);
}

static int load_and_run(const char *path, int via_mprotect)
{
    int fd = open(path, O_RDONLY | O_CLOEXEC);
    if (fd < 0) { perror("open"); return 1; }
    Elf64_Ehdr eh;
    if (pread(fd, &eh, sizeof eh, 0) != sizeof eh || memcmp(eh.e_ident, ELFMAG, SELFMAG)) {
        fprintf(stderr, "no es ELF\n"); return 1;
    }
    for (int i = 0; i < eh.e_phnum; i++) {
        Elf64_Phdr ph;
        if (pread(fd, &ph, sizeof ph, eh.e_phoff + (off_t)i * eh.e_phentsize) != sizeof ph) return 1;
        if (ph.p_type != PT_LOAD) continue;
        unsigned long a = DOWN(ph.p_vaddr), len = UP(ph.p_vaddr + ph.p_memsz) - a;
        int prot = prot_of(ph.p_flags);
        int first = via_mprotect ? (prot & ~PROT_EXEC) : prot;
        void *m = mmap((void *)a, len, first, MAP_PRIVATE | MAP_FIXED_NOREPLACE, fd, (off_t)DOWN(ph.p_offset));
        if (m == MAP_FAILED) {
            printf("mmap %#lx prot=%#x: errno=%d (%s)\n", a, first, errno, strerror(errno));
            return 3;
        }
        if (via_mprotect && (prot & PROT_EXEC)) {
            if (mprotect(m, len, prot) != 0) {
                printf("mprotect %#lx prot=%#x: errno=%d (%s)\n", a, prot, errno, strerror(errno));
                return 4;
            }
        }
    }
    long (*entry)(void) = (long (*)(void))eh.e_entry;
    long r = entry();
    printf("entry=%ld\n", r);
    return r == 296 ? 0 : 2;
}

static int anon_jit(void)
{
    static const unsigned char code[] = {0xb8, 0x2a, 0x00, 0x00, 0x00, 0xc3}; /* mov eax,42; ret */
    void *m = mmap(NULL, PAGE, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (m == MAP_FAILED) { perror("mmap rw"); return 1; }
    memcpy(m, code, sizeof code);
    int bad = 0;
    if (mprotect(m, PAGE, PROT_READ | PROT_EXEC) == 0) { printf("mprotect anon RX: PASÓ\n"); bad = 1; }
    else printf("mprotect anon RX: errno=%d\n", errno);
    void *w = mmap(NULL, PAGE, PROT_READ | PROT_WRITE | PROT_EXEC, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (w != MAP_FAILED) { printf("mmap anon RWX: PASÓ\n"); bad = 1; }
    else printf("mmap anon RWX: errno=%d\n", errno);
    return bad ? 5 : 0;
}

static int child_fn(void *arg) { (void)arg; return 0; }

int main(int argc, char **argv)
{
    setvbuf(stdout, NULL, _IONBF, 0);
    if (argc < 2) { fprintf(stderr, "uso: rawload modo [arg]\n"); return 1; }
    const char *m = argv[1];
    if (!strcmp(m, "mmap-exec") && argc == 3) return load_and_run(argv[2], 0);
    if (!strcmp(m, "mprotect") && argc == 3) return load_and_run(argv[2], 1);
    if (!strcmp(m, "anon-jit")) return anon_jit();
    if (!strcmp(m, "exec") && argc == 3) {
        char *av[] = {argv[2], NULL};
        execv(argv[2], av);
        printf("execve: errno=%d\n", errno);
        return 0;
    }
    if (!strcmp(m, "personality")) {
        if (personality(READ_IMPLIES_EXEC) == -1) { printf("personality: errno=%d\n", errno); return 0; }
        printf("personality: PASÓ\n");
        return 7;
    }
    if (!strcmp(m, "thread")) {
        static char stack[65536];
        int r = clone(child_fn, stack + sizeof stack, CLONE_VM | CLONE_FS | CLONE_FILES | CLONE_SIGHAND | CLONE_THREAD, NULL);
        if (r == -1) { printf("clone(CLONE_VM|CLONE_THREAD): errno=%d\n", errno); return 0; }
        printf("clone: PASÓ\n");
        return 8;
    }
    fprintf(stderr, "modo desconocido\n");
    return 1;
}
