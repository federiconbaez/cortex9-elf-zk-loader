// SPDX-License-Identifier: GPL-2.0
// Cumplimiento en kernel (diseño): niega PROT_EXEC sobre archivos cuyo inodo
// no esté en el mapa `verified_inodes`, que llenaría un daemon de usuario
// después de verificar .fnbr.sig. Este es el control que NO se puede saltear
// desde espacio de usuario, a diferencia del cargador de src/loader.rs.
//
// ESTADO EN LA COMPUTADORA COMPARTIDA: compila, pero NO carga — el kernel no
// tiene "bpf" en la lista de LSM activos (capability,landlock,selinux).
// Ver LIMITES.md para el error exacto.
//
// Límites del diseño aun con BPF-LSM: no cubre mmap anónimo + mprotect de
// memoria JIT (habría que tratarlo aparte) ni verifica la firma en el kernel:
// confía en el daemon que llena el mapa (y en que el archivo no cambie después;
// un diseño completo usaría fs-verity o IMA para atar el inodo al contenido).
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

#define PROT_EXEC 0x4
#define EPERM 1

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 4096);
    __type(key, __u64);   /* número de inodo */
    __type(value, __u8);
} verified_inodes SEC(".maps");

/* Modo: 0 = solo auditar (contar), 1 = negar. */
const volatile __u32 enforce = 0;

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 2);
    __type(key, __u32);
    __type(value, __u64);
} counters SEC(".maps");

static __always_inline int decide(struct file *file, unsigned long prot)
{
    if (!file || !(prot & PROT_EXEC))
        return 0;
    __u64 ino = BPF_CORE_READ(file, f_inode, i_ino);
    if (bpf_map_lookup_elem(&verified_inodes, &ino))
        return 0;
    __u32 k = 0;
    __u64 *c = bpf_map_lookup_elem(&counters, &k);
    if (c)
        __sync_fetch_and_add(c, 1);
    return enforce ? -EPERM : 0;
}

SEC("lsm/mmap_file")
int BPF_PROG(fnbr_mmap_file, struct file *file, unsigned long reqprot,
             unsigned long prot, unsigned long flags, int ret)
{
    if (ret)
        return ret;
    return decide(file, prot);
}

SEC("lsm/file_mprotect")
int BPF_PROG(fnbr_file_mprotect, struct vm_area_struct *vma,
             unsigned long reqprot, unsigned long prot, int ret)
{
    if (ret)
        return ret;
    return decide(vma->vm_file, prot);
}

char LICENSE[] SEC("license") = "GPL";
