# LIMITES — #9

- **El cargador de usuario se puede saltear**: otro proceso puede llamar a
  `mmap(PROT_EXEC)` sin pasar por `loader.rs`. Por eso existe el supervisor.
- **El supervisor solo cubre procesos que instalen el filtro**: se instala en
  el hijo justo antes del `execve` (`fnbr-supervise` / `run_supervised`). Un
  proceso lanzado por fuera no está sujeto a esto.
- **BPF-LSM no disponible**: `bpf/lsm_exec_guard.bpf.c` compila, pero al cargarlo:
  `libbpf: prog 'fnbr_mmap_file': failed to find kernel BTF type ID of 'mmap_file': -3`.
  El kernel 6.12.94+ está compilado sin `CONFIG_BPF_LSM` (LSMs activos:
  capability, landlock, selinux). El camino de cumplimiento en esta máquina es
  seccomp USER_NOTIF, no LSM.
- **TOCTOU de `SECCOMP_USER_NOTIF_FLAG_CONTINUE`**: la documentación del kernel
  advierte que `CONTINUE` **no** es un límite de seguridad para chequeos
  basados en rutas. Mitigación: verificamos el contenido abriendo
  `/proc/<pid>/fd/<n>` (mismo open file description), no la ruta de
  `readlink`. Riesgo residual: el inode puede mutar entre la lectura y el
  `mmap` real del kernel; en `mprotect` solo tenemos la ruta de
  `/proc/<pid>/maps` (peor). No afirmamos perímetro de kernel.
- Cargador mínimo: solo ELF64 x86-64 `ET_EXEC` estático, sin relocaciones, sin
  PIE, y no es `execve`.
- La firma prueba origen e integridad, no inocuidad. Las claves de
  `fixtures/keys/` son públicas y de prueba.
- v0.2: el `alg=2` (ZK) está reservado y siempre se rechaza.
