# LIMITES — #9

- **El cargador de usuario se puede saltear**: otro proceso puede llamar a
  `mmap(PROT_EXEC)` sin pasar por `loader.rs`. Por eso existe el supervisor.
- **El supervisor solo cubre procesos que instalen el filtro**: se instala en
  el hijo justo antes del `execve` (`fnbr-supervise` / `run_supervised`).
- **BPF-LSM no disponible**: `bpf/lsm_exec_guard.bpf.c` compila, pero al cargarlo:
  `libbpf: prog 'fnbr_mmap_file': failed to find kernel BTF type ID of 'mmap_file': -3`.
  Kernel 6.12.94+ sin `CONFIG_BPF_LSM`. Cumplimiento aquí = seccomp USER_NOTIF.
- **TOCTOU de `SECCOMP_USER_NOTIF_FLAG_CONTINUE`**: el kernel advierte que
  `CONTINUE` no es un límite de seguridad para chequeos por ruta. Mitigación:
  leer por `/proc/<pid>/fd/<n>` (mismo open file). Riesgo residual si el inode
  muta entre lectura y `mmap`; en `mprotect` solo hay ruta de `/proc/.../maps`.
- **ZK ≠ prueba de programa**: `alg=2` demuestra conocimiento del DL de la
  clave del publicador atado al hash del binario. No demuestra corrección ni
  inocuidad del código.
- Cargador mínimo: ELF64 x86-64 `ET_EXEC` estático, sin PIE, no es `execve`.
- Claves de `fixtures/keys/` son públicas y de prueba.
