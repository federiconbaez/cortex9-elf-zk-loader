# LIMITES — #9

- **El cargador de usuario se puede saltear**: otro proceso puede llamar a `mmap(PROT_EXEC)` sin pasar por acá.
- **BPF-LSM no disponible**: `bpf/lsm_exec_guard.bpf.c` compila, pero al cargarlo:
  `libbpf: prog 'fnbr_mmap_file': failed to find kernel BTF type ID of 'mmap_file': -3`.
  El kernel 6.12.94+ está compilado sin `CONFIG_BPF_LSM` (LSMs activos: capability, landlock, selinux).
- Cargador mínimo: solo ELF64 x86-64 `ET_EXEC` estático, sin relocaciones, sin PIE, y no es `execve`.
- La firma prueba origen e integridad, no inocuidad. Las claves de `fixtures/keys/` son públicas y de prueba.
- v0.1: el `alg=2` (ZK) está reservado y siempre se rechaza.
