# LIMITES — #9 (v0.3, pre-medición)

Documento de contrato **antes** de la remedición de valor. Todo lo que aquí
no se excluya cuenta como en alcance para el umbral.

## Superficies y contratos

### `fnbr-load` (cargador tipado)

- **En contrato:** ELF64 x86-64 `ET_EXEC` estático **sin libc / sin ABI de
  proceso** (guests `nostdlib` con `fnbr_entry` llamado como función). Verifica
  `.fnbr.sig` y mapea W^X en el proceso actual.
- **Fuera de contrato (redefinido antes de medir):** binarios estáticos
  **glibc** (necesitan pila, auxv y TLS que este cargador mínimo no arma) y
  cualquier PIE / `PT_INTERP`. Un glibc-static firmado verifica la firma y
  mapea, pero `call_entry` no es un `execve`: el proceso SIGSEGV. **No es un
  falso positivo criptográfico**; se excluye del denominador FPR del loader.
- **No es `execve`:** otro proceso puede saltearlo. Por eso existe el supervisor.

### `fnbr-supervise` (cumplimiento real)

- **En contrato:** ejecutables **estáticos** firmados (sin `PT_INTERP`, sin
  pila ejecutable). Se lanzan vía memfd sellado + `execveat(fd,"",AT_EMPTY_PATH)`.
- **Fuera de contrato (redefinido antes de medir):**
  - Binarios dinámicos / PIE (`PT_INTERP`): el kernel abriría el intérprete por
    ruta (TOCTOU). El gate los rechaza. Lanzar `ld.so` firmado + main firmado
    exigiría conceder `mmap(PROT_EXEC)` file-backed, y un `CONTINUE` sobre un
    archivo mutable es TOCTOU (demostrado). Por eso el contrato es estático.
  - Guests `nostdlib` del loader: su `e_entry` es una función, no un `_start`
    de proceso; bajo `execveat` no son un proceso válido. FPR del supervisor
    se mide sobre el corpus **process-form** (estáticos glibc).
- **Solo cubre procesos que instalen el filtro** (`fnbr-supervise` /
  `run_supervised`). Sin filtro = fuera de alcance (LIMITES histórico).

## Mecanismo v0.3 (qué cierra / qué no)

- Filtro seccomp USER_NOTIF: `execve` path → deny; solo `execveat(AT_EMPTY_PATH)`
  con contenido firmado; todo `PROT_EXEC` de usuario (`mmap`/`mprotect`/
  `pkey_mprotect`) → deny; arch ≠ x86-64 y x32 → `KILL`; inyección
  (`ptrace`, `process_vm_writev`, `userfaultfd`, `seccomp`,
  `prctl(PR_SET_SECCOMP)`, `io_uring_setup`, `shmat(SHM_EXEC)`) → deny.
- Landlock: niega `WRITE_FILE` bajo `/proc` → cierra `/proc/<pid>/mem`
  (FOLL_FORCE sobre `.text` r-x).
- Memfd sellado: los bytes que ejecuta el kernel son los verificados.

## Residuales declarados (no relajan el umbral)

- **BPF-LSM no disponible** en este kernel (`CONFIG_BPF_LSM` ausente).
- **vDSO / vsyscall:** no cuentan como FP ni como bypass.
- **`SECCOMP_USER_NOTIF_FLAG_CONTINUE`:** mitigado no usándolo para mapear
  código (se niega todo `PROT_EXEC` de usuario; el exec usa memfd sellado).
- **ZK ≠ prueba de programa** (`alg=2`).
- Claves de `fixtures/keys/` son públicas y de prueba.
- Landlock requiere ABI ≥ 1; si falta, `run_supervised` aborta el hijo (rc 94)
  en vez de lanzar sin la mitigación de `/proc/*/mem`.

## Evidencia

La remedición versiona el crudo bajo `experimento/valor/` (no gitignore).
