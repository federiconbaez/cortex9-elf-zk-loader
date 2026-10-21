# AUDIT-valor — sistema 9 (`fnbr-elf-zk-loader`)

**Auditora:** Federica Research Sentinel · **Fecha:** 2026-10-21 (America/Buenos_Aires)
**Commit auditado:** `b14c2a0` (padre `7bd0e8a`). Solo box; no se tocó `host-de-pruebas`.

## Veredicto

**FALLA el umbral #9 (literal).** «Valor no demostrado» es correcto. Falla en las
cuatro categorías del umbral, no solo en «sin firma»:

| Categoría del umbral | Resultado | Evidencia |
|---|---|---|
| ELF sin firma | **FALLA** | execve estático 0/5, memfd+execveat 0/2, main dinámico 0/3, PT_INTERP (sup) 0/2; repro propio `us` rc=42 |
| ELF adulterado | **FALLA** | loader y `sup mmap` 100 %, pero un estático firmado con 1 byte cambiado corre por `execve` bajo el supervisor (`us.flip`, rc=42). El experimento no midió esta vía. |
| Firmado con otra clave | **FALLA** | loader 10/10, pero por `execve` corre (`us.wk`, rc=42). Tampoco se midió. |
| RWX/JIT anónimo bajo supervisor | **FALLA** | `anon-jit` 1/1 (n=1) solo cubre `mmap`/`mprotect`. **Hallazgos nuevos:** `pkey_mprotect(…, PROT_READ|PROT_EXEC, -1)` y `mprotect` i386 por `int $0x80` sobre una página anónima ejecutan código (ret=42). También pasa `READ_IMPLIES_EXEC` (0/3). |
| 0 FP sobre el corpus válido | Supervisor 55/55 sin rechazo. Loader: ver abajo. | |

El valor parcial es real: el **loader tipado** rechaza al 100 % lo criptográfico
(sin firma, otra clave, flips, append, sig-swap, truncado, malformado y clave rotada), y el
**supervisor** niega `mmap(PROT_EXEC)` file-backed no verificado, JIT anónimo vía
`mmap`/`mprotect`, `LD_PRELOAD` sin firma y `ld.so` directo. No es un mecanismo de
cumplimiento: cualquier proceso supervisado puede ejecutar código no autorizado de al menos
siete maneras.

## 1. Commit, árbol y diff
- HEAD `b14c2a0`, árbol limpio (solo ignorados: `target/`, `experimento/out/`, `fixtures/rawload`, `bpf/vmlinux.h`).
- `git diff 7bd0e8a b14c2a0`: `.gitignore`, `VALOR.md`, `experimento/harness.c`, `scripts/experimento-valor.sh`. **No toca `src/`.** ✔
- **Caveat:** `experimento/out/` (con `results.json` y los logs) está en `.gitignore`. La evidencia cruda **no está versionada**; solo `VALOR.md`.

## 2. Tests y clippy
- `cargo clippy --release --all-targets -- -D warnings`: limpio.
- `cargo test --release`: 13 + 16 + 9 = **38/38**. ✔

## 3. Re-corrida en un clon aparte (`/tmp/audit09`, ~39 s)
- `summary` y los 147 resultados de ataque (familia, id y bloqueado) **idénticos** a los de `experimento/out/results.json` de Ben: 122/143 en alcance, loader 0/40, sup 11/11, FAIL.
- Suma de familias verificada: 143 en total y 122 bloqueados. «byte-flip 47/47» = `byte-flip` 42 + `byte-flip-sig` 5.
- Fuera de alcance (4 casos, fuera del denominador): `no-filter-installed` 0/2, legítimo porque LIMITES dice que el filtro solo cubre a quien lo instala; y `symlink-race-loader` 2/2, que **no ejecuta nada**: se registra «bloqueado» con rc=0 fijo. No afecta al denominador, pero no es una medición.
- Latencia: `fnbr-load` p50 0,95–1,04 ms contra 0,387 ms de exec plano (Ben: 1,0–1,09 contra 0,352). Supervisor p50 1,60 ms contra 0,42 de rawload. Coincide.

## 4. 55 contra 40 (FP sobre el corpus completo, medido por Research)
Corpus: 40 guests `-nostdlib` ET_EXEC + 10 estáticos glibc + 5 dinámicos PIE.

| Tipo | n | Loader | Supervisor |
|---|---|---|---|
| guests nostdlib | 40 | 40/40 OK | 40/40 corren (vía `rawload mmap-exec`; entry = esperado 296..335)¹ |
| estáticos glibc | 10 | **10/10 verifican y mapean, después SIGSEGV (rc 139)** | 10/10 corren (Ben corrió 5; los otros 5 los corrí yo) |
| dinámicos PIE | 5 | 5/5 `Unsupported("solo ET_EXEC estático (sin PIE)")`, **por diseño** | 5/5 corren con la libc firmada en `LD_LIBRARY_PATH` |

¹ `rawload` devuelve rc=2 cuando entry≠296 (está fijado al guest canónico), así que con él
39/40 «fallan» aunque corrieron bien. El script de Ben no usa esa ruta para el FPR.

- **Supervisor: 0 FP sobre 55/55.** Pero en estáticos y en el main dinámico no discrimina: también corren los sin firma, adulterados y con otra clave.
- **Loader:** 0/40 vale solo para los guests nostdlib. Los dinámicos quedan fuera por diseño (LIMITES: «ET_EXEC estático, sin PIE»), así que no son FP. Los **10 estáticos glibc sí están dentro del contrato documentado** (ET_EXEC estático sin PIE) y ninguno corre: la firma valida, pero el cargador no arma pila, auxv ni TLS. No es un rechazo criptográfico, aunque son binarios firmados válidos que no se pueden ejecutar: **10/50 (20 %) de fallo funcional dentro del contrato**. Excluirlos del denominador no estaba justificado en `VALOR.md`. No cambia el veredicto.

## 5. Agujero reproducido y causa raíz
`experimento/auditoria/repro.sh` (C mínimos en el mismo directorio):
- `fnbr-supervise test_pub.hex ./us` (estático glibc **sin firma**) → imprime y devuelve 42.
- Igual con `us.wk` (otra clave) y `us.flip` (firmado y adulterado): corren, rc=42, aunque `fnbr-load` los rechaza (`UnknownKey` y `BadSignature`).
- `pkey`: `mprotect` RX se niega (EPERM), pero `pkey_mprotect` RX **pasa** y ejecuta.
- `i386`: `mprotect` por `int $0x80` (nr 125) **pasa** y ejecuta.

Causa en `src/supervisor.rs`, `filter_program()` (líneas ~97–117): el cBPF solo notifica
`nr == 9 (mmap)` y `nr == 10 (mprotect)`, y todo lo demás es `SECCOMP_RET_ALLOW`. Por eso:
- `execve`/`execveat` (59/322) pasan, y lo que mapea el kernel (main, PT_INTERP) nunca se verifica. Esto confirma la causa que reportó Ben.
- `pkey_mprotect` (329) no está en el filtro.
- Si `arch != AUDIT_ARCH_X86_64`, salta a `ALLOW`, así que cualquier syscall i386 por `int $0x80` pasa sin filtro. Debería ser `KILL`.
- `personality` (135) no se filtra (`READ_IMPLIES_EXEC`).
- `policy_verify_fnbr` relee `mprotect` por la **ruta** de `/proc/pid/maps` (TOCTOU 0/3).

## 6. Otras observaciones del corpus de ataques
- `unsigned` 10/10 y `wrong-key` 10/10 son en realidad **2 pruebas distintas cada una** (loader y sup-mmap), repetidas 5 veces sobre el mismo archivo. La «semilla» no cambia nada.
- `byte-flip`: 6 offsets fijos por región; la semilla solo cambia el valor del XOR. El supervisor solo se muestreó con las semillas 1–2.
- `key-rotation-replay` equivale a otra clave: no hay revocación ni anti-replay real.
- `malformed-elf` también rompe la firma, así que no prueba el parser de forma independiente.
- `anon-jit` tiene n=1, y el umbral nombra explícitamente RWX anónimo.
- Ninguna familia de adulterados u otra clave se probó por `execve` bajo supervisor, que es donde fallan.

## 7. Condiciones para remedir (reapertura)
1. Corpus nuevo con **semilla fija, commiteado antes de remedir**, con muestras realmente distintas por semilla y la evidencia cruda (`results.json`, logs) **versionada**.
2. Las 7 familias de agujeros actuales, más estas variantes: `execveat(AT_EMPTY_PATH)` y por fd de path normal; `fexecve`; binfmt_misc o `binfmt_script` si aplica; shebang anidado; adulterados y otra clave **por `execve`** bajo supervisor.
3. Fuera de `mmap`/`mprotect`: `pkey_mprotect`, syscalls i386 por `int $0x80` y x32 (bit `0x40000000`), `remap_file_pages`/`mremap` de VMAs ejecutables, `personality` (RIE) también sobre una página anónima.
4. Inyección: `ptrace` (POKETEXT o regs) y `process_vm_writev` sobre `.text` de un hijo supervisado, `/proc/pid/mem`, `userfaultfd` en el rango de un `mmap` verificado, escritura de un archivo `MAP_SHARED` después del verify (inode compartido).
5. vDSO/vsyscall **no cuenta** como FP ni como bypass, pero hay que declararlo explícitamente.
6. FPR sobre el **corpus válido completo**, por superficie: loader con todos los ET_EXEC estáticos (incluido glibc) o el contrato del loader redefinido y commiteado antes; supervisor con todo, usando un harness que no tenga el valor de retorno fijado.
7. Latencia p50/p99 de exec bajo supervisor contra exec plano con el mismo binario, más el costo del hash por `execve`, con n declarado.
8. Mismo umbral: 100 % en alcance y 0 FP. Fuera de alcance, solo lo que LIMITES excluya **antes** de medir.

## Caveats
- Una sola re-corrida, en la box compartida (kernel 6.12.94+), no en `host-de-pruebas`.
- El bypass i386 depende de `IA32_EMULATION` en el kernel; acá está activo. x32 no se probó.
- No reproduje uno por uno los otros agujeros (memfd, dyn-main, TOCTOU, RIE, shebang, PT_INTERP): se confirman por la re-corrida idéntica y la lectura del filtro.
