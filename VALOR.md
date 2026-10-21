# VALOR — sistema 9 (`fnbr-elf-zk-loader`)

**Fecha:** 2026-10-21 (America/Buenos_Aires)
**Commits bajo prueba:** `7bd0e8a` / `319e447` / `2a589dd`
**Umbral (Research Sentinel, fijo):** PASS solo si el **100 %** de los intentos
de ejecución no autorizados / sin firma (en alcance) se bloquean **y** hay
**0 falsos positivos** sobre un corpus de binarios firmados válidos.
Cualquier exec no autorizado que corra, o cualquier binario válido rechazado = **FAIL**.

## Qué se midió

El sistema tiene dos superficies:

1. **`fnbr-load`** — cargador tipado de usuario: verifica `.fnbr.sig` y mapea
   ELF64 x86-64 `ET_EXEC` estático (sin PIE, sin intérprete) con W^X.
2. **`fnbr-supervise`** — cumplimiento real vía seccomp `USER_NOTIF` sobre
   `mmap`/`mprotect` con `PROT_EXEC`. Es la pieza que debería impedir que otro
   proceso saltee el cargador.

El umbral se juzga sobre ataques **en alcance**. `LIMITES.md` documenta:
cargador salteable (por eso existe el supervisor), filtro solo si se instala,
TOCTOU residual de `CONTINUE` / `mprotect` por ruta, ZK ≠ prueba de programa,
cargador mínimo sin `execve`. **Todo lo que `LIMITES.md` no excluye cuenta
como en alcance**, incluido el TOCTOU residual (riesgo documentado ≠ fuera de modelo).

## Método

- Corpus válido: **55** ELF firmados con el flujo normal (`prepare`+`sign` Ed25519),
  mezcla de guests `ET_EXEC` estáticos (sin libc, distintos tamaños/retornos),
  binarios estáticos glibc y dinámicos PIE + `libc.so.6` firmada.
- Ataques: familias con semillas 1..5, generadas de forma determinista.
- Baseline: Linux plano (sin filtro) y un wrapper sha256-allowlist trivial.
- Latencia: p50/p99 de `fnbr-load` vs `execve` plano de un estático comparable.
- Repro: `bash scripts/experimento-valor.sh` (escribe `experimento/out/` y este archivo).
- **No se modificó `src/`.**

## Corpus válido — FPR

| Superficie | OK | Rechazados (FP) | Total | FPR |
|------------|----|-----------------|-------|-----|
| `fnbr-load` (ET_EXEC estático firmado) | 40 | 0 | 40 | 0.00 % |
| `fnbr-supervise` (muestra: fixture + estáticos + dinámicos) | 11 | 0 | 11 | — |

Nota: un estático firmado bajo `fnbr-supervise` **corre**, pero un estático
**sin firma también corre** (el `execve` inicial no se verifica; ver ataques).
El FPR del loader es el que entra al umbral (0 exigido).

## Ataques por familia

| Familia | Alcance | Bloqueados/Total | % | Bypass (ids) |
|---------|---------|------------------|---|--------------|
| `anon-jit` | in-scope | 1/1 | 100 % | — |
| `append` | in-scope | 5/5 | 100 % | — |
| `byte-flip` | in-scope | 42/42 | 100 % | — |
| `byte-flip-sig` | in-scope | 5/5 | 100 % | — |
| `execve-unsigned-static` | in-scope | 0/5 | 0 % | sup-s1, sup-s2, sup-s3, sup-s4, sup-s5 |
| `key-rotation-replay` | in-scope | 5/5 | 100 % | — |
| `ld-preload` | in-scope | 3/3 | 100 % | — |
| `ld-preload-child` | in-scope | 1/1 | 100 % | — |
| `ldso-direct` | in-scope | 3/3 | 100 % | — |
| `malformed-elf` | in-scope | 25/25 | 100 % | — |
| `memfd-fexecve` | in-scope | 0/2 | 0 % | sup-s1, sup-s2 |
| `mprotect-toctou` | in-scope | 0/3 | 0 % | sup-s1, sup-s2, sup-s3 |
| `pt-interp` | in-scope | 2/4 | 50 % | sup-s1, sup-s2 |
| `read-implies-exec` | in-scope | 0/3 | 0 % | sup-s1, sup-s2, sup-s3 |
| `shebang-unsigned-script` | in-scope | 0/3 | 0 % | sup-s1, sup-s2, sup-s3 |
| `sig-swap` | in-scope | 5/5 | 100 % | — |
| `truncated` | in-scope | 5/5 | 100 % | — |
| `unsigned` | in-scope | 10/10 | 100 % | — |
| `unsigned-dyn-main` | in-scope | 0/3 | 0 % | sup-s1, sup-s2, sup-s3 |
| `wrong-key` | in-scope | 10/10 | 100 % | — |
| `no-filter-installed` | out-of-scope | 0/2 | 0 % | plain-s1, plain-s2 |
| `symlink-race-loader` | out-of-scope | 2/2 | 100 % | — |

**En alcance:** 122/143 bloqueados (85.3 %).

### Hallazgos críticos (bypasses en alcance)

1. **`execve` de binario estático sin firma** — Bajo el supervisor, `rawload exec`
   / `execve` directo de un ELF estático **sin** `.fnbr.sig` corre con código de
   salida del programa (p. ej. 42) e imprime su salida. El kernel mapea los
   `PT_LOAD` en el `execve` **sin** pasar por `mmap`/`mprotect` del usuario; el
   filtro seccomp no ve esas asignaciones. `LIMITES.md` no lo excluye.
2. **`memfd_create` + `execveat(AT_EMPTY_PATH)`** — Misma raíz: el mapeo lo hace
   el kernel en el exec; el estático unsigned corre.
3. **Main dinámico unsigned + `libc` firmada** — El supervisor verifica el archivo
   de respaldo de cada `mmap(PROT_EXEC)`. Las páginas de `libc` firmada pasan;
   las del **main** las pone el kernel en el `execve` y **nunca se verifican**.
   Resultado: main unsigned ejecuta.
4. **`mprotect` path-TOCTOU** — `mmap` RW del unsigned (sin `PROT_EXEC` → Continue),
   `rename` del path al firmado, `mprotect(RX)`: la política lee la **ruta** de
   `/proc/pid/maps`, ve el firmado y aprueba; las páginas privadas ya tienen el
   código evil (entry=666). Coherente con el riesgo residual de LIMITES, pero
   en alcance → falla el umbral.
5. **`personality(READ_IMPLIES_EXEC)` + `mmap(PROT_READ)`** — seccomp ve
   `prot=PROT_READ` (Continue sin verificar); el kernel agrega `PROT_EXEC`.
   Código unsigned corre (entry=666). No está en LIMITES.
6. **Shebang con intérprete firmado** — El intérprete (dash) firmado + libc
   firmada corren; el **texto del script** no se firma ni se verifica. Script
   arbitrario ejecuta lógica no autorizada.

### Lo que sí bloquea

- Loader: unsigned, otra clave, flips de un byte (texto/datos/cabeceras/tabla),
  append, swap de sección, truncado, ELF malformado, replay tras "rotación"
  (verificador con clave nueva).
- Supervisor: `mmap`/`mprotect` file-backed de unsigned / otra clave / adulterado;
  JIT anónimo; `LD_PRELOAD` de `.so` unsigned en el **hijo** (el mapa falla);
  `ld.so` unsigned como intérprete directo (sus `PROT_EXEC` se niegan).

## Baseline

- baseline plain Linux unsigned static: rc=42 (corre sin control)
- baseline sha256-allowlist: valid→rc=0, unsigned→rc=1

Linux plano no impone nada: el estático unsigned corre. Un allowlist sha256
trivial discrimina hash≠permitido, pero no cubre `PROT_EXEC` ni TOCTOU; es solo contexto.

## Latencia

| Tamaño approx (B) | n | load p50 (ms) | load p99 (ms) | plain exec p50 | plain exec p99 |
|------------------|---|---------------|---------------|----------------|----------------|
| 13424 | 45 | 0.998 | 2.163 | 0.352 | 2.874 |
| 17592 | 45 | 1.022 | 2.103 | 0.352 | 2.874 |
| 21688 | 45 | 1.011 | 2.05 | 0.352 | 2.874 |
| 25784 | 45 | 1.022 | 2.027 | 0.352 | 2.874 |
| 29880 | 45 | 1.032 | 1.7 | 0.352 | 2.874 |
| 33976 | 45 | 1.051 | 2.116 | 0.352 | 2.874 |
| 38072 | 45 | 1.0 | 2.137 | 0.352 | 2.874 |
| 42168 | 45 | 1.092 | 2.285 | 0.352 | 2.874 |

`fnbr-load` incluye verificación Ed25519 + mmap W^X en-proceso; no es un
`execve`. La comparación con plain exec es orientativa.

| Supervisor mmap firmado p50 | Supervisor p99 | rawload plano p50 | rawload plano p99 |
|-----------------------------|----------------|-------------------|-------------------|
| 1.72 | 6.353 | 0.404 | 1.536 |

Overhead del supervisor ≈ idas y vueltas USER_NOTIF + verificación Ed25519
por cada `PROT_EXEC` notificado.

## Bugs / remediaciones sugeridas (sin tocar `src/` en este experimento)

1. **Verificar el binario del `execve` inicial** antes de lanzarlo (o usar
   `execveat`+memfd propio solo tras verificar), y/o atrapar `execve`/`execveat`
   en el filtro seccomp y negar o re-verificar.
2. **Cerrar `READ_IMPLIES_EXEC`:** negar `personality` o tratar todo `mmap`
   file-backed como potencialmente ejecutable bajo ese flag.
3. **`mprotect`:** verificar por el inode/fd original (reabrir no basta si hubo
   rename); idealmente `mmap` RX directo del fd ya verificado y negar
   `mprotect→EXEC` sobre VMAs anónimas/privadas no atadas a un verify previo.
4. **Política de intérpretes/scripts:** firmar también el script o negar
   shebang / exigir que `argv[0]` y el intérprete estén en el allowlist firmado.
5. **Main dinámico:** el primer mapeo ejecutable del pathname de `execve` debe
   verificarse; hoy solo se ven los `mmap` posteriores (típicamente `.so`).

## Veredicto

**FAIL** — en alcance se bloquearon **122/143** (85.3 %); FPR del loader **0/40**.

El umbral exige 100 % de bloqueo en alcance y 0 FP. El loader tipado cumple
su contrato estrecho (ET_EXEC estático firmado / rechazos criptográficos),
pero el **supervisor —la pieza de cumplimiento real— no alcanza el umbral**:
cualquier `execve` de un ELF estático sin firma, `memfd+fexecve`, main
dinámico unsigned con libs firmadas, TOCTOU de `mprotect` y
`READ_IMPLIES_EXEC` ejecutan código no autorizado. No se maquilla.

## Reproducir

```bash
bash scripts/experimento-valor.sh
# artefactos: experimento/out/results.json, VALOR.md
cargo test && cargo clippy --all-targets -- -D warnings
```

## Límites del experimento

- Una máquina (box compartida), load variable; latencias ± ruido.
- Corpus de guests sintéticos + utils mínimas; no es un OS completo firmado.
- `alg=2` Schnorr no se re-mide aquí (mismo binding al hash; la falla es de
  cumplimiento de `PROT_EXEC`/`execve`, no del esquema de firma).
- BPF-LSM no disponible en este kernel (ya en LIMITES).
- El padre `fnbr-supervise` es dinámico: `LD_PRELOAD` lo afecta a él; el
  marcador por `/proc/self/exe` separa padre/hijo.

