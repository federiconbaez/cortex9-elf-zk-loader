# AUDIT-valor-v03 — sistema 9 (`fnbr-elf-zk-loader`), remedición v0.3

**Auditora:** Federica Research Sentinel · **Fecha:** 2026-10-22 (America/Buenos_Aires)
**Commit auditado:** `e1b9d79` (PASS 149/149). Clon aparte: `/workspace/audit-clones/09-v03`.
Hashes según el historial reescrito (ver `docs/HASHES.md`): la auditoría previa `64413db` es hoy `0689cab`.

## Veredicto

**PASS en lo medido, confirmado.** La re-corrida es idéntica: 149/149 en alcance, FP 0/40 en el loader y 0/55 en el supervisor. La salvedad es de **cobertura, no de resultado**: `mremap` y `remap_file_pages` tienen política en el código, pero **ningún caso del corpus los ejercita**.

## 1. Orden de commits (UTC → America/Buenos_Aires, UTC-3)

| Commit | Rol | Autor = committer (BA) |
|---|---|---|
| `b14c2a0` | experimento VALOR FAIL | 2026-10-21 00:36:43 |
| `0689cab` (ex `64413db`) | auditoría previa FALLA | 2026-10-21 00:41:47 |
| `198a7d4` | **pre-medición:** corpus, harness, contrato, LIMITES | 2026-10-21 01:23:45 |
| `6953a3d` | código del supervisor v0.3 (arreglo) | 2026-10-21 01:23:48 |
| `e1b9d79` | **medición** + crudo | 2026-10-21 01:24:15 |

- **El commit de corpus/harness/contrato existe y es anterior** al arreglo y a la medición: `198a7d4` < `6953a3d` < `e1b9d79`.
- `git diff 198a7d4..HEAD` sobre `experimento/harness.c`, `scripts/`, `fixtures/` y `LIMITES.md` sale **vacío**: el harness y el corpus no cambian después del commit de pre-medición. ✔
- **Local = remoto** para `e1b9d79`: el árbol es `756314f` en los dos (`gh api`). ✔
- Amenaza: entre los tres commits pasan 3 s y 27 s, así que se commitearon en tanda. El orden de los commits **no prueba** que el arreglo se escribiera después del corpus; prueba solo el orden en que se registraron.

## 2. Qué son los 149

- **Denominador = ataques en alcance** (149). No incluye el corpus válido (95 = 40 + 55), que se mide aparte como FP. Hay 26 familias. Fuera de alcance quedan 3 (`no-filter-installed` 2, que LIMITES excluye; `symlink-race-loader` 1).
- Frente al corpus previo (143 en alcance), **ninguna familia que haya fallado se sacó del denominador**. Se agregaron los agujeros: pkey 3, i386 3, x32 2, ptrace 2, vm_writev 2, uffd 2, /proc/mem 2, memfd 3, TOCTOU 3, RIE 3, MAP_SHARED 2, CoW 2, dyn-main 3, shebang 3, anon-jit 2.
- **Agujeros listados:**

| Agujero | ¿Lo ejercita el corpus? | ¿Bloqueado? |
|---|---|---|
| pkey_mprotect | sí (3) | sí |
| int $0x80 (i386) | sí (3) | sí, KILL (rc 128) |
| x32 | sí (2) | sí, KILL |
| personality / RIE | sí (3) | sí |
| execve de adulterados y de otra clave bajo el supervisor | sí (unsigned, wrong-key y byte-flip por sup-exec) | sí |
| TOCTOU de USER_NOTIF | sí (`mprotect-toctou` 3) | sí |
| **mremap / remap_file_pages** | **no: no hay ningún caso** | hay política en el código (`policy`, VMA exec → EPERM), pero **sin medir** |

- **Duplicados resueltos:** `unsigned` y `wrong-key` se recompilan por semilla (`U-{seed}` y `WK-{seed}`), así que son binarios distintos. ✔
- **Crudo versionado:** `experimento/valor/results.json` y los logs están en `e1b9d79`. ✔
- **296 fijo eliminado:** los guests devuelven 296+i, y `rawload` ya no espera 296 (`RAWLOAD_EXPECT` es opcional). ✔

## 3. Re-corrida en el clon aparte

- `cargo build --release` y `cargo clippy --release --all-targets -- -D warnings` salen limpios.
- `cargo test --release`: 17 + 16 + 23 = **56/56**.
- Medición (`experimento-valor.sh`, unos 19 s): los resultados son **idénticos** a los de Ben en las mismas claves (familia e id), con 0 diferencias. Recalculado desde el crudo: 149/149.
- Latencia del supervisor: p50 4,25 ms contra 0,43 ms de exec plano (Ben midió 4,86), con n=30.

### Umbral literal por superficie (100 % de bloqueo y 0 FP)

| Superficie | Bloqueo | FP | Veredicto |
|---|---|---|---|
| Loader (guests nostdlib) | 100 % de lo criptográfico | 0/40 | **PASS** |
| Supervisor (estáticos glibc) | 100 % de lo medido | 0/55 | **PASS** |
| glibc estático en el loader | fuera del contrato (LIMITES, `198a7d4`) | no aplica | **acotado, no arreglado** |

- **glibc estático:** el 10/50 de fallo funcional se resolvió **acotando el contrato**, no arreglando el loader. Desde `198a7d4`, LIMITES deja el glibc estático fuera del loader y dentro del supervisor, y la regla #6 de la auditoría previa lo permite. El loader sigue sin armar pila, auxv ni TLS, y `README` no debería decir que el loader corre glibc estático.

## 4. Exploratorio (fuera del corpus, aparte)

Probé dos vectores que no están en el corpus, con `exploratorio-v03.c` firmado y corrido bajo el supervisor:
- `memfd` + `mmap(PROT_EXEC, MAP_SHARED)`: **bloqueado** (EPERM).
- Hilo nuevo por `clone` después de instalado el filtro, haciendo `mprotect` RX: **bloqueado** (EPERM). El filtro se hereda.

En esos dos casos el PASS generaliza. **No** probé mremap ni remap_file_pages de un VMA ejecutable; quedan pendientes.

## 5. Amenazas a la validez

- **mremap y remap_file_pages no se miden:** se agregaron al código sin un caso de ataque.
- **El orden de commits es en tanda** (3 s y 27 s): no excluye que el arreglo se escribiera antes que el corpus.
- **n chico** en los ataques del harness (2 o 3 por familia, deterministas): «2/2» equivale a 1 prueba repetida.
- **El harness da «bloqueado» ante cualquier errno**, sin control positivo de que el ataque funcione fuera del supervisor.
- **El clasificador de byte-flip bajo el supervisor** acepta `rc > 90` como bloqueo, así que un crash contaría como bloqueado. Acá dio rc=93 en todos los casos, sin efecto.
- `symlink-race-loader` sigue sin ser una medición (rc=0 fijo), pero está fuera de alcance.
- **Una sola re-corrida**, en la box compartida (kernel 6.12.94+, con IA32_EMULATION), no en `host-de-pruebas`.

## Confianza

**Media-alta** en que el PASS 149/149 es correcto sobre el corpus medido. **Media** en la generalización, porque quedan sin medir mremap y remap_file_pages.
