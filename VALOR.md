# VALOR — sistema 9 (`fnbr-elf-zk-loader`) v0.3 remedición

**Fecha:** 2026-10-21 (America/Buenos_Aires)
**Commits:** pre-medición `c5836c3` → código `3a03bbe` → este de resultados.
**Umbral (Research Sentinel, fijo):** 100 % bloqueo en alcance **y** 0 FP
por superficie sobre el corpus válido del contrato.

## Contrato (LIMITES.md, pre-medición)

- **Loader:** guests `ET_EXEC` nostdlib. Glibc-static y PIE fuera.
- **Supervisor:** estáticos glibc process-form. PIE/`PT_INTERP` y guests
  nostdlib fuera. Solo procesos que instalan el filtro.

## Corpus válido — FPR

| Superficie | OK | FP | Total | FPR |
|------------|----|----|-------|-----|
| `fnbr-load` (guests nostdlib) | 40 | 0 | 40 | 0.00 % |
| `fnbr-supervise` (estáticos glibc) | 55 | 0 | 55 | 0.00 % |

## Ataques por familia

| Familia | Alcance | Bloqueados/Total | % | Bypass |
|---------|---------|------------------|---|--------|
| `anon-jit` | in-scope | 2/2 | 100 % | — |
| `append` | in-scope | 5/5 | 100 % | — |
| `byte-flip` | in-scope | 42/42 | 100 % | — |
| `byte-flip-sig` | in-scope | 5/5 | 100 % | — |
| `cow-dirty` | in-scope | 2/2 | 100 % | — |
| `i386-int80` | in-scope | 3/3 | 100 % | — |
| `key-rotation-replay` | in-scope | 5/5 | 100 % | — |
| `malformed-elf` | in-scope | 25/25 | 100 % | — |
| `map-shared-exec` | in-scope | 2/2 | 100 % | — |
| `memfd-fexecve` | in-scope | 3/3 | 100 % | — |
| `mprotect-toctou` | in-scope | 3/3 | 100 % | — |
| `pkey-mprotect` | in-scope | 3/3 | 100 % | — |
| `proc-self-mem` | in-scope | 2/2 | 100 % | — |
| `process-vm-writev` | in-scope | 2/2 | 100 % | — |
| `ptrace-poketext` | in-scope | 2/2 | 100 % | — |
| `read-implies-exec` | in-scope | 3/3 | 100 % | — |
| `shebang-unsigned-script` | in-scope | 3/3 | 100 % | — |
| `sig-swap` | in-scope | 5/5 | 100 % | — |
| `truncate` | in-scope | 5/5 | 100 % | — |
| `unsigned` | in-scope | 10/10 | 100 % | — |
| `unsigned-dyn-main` | in-scope | 3/3 | 100 % | — |
| `userfaultfd` | in-scope | 2/2 | 100 % | — |
| `wrong-key` | in-scope | 10/10 | 100 % | — |
| `x32-syscall` | in-scope | 2/2 | 100 % | — |
| `no-filter-installed` | out-of-scope | 0/2 | 0 % | plain-s1, plain-s2 |
| `symlink-race-loader` | out-of-scope | 1/1 | 100 % | — |

**En alcance:** 149/149 bloqueados (100.0 %).

## Latencia

| Tamaño approx (B) | n | load p50 | load p99 | plain p50 | plain p99 |
|------------------|---|----------|----------|-----------|-----------|
| 13424 | 30 | 0.908 | 1.064 | 0.314 | 0.679 |
| 17592 | 30 | 0.872 | 1.147 | 0.314 | 0.679 |
| 21688 | 30 | 0.927 | 1.131 | 0.314 | 0.679 |
| 25784 | 30 | 0.978 | 1.279 | 0.314 | 0.679 |
| 29880 | 30 | 0.924 | 1.187 | 0.314 | 0.679 |
| 33976 | 30 | 0.998 | 1.393 | 0.314 | 0.679 |
| 38072 | 30 | 1.061 | 1.445 | 0.314 | 0.679 |
| 42168 | 30 | 0.852 | 1.128 | 0.314 | 0.679 |

| Supervisor exec firmado p50 | p99 | plain p50 | plain p99 | n |
|-----------------------------|-----|-----------|-----------|---|
| 4.863 | 5.727 | 0.463 | 6.242 | 30/30 |

## Veredicto

**PASS** — en alcance **149/149** (100.0 %); FPR loader **0/40**; FPR supervisor **0/55**.

Cumple el umbral de Research Sentinel sin relajarlo.

## Reproducir

```bash
bash scripts/experimento-valor.sh
# artefactos: experimento/valor/results.json, VALOR.md
```

