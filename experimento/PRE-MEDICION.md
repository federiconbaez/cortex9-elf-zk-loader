# Pre-medición v0.3 — corpus y contrato (antes de medir)

Este archivo se commitea **antes** del código de arreglo y **antes** de los
resultados. Los auditores verifican el orden.

## Corpus

- **Loader (FPR):** 40 guests `ET_EXEC` nostdlib, retorno `296+i` (muestra
  distinta por índice; no se repiten 2 archivos × 5 semillas).
- **Supervisor (FPR):** 55 estáticos glibc process-form (`static-s00` …
  `static-s54`), cada uno imprime y retorna `i%50`.
- **Ataques:** familias con semillas 1..5; unsigned/wrong-key se **recompilan**
  por semilla (binarios distintos). Harness firmado (`experimento/harness.c`)
  cubre pkey, i386, x32, ptrace, process_vm_writev, uffd, procmem, mapshared,
  cow-dirty, memfd-fexecve, mprotect-toctou, READ_IMPLIES_EXEC.

## Contrato del loader para glibc-static

**Redefinido en `LIMITES.md`:** el cargador tipado **no** arma pila/auxv/TLS.
Los 10 (ahora 55) glibc-static firmados están **fuera del contrato del loader**
y **dentro del contrato del supervisor**. No se implementa el setup de proceso
en `loader.rs` en esta remedición.

## Evidencia cruda

Versionada bajo `experimento/valor/` (`results.json`, logs). `experimento/out/`
sigue en `.gitignore` como scratch local.

## Harness

`experimento/harness.c` v0.2+: exit 0 = bloqueado, exit 9 = bypass. Sin
expectativa fija de retorno 296 en `rawload` (usa `RAWLOAD_EXPECT` opcional).
