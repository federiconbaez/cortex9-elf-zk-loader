# Hashes / Historial reescrito

**ES:** El 2026-10-22 se reescribió todo el historial de este repositorio (git-filter-repo) para quitar datos del host y del usuario (nombre de máquina, usuario, uid, rutas de cgroup, versión de kernel). Los commits cambiaron de hash; los documentos de auditoría citan los hashes viejos. Esta tabla da la equivalencia.

**EN:** On 2026-10-22 this repository's full history was rewritten (git-filter-repo) to remove host and user data. Commit hashes changed; audit documents cite the old hashes. This table maps old → new.

| Viejo / Old | Nuevo / New | Fecha (UTC) | Mensaje / Message |
|---|---|---|---|
| `525fcd8` | `525fcd8` | 2026-10-21T02:03:21Z | 09: .fnbr.sig Ed25519 + cargador typestate W^X, trait ProofVerifier (ZK reservado, rechaza), guard BPF-LSM (no carga: kernel sin CONFIG_BPF_LSM), fixtures y 16 tests |
| `44fcf0e` | `44fcf0e` | 2026-10-21T02:03:39Z | 09: README, LIMITES, VERIFICADO en español |
| `2a589dd` | `2a589dd` | 2026-10-21T02:22:30Z | 09: supervisor seccomp USER_NOTIF — cumplimiento real de PROT_EXEC sin BPF-LSM |
| `319e447` | `319e447` | 2026-10-21T02:28:54Z | 09: Schnorr/Ristretto Fiat-Shamir (alg=2) — ZK genuina atada al hash del ELF |
| `7bd0e8a` | `7bd0e8a` | 2026-10-21T02:32:27Z | 09: README aclara que alg=2 es una firma Schnorr (ZK sobre la clave, no sobre el programa) — nota de Research |
| `b14c2a0` | `b14c2a0` | 2026-10-21T03:36:43Z | 09: experimento VALOR — FAIL el umbral de Research (execve/TOCTOU/RIE) |
| `64413db` | `0689cab` | 2026-10-21T03:41:47Z | 09: auditoría de Research del experimento VALOR — FALLA confirmado (execve, pkey_mprotect, int 0x80); FP sobre los 55 |
| `c5836c3` | `198a7d4` | 2026-10-21T04:23:45Z | 09: pre-medición v0.3 — corpus, contrato glibc-static y evidencia versionada |
| `3a03bbe` | `6953a3d` | 2026-10-21T04:23:48Z | 09: supervisor v0.3 — memfd sellado + execveat, Landlock, niega PROT_EXEC de usuario |
| `0759a66` | `e1b9d79` | 2026-10-21T04:24:15Z | 09: remedición VALOR v0.3 — PASS 149/149, FPR 0/40 loader y 0/55 supervisor |
| `e33e31c` | `a87add3` | 2026-10-22 | Licencia Apache-2.0 (mensaje reescrito con formato nuevo / rewritten message) |
