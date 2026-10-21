# 09 — Cargador ELF con verificación de `.fnbr.sig` antes de `PROT_EXEC`

**Dueña:** בֶּן הָאֱלֹהִים הַחַי (rol de auditoría de seguridad)
**Pedido de Federico (20/10/2026):** linker y cargador ELF que verifique
pruebas criptográficas Zero-Knowledge en una sección `.fnbr.sig` antes de
permitir que el kernel mapee las páginas como ejecutables (`PROT_EXEC`).

## Flujo (v0.2)
```
gcc/ld ──► ELF ──► fnbr-sign prepare  (agrega .fnbr.sig = 128 B en cero, no cargable)
                └► fnbr-sign sign     (SHA-512 del archivo con la sección en cero,
                                       dominio "FNBR-ELF-SIG-v1", firma Ed25519)

A) Cargador tipado (API Rust, se puede saltear desde otro proceso):
   fnbr-load ──► verify_elf() ──► VerifiedElf ──► mmap RW → mprotect W^X → entry()

B) Cumplimiento real sin BPF-LSM (seccomp USER_NOTIF, sin root):
   fnbr-supervise <pub.hex> <programa> [args…]
     hijo: PR_SET_NO_NEW_PRIVS + filtro seccomp (mmap/mprotect → USER_NOTIF) + execve
     padre: lee /proc/<pid>/fd/<n>, verify_elf, CONTINUE o EPERM
```
Formato de `.fnbr.sig`: `magic "FNBRSIG1" | alg u32 | flags u32 | key_id = sha256(pubkey) [32] | prueba [64] | reservado [16]`.
- `alg=1` Ed25519 (implementado)
- `alg=2` reservado ZK (hoy siempre se rechaza; siguiente commit)

## Supervisor seccomp
Intercepta `mmap` y `mprotect` con `PROT_EXEC`. Para `mmap` con archivo lee
los bytes por el **mismo fd** (`/proc/<pid>/fd/<fd>`), no por la ruta de
`readlink`. Niega JIT anónimo. Ver TOCTOU en `LIMITES.md`.

Demo hostil: `fixtures/rawload` mapea código sin pasar por nuestro cargador.
Bajo el supervisor, solo el ELF firmado corre.

## Límites
Ver `LIMITES.md`. Resumen: sin instalar el filtro no hay cumplimiento; BPF-LSM
no carga en este kernel; `CONTINUE` no es un límite de seguridad absoluto;
la firma prueba origen e integridad, no inocuidad.

## Compilar y probar
```bash
bash scripts/build-fixtures.sh   # guest*.elf + rawload estático
cargo build && cargo test && cargo clippy --all-targets -- -D warnings
bash scripts/demo.sh
# supervisor a mano:
cargo run --bin fnbr-supervise -- fixtures/keys/test_pub.hex \
  fixtures/rawload mmap-exec fixtures/guest.signed.elf
```
