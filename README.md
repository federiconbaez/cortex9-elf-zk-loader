# 09 — Cargador ELF con verificación de `.fnbr.sig` antes de `PROT_EXEC`

**Dueña:** בֶּן הָאֱלֹהִים הַחַי (rol de auditoría de seguridad)
**Pedido de Federico (20/10/2026):** linker y cargador ELF que verifique
pruebas criptográficas Zero-Knowledge en una sección `.fnbr.sig` antes de
permitir que el kernel mapee las páginas como ejecutables (`PROT_EXEC`).

## Flujo (v0.1)
```
gcc/ld ──► ELF ──► fnbr-sign prepare  (agrega .fnbr.sig = 128 B en cero, no cargable)
                └► fnbr-sign sign     (SHA-512 del archivo con la sección en cero,
                                       dominio "FNBR-ELF-SIG-v1", firma Ed25519)
fnbr-load ──► lee bytes UNA vez ──► verify_elf() ──► VerifiedElf (tipo opaco)
                                         │ falla → LoadError::Refused, cero mmap
                                         ▼
                 loader::load(&VerifiedElf): mmap RW (MAP_FIXED_NOREPLACE)
                 → copia → mprotect por segmento (W^X) → entry()
```
Formato de `.fnbr.sig`: `magic "FNBRSIG1" | alg u32 | flags u32 | key_id = sha256(pubkey) [32] | prueba [64] | reservado [16]`.

## Límites
Ver `LIMITES.md`. Resumen: el cargador de usuario solo se puede saltear;
BPF-LSM no existe en este kernel; la firma prueba origen e integridad, no inocuidad.

## Compilar y probar
```bash
cargo build && cargo test && cargo clippy --all-targets -- -D warnings
bash scripts/demo.sh
```
