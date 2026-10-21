//! FNBR #9 — cargador ELF con verificación criptográfica de `.fnbr.sig`.
//!
//! Flujo:
//! 1. `fnbr-sign` (paso post-link) escribe una firma Ed25519 dentro de la
//!    sección `.fnbr.sig` (128 B, no cargable) de un ELF ya enlazado.
//! 2. [`verify::verify_elf`] recalcula el digest del archivo (con la sección
//!    puesta en cero) y verifica la firma contra un conjunto de claves de
//!    confianza mediante el trait [`verify::ProofVerifier`].
//! 3. [`loader`] solo puede mapear segmentos con `PROT_EXEC` a partir de un
//!    [`verify::VerifiedElf`], tipo que solo se construye si la verificación
//!    pasó (typestate). Sin firma válida no hay camino a `PROT_EXEC` en la API.
//!
//! LÍMITE: esto es espacio de usuario. Cualquier proceso puede llamar a
//! `mmap(PROT_EXEC)` por su cuenta y saltarse este cargador. El cumplimiento
//! real necesita el kernel (BPF-LSM en `mmap_file`/`file_mprotect`); ver
//! `bpf/lsm_exec_guard.bpf.c` y `LIMITES.md`.

pub mod loader;
pub mod sigsection;
pub mod verify;
