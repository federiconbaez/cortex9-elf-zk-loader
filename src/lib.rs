//! FNBR #9 — cargador ELF con verificación criptográfica de `.fnbr.sig`.
//!
//! Flujo:
//! 1. `fnbr-sign` (paso post-link) escribe una firma Ed25519 (o prueba Schnorr
//!    ZK, ver `verify`) dentro de la sección `.fnbr.sig` (128 B, no cargable)
//!    de un ELF ya enlazado.
//! 2. [`verify::verify_elf`] recalcula el digest del archivo (con la sección
//!    puesta en cero) y verifica la prueba contra un conjunto de claves de
//!    confianza mediante el trait [`verify::ProofVerifier`].
//! 3. [`loader`] solo puede mapear segmentos con `PROT_EXEC` a partir de un
//!    [`verify::VerifiedElf`], tipo que solo se construye si la verificación
//!    pasó (typestate). Sin firma válida no hay camino a `PROT_EXEC` en la API.
//! 4. [`supervisor`] aplica cumplimiento real en espacio de usuario vía
//!    seccomp `USER_NOTIF`: intercepta `mmap`/`mprotect` con `PROT_EXEC` y
//!    solo deja continuar si el archivo verifica. No requiere BPF-LSM ni root.
//!
//! LÍMITE: un proceso que nunca instale el filtro seccomp no está sujeto a
//! esto. BPF-LSM sería el límite de kernel; este host no lo tiene
//! (`CONFIG_BPF_LSM` ausente). Ver `LIMITES.md`.

pub mod loader;
pub mod sigsection;
pub mod supervisor;
pub mod verify;
