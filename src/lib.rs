//! FNBR #9 — cargador ELF con verificación criptográfica de `.fnbr.sig`.
//!
//! Flujo:
//! 1. `fnbr-sign` escribe Ed25519 (`alg=1`) o Schnorr/Ristretto ZK (`alg=2`)
//!    en `.fnbr.sig` (128 B, no cargable).
//! 2. [`verify::verify_elf`] + [`verify::ProofVerifier`].
//! 3. [`loader`] solo concede `PROT_EXEC` a un [`verify::VerifiedElf`] (typestate).
//! 4. [`supervisor`] aplica cumplimiento real vía seccomp `USER_NOTIF`.
//!
//! Sobre la prueba ZK: ver módulo [`zk`] y README (qué se prueba / qué no).

pub mod loader;
pub mod sigsection;
pub mod supervisor;
pub mod verify;
pub mod zk;
