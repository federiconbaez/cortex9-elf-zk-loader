//! Verificación de la prueba en `.fnbr.sig`, extensible por algoritmo.
//!
//! Hoy hay **un** verificador real: Ed25519 (firma, no Zero-Knowledge).
//! `ZkUnimplemented` existe para fijar la interfaz y siempre rechaza: no se
//! finge una prueba ZK que no se verifica.

use ed25519_dalek::{Signature, Verifier as _, VerifyingKey};
use sha2::{Digest, Sha256};

use crate::sigsection::{self, Alg, SectionError, SigSection};

#[derive(Debug, PartialEq, Eq)]
pub enum VerifyError {
    Section(SectionError),
    UnknownAlg(u32),
    /// Hay sección y algoritmo, pero ningún verificador registrado lo acepta.
    NoVerifierFor(Alg),
    /// El algoritmo existe en el formato pero no está implementado (ZK).
    Unsupported(&'static str),
    UnknownKey([u8; 32]),
    BadSignature,
}

impl std::fmt::Display for VerifyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            VerifyError::UnknownKey(k) => write!(f, "UnknownKey({})", hex::encode(k)),
            other => write!(f, "{other:?}"),
        }
    }
}
impl std::error::Error for VerifyError {}

impl From<SectionError> for VerifyError {
    fn from(e: SectionError) -> Self {
        VerifyError::Section(e)
    }
}

/// Un verificador de pruebas para un algoritmo. Implementar este trait es el
/// punto de extensión para un verificador ZK real en el futuro.
pub trait ProofVerifier {
    fn alg(&self) -> Alg;
    fn verify(&self, digest: &[u8; 64], sec: &SigSection) -> Result<(), VerifyError>;
}

pub fn key_id(pk: &VerifyingKey) -> [u8; 32] {
    Sha256::digest(pk.as_bytes()).into()
}

/// Ed25519 sobre el digest SHA-512 del ELF. Conjunto cerrado de claves de confianza.
pub struct Ed25519Verifier {
    trusted: Vec<VerifyingKey>,
}

impl Ed25519Verifier {
    pub fn new(trusted: Vec<VerifyingKey>) -> Self {
        Self { trusted }
    }
}

impl ProofVerifier for Ed25519Verifier {
    fn alg(&self) -> Alg {
        Alg::Ed25519
    }

    fn verify(&self, digest: &[u8; 64], sec: &SigSection) -> Result<(), VerifyError> {
        let pk = self
            .trusted
            .iter()
            .find(|k| key_id(k) == sec.key_id)
            .ok_or(VerifyError::UnknownKey(sec.key_id))?;
        let sig = Signature::from_bytes(&sec.proof);
        // verify_strict rechaza firmas maleables y claves de orden pequeño.
        pk.verify_strict(digest, &sig).map_err(|_| VerifyError::BadSignature)?;
        // `verify` normal también, por si cambia la semántica de strict.
        pk.verify(digest, &sig).map_err(|_| VerifyError::BadSignature)
    }
}

/// Marcador honesto: el formato reserva `alg = 2` para ZK, pero no hay
/// verificador. Registrarlo no habilita nada; siempre devuelve `Unsupported`.
pub struct ZkUnimplemented;

impl ProofVerifier for ZkUnimplemented {
    fn alg(&self) -> Alg {
        Alg::ZkReserved
    }
    fn verify(&self, _: &[u8; 64], _: &SigSection) -> Result<(), VerifyError> {
        Err(VerifyError::Unsupported(
            "verificación Zero-Knowledge no implementada; no se acepta ningún binario con alg=2",
        ))
    }
}

/// ELF cuyos bytes pasaron la verificación. Los campos son privados y el
/// único constructor es [`verify_elf`]: el cargador solo concede `PROT_EXEC`
/// a partir de este tipo. Guarda **su propia copia** de los bytes, así lo
/// que se mapea es exactamente lo que se verificó (sin carrera de archivo).
#[derive(Debug)]
pub struct VerifiedElf {
    bytes: Vec<u8>,
    alg: Alg,
    key_id: [u8; 32],
}

impl VerifiedElf {
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }
    pub fn alg(&self) -> Alg {
        self.alg
    }
    pub fn key_id(&self) -> [u8; 32] {
        self.key_id
    }
}

pub fn verify_elf(bytes: Vec<u8>, verifiers: &[&dyn ProofVerifier]) -> Result<VerifiedElf, VerifyError> {
    let loc = sigsection::locate(&bytes)?;
    let sec = SigSection::parse(&bytes[loc.offset..loc.offset + loc.size])?;
    let alg = Alg::from_u32(sec.alg).ok_or(VerifyError::UnknownAlg(sec.alg))?;
    let v = verifiers
        .iter()
        .find(|v| v.alg() == alg)
        .ok_or(VerifyError::NoVerifierFor(alg))?;
    let digest = sigsection::signing_digest(&bytes, loc);
    v.verify(&digest, &sec)?;
    Ok(VerifiedElf { bytes, alg, key_id: sec.key_id })
}
