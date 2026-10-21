//! Prueba Zero-Knowledge genuina: Schnorr no interactivo (Fiat-Shamir) sobre
//! Ristretto255 (curve25519-dalek).
//!
//! ## Qué SE prueba
//! Conocimiento del logaritmo discreto `k` tal que `K = k·B` (clave pública
//! del publicador en el grupo Ristretto), con el desafío Fiat-Shamir atado al
//! SHA-256 del binario (archivo con `.fnbr.sig` en cero) y a `K`. Quien pasa
//! la verificación demostró conocer `k` para ese `K` ligado a ese hash.
//!
//! ## Qué NO se prueba
//! - Corrección del programa (no es una zk-SNARK/STARK del código).
//! - Inocuidad, ausencia de bugs, ni que el binario sea el “que uno quiere”.
//! - Nada más allá del conocimiento de `k` bajo el binding del transcript.
//!
//! Formato de la prueba en `.fnbr.sig` (`alg = 2`): `R || s` (32+32 = 64 B),
//! con `key_id = SHA-256(K_comprimido)`.

use curve25519_dalek::ristretto::{CompressedRistretto, RistrettoPoint};
use curve25519_dalek::scalar::Scalar;
use curve25519_dalek::traits::Identity;
use rand_core::{CryptoRng, RngCore};
use sha2::{Digest, Sha256, Sha512};

use crate::sigsection::{self, Alg, SigSection};
use crate::verify::{ProofVerifier, VerifyError, VerifyMaterial};

pub const DOMAIN: &[u8] = b"FNBR-ZK-SCHNORR-v1\0";

/// Par de claves Schnorr/Ristretto del publicador.
#[derive(Clone)]
pub struct SchnorrKeypair {
    pub secret: Scalar,
    pub public: RistrettoPoint,
}

impl SchnorrKeypair {
    pub fn generate<R: RngCore + CryptoRng>(rng: &mut R) -> Self {
        let mut seed = [0u8; 64];
        rng.fill_bytes(&mut seed);
        let secret = Scalar::from_bytes_mod_order_wide(&seed);
        let public = RistrettoPoint::mul_base(&secret);
        Self { secret, public }
    }

    pub fn from_secret_bytes(bytes: &[u8; 32]) -> Self {
        let secret = Scalar::from_bytes_mod_order(*bytes);
        let public = RistrettoPoint::mul_base(&secret);
        Self { secret, public }
    }

    pub fn public_bytes(&self) -> [u8; 32] {
        self.public.compress().to_bytes()
    }

    pub fn secret_bytes(&self) -> [u8; 32] {
        self.secret.to_bytes()
    }

    pub fn key_id(&self) -> [u8; 32] {
        Sha256::digest(self.public_bytes()).into()
    }
}

/// Prueba: `R` (compromiso) + `s` (respuesta).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SchnorrProof {
    pub r: [u8; 32],
    pub s: [u8; 32],
}

impl SchnorrProof {
    pub fn to_bytes(self) -> [u8; 64] {
        let mut out = [0u8; 64];
        out[..32].copy_from_slice(&self.r);
        out[32..].copy_from_slice(&self.s);
        out
    }
    pub fn from_bytes(b: &[u8; 64]) -> Self {
        let mut r = [0u8; 32];
        let mut s = [0u8; 32];
        r.copy_from_slice(&b[..32]);
        s.copy_from_slice(&b[32..]);
        Self { r, s }
    }
}

fn challenge(r_bytes: &[u8; 32], k_bytes: &[u8; 32], file_hash: &[u8; 32]) -> Scalar {
    let mut h = Sha512::new();
    h.update(DOMAIN);
    h.update(r_bytes);
    h.update(k_bytes);
    h.update(file_hash);
    let wide: [u8; 64] = h.finalize().into();
    Scalar::from_bytes_mod_order_wide(&wide)
}

/// Produce una prueba de conocimiento de `kp.secret` atada a `file_hash`.
pub fn prove<R: RngCore + CryptoRng>(
    kp: &SchnorrKeypair,
    file_hash: &[u8; 32],
    rng: &mut R,
) -> SchnorrProof {
    let mut seed = [0u8; 64];
    rng.fill_bytes(&mut seed);
    let nonce = Scalar::from_bytes_mod_order_wide(&seed);
    let r_point = RistrettoPoint::mul_base(&nonce);
    let r_bytes = r_point.compress().to_bytes();
    let k_bytes = kp.public_bytes();
    let c = challenge(&r_bytes, &k_bytes, file_hash);
    let s = nonce + c * kp.secret;
    SchnorrProof { r: r_bytes, s: s.to_bytes() }
}

/// Verifica la prueba contra `public` y `file_hash`.
pub fn verify_proof(
    public: &RistrettoPoint,
    file_hash: &[u8; 32],
    proof: &SchnorrProof,
) -> Result<(), VerifyError> {
    if public == &RistrettoPoint::identity() {
        return Err(VerifyError::BadSignature);
    }
    let r_point = CompressedRistretto(proof.r)
        .decompress()
        .ok_or(VerifyError::BadSignature)?;
    if r_point == RistrettoPoint::identity() {
        return Err(VerifyError::BadSignature);
    }
    let s = Option::<Scalar>::from(Scalar::from_canonical_bytes(proof.s)).ok_or(VerifyError::BadSignature)?;
    let k_bytes = public.compress().to_bytes();
    let c = challenge(&proof.r, &k_bytes, file_hash);
    let lhs = RistrettoPoint::mul_base(&s);
    let rhs = r_point + c * public;
    if lhs == rhs {
        Ok(())
    } else {
        Err(VerifyError::BadSignature)
    }
}

/// Verificador [`ProofVerifier`] para `alg = SchnorrRistretto`.
pub struct SchnorrVerifier {
    trusted: Vec<RistrettoPoint>,
}

impl SchnorrVerifier {
    pub fn new(trusted: Vec<RistrettoPoint>) -> Self {
        Self { trusted }
    }

    pub fn from_public_bytes(keys: &[[u8; 32]]) -> Result<Self, VerifyError> {
        let mut trusted = Vec::with_capacity(keys.len());
        for kb in keys {
            let p = CompressedRistretto(*kb)
                .decompress()
                .ok_or(VerifyError::BadSignature)?;
            trusted.push(p);
        }
        Ok(Self { trusted })
    }
}

fn key_id_of(pk: &RistrettoPoint) -> [u8; 32] {
    Sha256::digest(pk.compress().to_bytes()).into()
}

impl ProofVerifier for SchnorrVerifier {
    fn alg(&self) -> Alg {
        Alg::SchnorrRistretto
    }

    fn verify(&self, material: &VerifyMaterial<'_>, sec: &SigSection) -> Result<(), VerifyError> {
        let pk = self
            .trusted
            .iter()
            .find(|k| key_id_of(k) == sec.key_id)
            .ok_or(VerifyError::UnknownKey(sec.key_id))?;
        let proof = SchnorrProof::from_bytes(&sec.proof);
        verify_proof(pk, material.content_sha256, &proof)
    }
}

/// Escribe una prueba Schnorr en `.fnbr.sig` (`alg=2`).
pub fn sign_elf(
    mut bytes: Vec<u8>,
    kp: &SchnorrKeypair,
    rng: &mut (impl RngCore + CryptoRng),
) -> Result<Vec<u8>, sigsection::SectionError> {
    let loc = sigsection::locate(&bytes)?;
    bytes[loc.offset..loc.offset + loc.size].fill(0);
    let file_hash = sigsection::content_hash_sha256(&bytes, loc);
    let proof = prove(kp, &file_hash, rng);
    let sec = SigSection {
        alg: Alg::SchnorrRistretto as u32,
        flags: 0,
        key_id: kp.key_id(),
        proof: proof.to_bytes(),
    };
    bytes[loc.offset..loc.offset + loc.size].copy_from_slice(&sec.to_bytes());
    Ok(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::rngs::OsRng;

    #[test]
    fn roundtrip_proof_on_random_hash() {
        let mut rng = OsRng;
        let kp = SchnorrKeypair::generate(&mut rng);
        let hash = [7u8; 32];
        let proof = prove(&kp, &hash, &mut rng);
        assert!(verify_proof(&kp.public, &hash, &proof).is_ok());
    }

    #[test]
    fn wrong_key_rejected() {
        let mut rng = OsRng;
        let kp = SchnorrKeypair::generate(&mut rng);
        let other = SchnorrKeypair::generate(&mut rng);
        let hash = [1u8; 32];
        let proof = prove(&kp, &hash, &mut rng);
        assert!(verify_proof(&other.public, &hash, &proof).is_err());
    }

    #[test]
    fn tampered_hash_rejected() {
        let mut rng = OsRng;
        let kp = SchnorrKeypair::generate(&mut rng);
        let proof = prove(&kp, &[2u8; 32], &mut rng);
        assert!(verify_proof(&kp.public, &[3u8; 32], &proof).is_err());
    }

    #[test]
    fn tampered_proof_rejected() {
        let mut rng = OsRng;
        let kp = SchnorrKeypair::generate(&mut rng);
        let hash = [9u8; 32];
        let mut proof = prove(&kp, &hash, &mut rng);
        proof.s[0] ^= 1;
        assert!(verify_proof(&kp.public, &hash, &proof).is_err());
        proof = prove(&kp, &hash, &mut rng);
        proof.r[0] ^= 1;
        assert!(verify_proof(&kp.public, &hash, &proof).is_err());
    }
}
