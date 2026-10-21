//! Formato de la sección `.fnbr.sig` y cálculo del digest firmado.

use goblin::elf::Elf;
use sha2::{Digest, Sha512};

pub const SECTION_NAME: &str = ".fnbr.sig";
pub const SECTION_SIZE: usize = 128;
pub const MAGIC: &[u8; 8] = b"FNBRSIG1";

/// Algoritmos de prueba. Los números quedan fijos en el formato.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Alg {
    Ed25519 = 1,
    /// Reservado para una prueba Zero-Knowledge. **No implementado**: ningún
    /// verificador de este crate lo acepta.
    ZkReserved = 2,
}

impl Alg {
    pub fn from_u32(v: u32) -> Option<Self> {
        match v {
            1 => Some(Alg::Ed25519),
            2 => Some(Alg::ZkReserved),
            _ => None,
        }
    }
}

/// Contenido de `.fnbr.sig` (128 bytes, little-endian):
/// `magic[8] | alg u32 | flags u32 | key_id[32] = sha256(pubkey) | sig[64] | reservado[16]`
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SigSection {
    pub alg: u32,
    pub flags: u32,
    pub key_id: [u8; 32],
    pub proof: [u8; 64],
}

impl SigSection {
    pub fn to_bytes(&self) -> [u8; SECTION_SIZE] {
        let mut b = [0u8; SECTION_SIZE];
        b[0..8].copy_from_slice(MAGIC);
        b[8..12].copy_from_slice(&self.alg.to_le_bytes());
        b[12..16].copy_from_slice(&self.flags.to_le_bytes());
        b[16..48].copy_from_slice(&self.key_id);
        b[48..112].copy_from_slice(&self.proof);
        b
    }

    pub fn parse(b: &[u8]) -> Result<Self, SectionError> {
        if b.len() != SECTION_SIZE {
            return Err(SectionError::WrongSize(b.len()));
        }
        if b.iter().all(|&x| x == 0) {
            return Err(SectionError::Unsigned);
        }
        if &b[0..8] != MAGIC {
            return Err(SectionError::BadMagic);
        }
        let mut key_id = [0u8; 32];
        key_id.copy_from_slice(&b[16..48]);
        let mut proof = [0u8; 64];
        proof.copy_from_slice(&b[48..112]);
        Ok(Self {
            alg: u32::from_le_bytes(b[8..12].try_into().unwrap()),
            flags: u32::from_le_bytes(b[12..16].try_into().unwrap()),
            key_id,
            proof,
        })
    }
}

#[derive(Debug, PartialEq, Eq)]
pub enum SectionError {
    NotElf(String),
    Missing,
    Duplicate,
    WrongSize(usize),
    OutOfBounds,
    /// La sección existe pero está en cero: binario preparado y no firmado.
    Unsigned,
    BadMagic,
    /// La sección está dentro de un segmento cargable: su contenido estaría
    /// en memoria y el formato exige que no lo esté.
    Loadable,
}

impl std::fmt::Display for SectionError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{self:?}")
    }
}
impl std::error::Error for SectionError {}

/// Ubicación de `.fnbr.sig` dentro del archivo.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SectionLoc {
    pub offset: usize,
    pub size: usize,
}

pub fn locate(file: &[u8]) -> Result<SectionLoc, SectionError> {
    let elf = Elf::parse(file).map_err(|e| SectionError::NotElf(e.to_string()))?;
    let mut found = None;
    for sh in &elf.section_headers {
        if elf.shdr_strtab.get_at(sh.sh_name) == Some(SECTION_NAME) {
            if found.is_some() {
                return Err(SectionError::Duplicate);
            }
            if sh.sh_flags & u64::from(goblin::elf::section_header::SHF_ALLOC) != 0 {
                return Err(SectionError::Loadable);
            }
            found = Some(SectionLoc {
                offset: sh.sh_offset as usize,
                size: sh.sh_size as usize,
            });
        }
    }
    let loc = found.ok_or(SectionError::Missing)?;
    if loc.size != SECTION_SIZE {
        return Err(SectionError::WrongSize(loc.size));
    }
    if loc.offset.checked_add(loc.size).is_none_or(|end| end > file.len()) {
        return Err(SectionError::OutOfBounds);
    }
    Ok(loc)
}

/// Digest firmado: SHA-512 de todo el archivo con los 128 B de `.fnbr.sig`
/// en cero, con prefijo de dominio. Cubre cabeceras, segmentos, tablas de
/// secciones y la posición de la propia sección.
pub fn signing_digest(file: &[u8], loc: SectionLoc) -> [u8; 64] {
    let mut h = Sha512::new();
    h.update(b"FNBR-ELF-SIG-v1\0");
    h.update(&file[..loc.offset]);
    h.update([0u8; SECTION_SIZE]);
    h.update(&file[loc.offset + loc.size..]);
    h.finalize().into()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_section_bytes() {
        let s = SigSection { alg: 1, flags: 0, key_id: [7; 32], proof: [9; 64] };
        assert_eq!(SigSection::parse(&s.to_bytes()).unwrap(), s);
    }

    #[test]
    fn zero_section_is_unsigned() {
        assert_eq!(SigSection::parse(&[0u8; SECTION_SIZE]), Err(SectionError::Unsigned));
    }

    #[test]
    fn bad_magic_and_size() {
        let mut b = [1u8; SECTION_SIZE];
        b[0] = b'X';
        assert_eq!(SigSection::parse(&b), Err(SectionError::BadMagic));
        assert_eq!(SigSection::parse(&b[..10]), Err(SectionError::WrongSize(10)));
    }

    #[test]
    fn not_elf() {
        assert!(matches!(locate(b"hola"), Err(SectionError::NotElf(_))));
    }
}
