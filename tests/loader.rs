//! Tests de integración con los fixtures firmados/sin firmar de `fixtures/`.

use std::path::PathBuf;
use std::sync::Mutex;

use ed25519_dalek::{Signer, SigningKey, VerifyingKey};
use fnbr_elf_loader::loader::{load, load_path, LoadError};
use fnbr_elf_loader::sigsection::{self, Alg, SectionError, SigSection};
use fnbr_elf_loader::verify::{key_id, verify_elf, Ed25519Verifier, ProofVerifier, VerifyError, ZkUnimplemented};

// El invitado se mapea en una dirección fija: un solo test a la vez.
static MAP_LOCK: Mutex<()> = Mutex::new(());
const GUEST_BASE: u64 = 0x1000_0000;

fn fx(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("fixtures").join(name)
}
fn hex32(name: &str) -> [u8; 32] {
    hex::decode(std::fs::read_to_string(fx(name)).unwrap().trim()).unwrap().try_into().unwrap()
}
fn test_pk() -> VerifyingKey {
    VerifyingKey::from_bytes(&hex32("keys/test_pub.hex")).unwrap()
}
fn test_sk() -> SigningKey {
    SigningKey::from_bytes(&hex32("keys/test_seed.hex"))
}
fn ed() -> Ed25519Verifier {
    Ed25519Verifier::new(vec![test_pk()])
}
fn guest_mapped() -> bool {
    let maps = std::fs::read_to_string("/proc/self/maps").unwrap();
    maps.lines().any(|l| l.starts_with(&format!("{GUEST_BASE:x}-")))
}

#[test]
fn signed_fixture_loads_and_runs() {
    let _g = MAP_LOCK.lock().unwrap();
    let e = ed();
    let img = load_path(&fx("guest.signed.elf"), &[&e]).expect("debe cargar");
    assert_eq!(img.range(), (GUEST_BASE, GUEST_BASE + 0x4000));
    // W^X: ningún segmento es escribible y ejecutable.
    for &(_, _, p) in &img.segments {
        assert!(!(p & libc::PROT_WRITE != 0 && p & libc::PROT_EXEC != 0));
    }
    assert!(img.segments.iter().any(|&(_, _, p)| p & libc::PROT_EXEC != 0));
    assert_eq!(unsafe { img.call_entry() }, 296);
    drop(img);
    assert!(!guest_mapped(), "Drop debe desmapear");
}

#[test]
fn unsigned_fixture_refused_without_mapping() {
    let _g = MAP_LOCK.lock().unwrap();
    let e = ed();
    match load_path(&fx("guest.unsigned.elf"), &[&e]) {
        Err(LoadError::Refused(VerifyError::Section(SectionError::Unsigned))) => {}
        other => panic!("esperaba Refused(Unsigned), obtuve {other:?}"),
    }
    assert!(!guest_mapped(), "un rechazo no debe dejar nada mapeado");
}

#[test]
fn other_key_refused() {
    let e = ed();
    let bytes = std::fs::read(fx("guest.signed-otherkey.elf")).unwrap();
    assert!(matches!(verify_elf(bytes, &[&e]), Err(VerifyError::UnknownKey(_))));
}

#[test]
fn every_single_byte_flip_outside_sig_is_rejected() {
    // Barrido completo: cambiar CUALQUIER byte fuera de .fnbr.sig invalida la firma
    // (o rompe el parseo del ELF). Nada adulterado pasa.
    let e = ed();
    let orig = std::fs::read(fx("guest.signed.elf")).unwrap();
    let loc = sigsection::locate(&orig).unwrap();
    let mut accepted = Vec::new();
    for i in (0..orig.len()).filter(|i| !(loc.offset..loc.offset + loc.size).contains(i)) {
        let mut b = orig.clone();
        b[i] ^= 0x01;
        if verify_elf(b, &[&e]).is_ok() {
            accepted.push(i);
        }
    }
    assert!(accepted.is_empty(), "bytes adulterados aceptados en offsets {accepted:?}");
}

#[test]
fn tampered_text_is_bad_signature() {
    let e = ed();
    let mut b = std::fs::read(fx("guest.signed.elf")).unwrap();
    b[0x1000] ^= 0xff; // primer byte de .text
    assert_eq!(verify_elf(b, &[&e]).unwrap_err(), VerifyError::BadSignature);
}

#[test]
fn tampered_signature_bytes_rejected() {
    let e = ed();
    let mut b = std::fs::read(fx("guest.signed.elf")).unwrap();
    let loc = sigsection::locate(&b).unwrap();
    b[loc.offset + 60] ^= 0x01; // dentro de la firma
    assert_eq!(verify_elf(b, &[&e]).unwrap_err(), VerifyError::BadSignature);
}

/// Firma `bytes` con un SigSection arbitrario (para probar casos de formato).
fn resign(mut bytes: Vec<u8>, alg: u32) -> Vec<u8> {
    let loc = sigsection::locate(&bytes).unwrap();
    bytes[loc.offset..loc.offset + loc.size].fill(0);
    let d = sigsection::signing_digest(&bytes, loc);
    let sk = test_sk();
    let sec = SigSection { alg, flags: 0, key_id: key_id(&sk.verifying_key()), proof: sk.sign(&d).to_bytes() };
    bytes[loc.offset..loc.offset + loc.size].copy_from_slice(&sec.to_bytes());
    bytes
}

#[test]
fn zk_alg_is_never_accepted() {
    let e = ed();
    let b = resign(std::fs::read(fx("guest.unsigned.elf")).unwrap(), Alg::ZkReserved as u32);
    // Sin verificador ZK registrado:
    assert_eq!(verify_elf(b.clone(), &[&e]).unwrap_err(), VerifyError::NoVerifierFor(Alg::ZkReserved));
    // Con el marcador registrado: rechaza explícitamente, no finge.
    assert!(matches!(verify_elf(b, &[&e, &ZkUnimplemented]), Err(VerifyError::Unsupported(_))));
}

#[test]
fn unknown_alg_rejected() {
    let e = ed();
    let b = resign(std::fs::read(fx("guest.unsigned.elf")).unwrap(), 99);
    assert_eq!(verify_elf(b, &[&e]).unwrap_err(), VerifyError::UnknownAlg(99));
}

#[test]
fn resign_with_trusted_key_roundtrips() {
    let e = ed();
    let b = resign(std::fs::read(fx("guest.unsigned.elf")).unwrap(), Alg::Ed25519 as u32);
    assert!(verify_elf(b, &[&e]).is_ok());
}

#[test]
fn verifier_trait_is_object_safe_and_extensible() {
    struct AlwaysNo;
    impl ProofVerifier for AlwaysNo {
        fn alg(&self) -> Alg {
            Alg::Ed25519
        }
        fn verify(&self, _: &[u8; 64], _: &SigSection) -> Result<(), VerifyError> {
            Err(VerifyError::BadSignature)
        }
    }
    let b = std::fs::read(fx("guest.signed.elf")).unwrap();
    let vs: Vec<Box<dyn ProofVerifier>> = vec![Box::new(AlwaysNo)];
    let refs: Vec<&dyn ProofVerifier> = vs.iter().map(|b| b.as_ref()).collect();
    assert_eq!(verify_elf(b, &refs).unwrap_err(), VerifyError::BadSignature);
}

#[test]
fn missing_section_rejected() {
    let e = ed();
    // El propio binario de test es un ELF sin .fnbr.sig.
    let me = std::fs::read(std::env::current_exe().unwrap()).unwrap();
    assert_eq!(verify_elf(me, &[&e]).unwrap_err(), VerifyError::Section(SectionError::Missing));
}

#[test]
fn signed_but_unsupported_layout_is_not_mapped() {
    // Un ELF PIE/dinámico firmado con clave válida: la firma pasa, pero el
    // cargador lo rechaza por formato, no por confianza.
    let _g = MAP_LOCK.lock().unwrap();
    let dir = std::env::temp_dir().join(format!("fnbr9-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let me = std::env::current_exe().unwrap();
    let prepared = dir.join("me.prepared");
    let st = std::process::Command::new(env!("CARGO_BIN_EXE_fnbr-sign"))
        .args(["prepare", me.to_str().unwrap(), prepared.to_str().unwrap()])
        .status()
        .unwrap();
    assert!(st.success());
    let b = resign(std::fs::read(&prepared).unwrap(), Alg::Ed25519 as u32);
    let e = ed();
    let v = verify_elf(b, &[&e]).expect("firma válida");
    assert!(matches!(load(&v), Err(LoadError::Unsupported(_))));
    let _ = std::fs::remove_dir_all(&dir);
}
