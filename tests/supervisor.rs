//! Integración del supervisor seccomp USER_NOTIF: el invitado hostil
//! (`fixtures/rawload`) intenta mapear con PROT_EXEC sin pasar por nuestro
//! cargador. Con el supervisor, solo el ELF firmado con clave de confianza
//! logra correr; sin firma / adulterado / JIT anónimo se niega.

use std::path::PathBuf;
use std::sync::Mutex;

use ed25519_dalek::VerifyingKey;
use fnbr_elf_loader::supervisor::{
    policy_verify_fnbr, run_supervised, run_supervised_verify, ExecRequest, Verdict,
};
use fnbr_elf_loader::verify::Ed25519Verifier;

// El filtro seccomp + fork no se lleva bien con tests en paralelo del mismo
// proceso; serializamos.
static LOCK: Mutex<()> = Mutex::new(());

fn fx(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("fixtures").join(name)
}
fn ed() -> Ed25519Verifier {
    let pk = hex::decode(std::fs::read_to_string(fx("keys/test_pub.hex")).unwrap().trim()).unwrap();
    let pk: [u8; 32] = pk.try_into().unwrap();
    Ed25519Verifier::new(vec![VerifyingKey::from_bytes(&pk).unwrap()])
}
fn ensure_rawload() {
    let p = fx("rawload");
    if p.is_file() { return; }
    let st = std::process::Command::new("gcc")
        .args(["-O1","-static","-Wall","-Wextra","-o"])
        .arg(&p)
        .arg(fx("src/rawload.c"))
        .status()
        .expect("gcc");
    assert!(st.success(), "falló gcc de rawload");
}
fn rawload() -> PathBuf {
    ensure_rawload();
    fx("rawload")
}
fn code(status: std::process::ExitStatus) -> i32 {
    status.code().unwrap_or(-1)
}

#[test]
fn signed_elf_runs_under_supervisor_via_mmap() {
    let _g = LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let e = ed();
    let (st, n) = run_supervised_verify(
        &rawload(),
        &["mmap-exec", fx("guest.signed.elf").to_str().unwrap()],
        &[&e],
    )
    .expect("supervisor");
    assert_eq!(code(st), 0, "ELF firmado debe correr (entry=296)");
    assert!(n >= 1, "debió haber al menos un PROT_EXEC notificado, n={n}");
}

#[test]
fn signed_elf_runs_under_supervisor_via_mprotect() {
    let _g = LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let e = ed();
    let (st, n) = run_supervised_verify(
        &rawload(),
        &["mprotect", fx("guest.signed.elf").to_str().unwrap()],
        &[&e],
    )
    .expect("supervisor");
    assert_eq!(code(st), 0, "mprotect→RX de firmado debe pasar");
    assert!(n >= 1, "n={n}");
}

#[test]
fn unsigned_elf_mmap_denied() {
    let _g = LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let e = ed();
    let (st, _) = run_supervised_verify(
        &rawload(),
        &["mmap-exec", fx("guest.unsigned.elf").to_str().unwrap()],
        &[&e],
    )
    .expect("supervisor");
    assert_eq!(code(st), 3, "sin firma → mmap negado (rawload exit 3)");
}

#[test]
fn other_key_mmap_denied() {
    let _g = LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let e = ed();
    let (st, _) = run_supervised_verify(
        &rawload(),
        &["mmap-exec", fx("guest.signed-otherkey.elf").to_str().unwrap()],
        &[&e],
    )
    .expect("supervisor");
    assert_eq!(code(st), 3, "otra clave → mmap negado");
}

#[test]
fn tampered_elf_mmap_denied() {
    let _g = LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let e = ed();
    let dir = std::env::temp_dir().join(format!("fnbr9-sup-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let t = dir.join("tampered.elf");
    let mut b = std::fs::read(fx("guest.signed.elf")).unwrap();
    b[0x1000] ^= 0xff;
    std::fs::write(&t, &b).unwrap();
    let (st, _) = run_supervised_verify(
        &rawload(),
        &["mmap-exec", t.to_str().unwrap()],
        &[&e],
    )
    .expect("supervisor");
    let _ = std::fs::remove_dir_all(&dir);
    assert_eq!(code(st), 3, "adulterado → mmap negado");
}

#[test]
fn anonymous_jit_denied() {
    let _g = LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let e = ed();
    let (st, n) = run_supervised_verify(&rawload(), &["anon-jit"], &[&e])
        .expect("supervisor");
    assert_eq!(code(st), 0, "ambos intentos JIT deben negarse (rawload exit 0)");
    assert!(n >= 1, "debió notificar PROT_EXEC anónimo, n={n}");
}

#[test]
fn deny_all_policy_blocks_even_signed() {
    let _g = LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let (st, _) = run_supervised(
        &rawload(),
        &["mmap-exec", fx("guest.signed.elf").to_str().unwrap()],
        |_req: &ExecRequest| Verdict::Deny(libc::EPERM),
    )
    .expect("supervisor");
    assert_eq!(code(st), 3);
}

#[test]
fn policy_helper_rejects_anonymous_without_io() {
    let e = ed();
    let req = ExecRequest {
        pid: std::process::id(),
        nr: fnbr_elf_loader::supervisor::SYS_MMAP as i32,
        prot: (libc::PROT_READ | libc::PROT_EXEC) as u64,
        flags: (libc::MAP_PRIVATE | libc::MAP_ANONYMOUS) as u64,
        fd: -1,
        addr: 0,
        len: 4096,
    };
    assert_eq!(
        policy_verify_fnbr(&req, &[&e as &dyn fnbr_elf_loader::verify::ProofVerifier]),
        Verdict::Deny(libc::EPERM)
    );
}

#[test]
fn rawload_fixture_exists() {
    let p = rawload();
    assert!(p.is_file(), "falta {}; corré scripts/build-fixtures.sh", p.display());
    let b = std::fs::read(&p).unwrap();
    assert_eq!(&b[0..4], b"\x7fELF");
}
