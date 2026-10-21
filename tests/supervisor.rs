//! Integración del supervisor seccomp USER_NOTIF + Landlock (v0.3).
//!
//! El supervisor solo lanza programas firmados (memfd sellado +
//! `execveat(fd,"",AT_EMPTY_PATH)`), niega `execve` con ruta y niega todo
//! `PROT_EXEC` de usuario. El invitado hostil (`harness`) se firma: es un
//! proceso confinado que intenta, desde adentro, correr código NO firmado.

use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::{Mutex, OnceLock};

use ed25519_dalek::VerifyingKey;
use fnbr_elf_loader::supervisor::{
    elf_exec_gate, is_proc_mem_path, policy_verify_fnbr, run_supervised, run_supervised_verify,
    ExecRequest, Verdict, READ_IMPLIES_EXEC, SYS_EXECVE, SYS_MMAP, SYS_PERSONALITY,
    SYS_PKEY_MPROTECT,
};
use fnbr_elf_loader::verify::Ed25519Verifier;

static LOCK: Mutex<()> = Mutex::new(());

fn fx(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("fixtures").join(name)
}
fn ed() -> Ed25519Verifier {
    let pk = hex::decode(std::fs::read_to_string(fx("keys/test_pub.hex")).unwrap().trim()).unwrap();
    let pk: [u8; 32] = pk.try_into().unwrap();
    Ed25519Verifier::new(vec![VerifyingKey::from_bytes(&pk).unwrap()])
}
fn code(status: std::process::ExitStatus) -> i32 {
    status.code().unwrap_or(-1)
}
fn signal(status: std::process::ExitStatus) -> Option<i32> {
    use std::os::unix::process::ExitStatusExt;
    status.signal()
}

fn work() -> &'static Path {
    static W: OnceLock<PathBuf> = OnceLock::new();
    W.get_or_init(|| {
        let d = std::env::temp_dir().join(format!("fnbr9-it-{}", std::process::id()));
        std::fs::create_dir_all(&d).unwrap();
        d
    })
}

fn gcc(args: &[&str]) {
    let st = Command::new("gcc").args(args).status().expect("gcc");
    assert!(st.success(), "falló gcc {args:?}");
}

fn sign(src: &Path, dst: &Path, seed: &str) {
    let sign = env!("CARGO_BIN_EXE_fnbr-sign");
    let u = dst.with_extension("u");
    assert!(Command::new(sign).arg("prepare").arg(src).arg(&u).status().unwrap().success());
    assert!(Command::new(sign)
        .arg("sign")
        .arg(fx(seed))
        .arg(&u)
        .arg(dst)
        .status()
        .unwrap()
        .success());
    let _ = std::fs::remove_file(&u);
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(dst, std::fs::Permissions::from_mode(0o755)).unwrap();
}

fn static_hello_signed() -> PathBuf {
    static P: OnceLock<PathBuf> = OnceLock::new();
    P.get_or_init(|| {
        let raw = work().join("hello.raw");
        let c = work().join("hello.c");
        std::fs::write(&c, b"#include <stdio.h>\nint main(){puts(\"OK\");return 0;}\n").unwrap();
        gcc(&["-static", "-O1", "-o", raw.to_str().unwrap(), c.to_str().unwrap()]);
        let dst = work().join("hello.signed");
        sign(&raw, &dst, "keys/test_seed.hex");
        dst
    })
    .clone()
}

fn harness_signed() -> PathBuf {
    static P: OnceLock<PathBuf> = OnceLock::new();
    P.get_or_init(|| {
        let raw = work().join("harness.raw");
        let src = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("experimento/harness.c");
        gcc(&["-static", "-O1", "-Wall", "-o", raw.to_str().unwrap(), src.to_str().unwrap()]);
        let dst = work().join("harness.signed");
        sign(&raw, &dst, "keys/test_seed.hex");
        dst
    })
    .clone()
}

fn unsigned_static() -> PathBuf {
    static P: OnceLock<PathBuf> = OnceLock::new();
    P.get_or_init(|| {
        let raw = work().join("unsigned.raw");
        let c = work().join("unsigned.c");
        std::fs::write(
            &c,
            b"#include <stdio.h>\nint main(){puts(\"UNSIGNED\");return 42;}\n",
        )
        .unwrap();
        gcc(&["-static", "-O1", "-o", raw.to_str().unwrap(), c.to_str().unwrap()]);
        raw
    })
    .clone()
}

#[test]
fn signed_static_runs_under_supervisor() {
    let _g = LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let e = ed();
    let (st, n) = run_supervised_verify(&static_hello_signed(), &[] as &[&str], &[&e]).unwrap();
    assert_eq!(code(st), 0, "estático firmado debe correr");
    assert!(n >= 1, "n={n}");
}

#[test]
fn unsigned_static_denied() {
    let _g = LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let e = ed();
    let (st, _) = run_supervised_verify(&unsigned_static(), &[] as &[&str], &[&e]).unwrap();
    // hijo no logra execveat → _exit(93)
    assert_eq!(code(st), 93);
}

#[test]
fn wrong_key_denied() {
    let _g = LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let e = ed();
    let raw = unsigned_static();
    let dst = work().join("wrongkey.signed");
    sign(&raw, &dst, "keys/other_seed.hex");
    let (st, _) = run_supervised_verify(&dst, &[] as &[&str], &[&e]).unwrap();
    assert_eq!(code(st), 93);
}

#[test]
fn tampered_denied() {
    let _g = LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let e = ed();
    let mut b = std::fs::read(static_hello_signed()).unwrap();
    // flip a byte outside the signature if possible
    let sig = b.windows(8).position(|w| w == b"FNBRSIG1").unwrap_or(64);
    let off = if sig > 100 { 64 } else { b.len() - 200 };
    b[off] ^= 0xff;
    let t = work().join("tampered.elf");
    std::fs::write(&t, &b).unwrap();
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(&t, std::fs::Permissions::from_mode(0o755)).unwrap();
    let (st, _) = run_supervised_verify(&t, &[] as &[&str], &[&e]).unwrap();
    assert_eq!(code(st), 93);
}

#[test]
fn deny_all_policy_blocks_even_signed() {
    let _g = LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let (st, _) = run_supervised(&static_hello_signed(), &[] as &[&str], |_r: &ExecRequest| {
        Verdict::Deny(libc::EPERM)
    })
    .unwrap();
    assert_ne!(code(st), 0);
}

fn harness_mode(mode: &str, extra: &[&str]) -> (i32, Option<i32>) {
    let e = ed();
    let h = harness_signed();
    let mut args: Vec<&str> = vec![mode];
    args.extend_from_slice(extra);
    let (st, _) = run_supervised_verify(&h, &args, &[&e]).unwrap();
    (code(st), signal(st))
}

#[test]
fn harness_pkey_blocked() {
    let _g = LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let (c, _) = harness_mode("pkey", &[]);
    assert_eq!(c, 0, "pkey_mprotect anon RX debe bloquearse (exit 0)");
}

#[test]
fn harness_i386_killed() {
    let _g = LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let (c, sig) = harness_mode("i386", &[]);
    assert!(sig == Some(31) || c == 128, "i386 debe recibir SIGSYS; c={c} sig={sig:?}");
}

#[test]
fn harness_x32_killed() {
    let _g = LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let (c, sig) = harness_mode("x32", &[]);
    assert!(sig == Some(31) || c == 128, "x32 debe recibir SIGSYS; c={c} sig={sig:?}");
}

#[test]
fn harness_ptrace_blocked() {
    let _g = LOCK.lock().unwrap_or_else(|e| e.into_inner());
    assert_eq!(harness_mode("ptrace", &[]).0, 0);
}

#[test]
fn harness_vmwritev_blocked() {
    let _g = LOCK.lock().unwrap_or_else(|e| e.into_inner());
    assert_eq!(harness_mode("vmwritev", &[]).0, 0);
}

#[test]
fn harness_uffd_blocked() {
    let _g = LOCK.lock().unwrap_or_else(|e| e.into_inner());
    assert_eq!(harness_mode("uffd", &[]).0, 0);
}

#[test]
fn harness_procmem_blocked() {
    let _g = LOCK.lock().unwrap_or_else(|e| e.into_inner());
    assert_eq!(harness_mode("procmem", &[]).0, 0, "Landlock debe negar /proc/self/mem O_RDWR");
}

#[test]
fn harness_rie_blocked() {
    let _g = LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let u = fx("guest.unsigned.elf");
    assert_eq!(harness_mode("read-implies-exec", &[u.to_str().unwrap()]).0, 0);
}

#[test]
fn harness_mapshared_blocked() {
    let _g = LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let s = static_hello_signed();
    assert_eq!(harness_mode("mapshared", &[s.to_str().unwrap()]).0, 0);
}

#[test]
fn harness_cow_dirty_blocked() {
    let _g = LOCK.lock().unwrap_or_else(|e| e.into_inner());
    // guest en 0x10000000: no choca con el harness (glibc-static típico).
    let s = fx("guest.signed.elf");
    let (c, _) = harness_mode("cow-dirty", &[s.to_str().unwrap()]);
    // 0 = bloqueado; 3 = armado falló (también no-bypass)
    assert!(c == 0 || c == 3, "cow-dirty bypass rc={c}");
}

#[test]
fn harness_memfd_fexecve_unsigned_blocked() {
    let _g = LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let u = unsigned_static();
    assert_eq!(harness_mode("memfd-fexecve", &[u.to_str().unwrap()]).0, 0);
}

#[test]
fn harness_toctou_blocked() {
    let _g = LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let work_elf = work().join("toctou-work.elf");
    let sgn = work().join("toctou-sgn.elf");
    std::fs::copy(fx("guest.unsigned.elf"), &work_elf).unwrap();
    std::fs::copy(static_hello_signed(), &sgn).unwrap();
    assert_eq!(
        harness_mode(
            "mprotect-toctou",
            &[work_elf.to_str().unwrap(), sgn.to_str().unwrap()]
        )
        .0,
        0
    );
}

#[test]
fn policy_execve_path_denied() {
    let req = ExecRequest {
        pid: 1,
        nr: SYS_EXECVE as i32,
        prot: 0,
        flags: 0,
        fd: -1,
        addr: 0,
        len: 0,
        args: [0; 6],
    };
    assert_eq!(policy_verify_fnbr(&req, &[]), Verdict::Deny(libc::EACCES));
}

#[test]
fn policy_personality_rie_denied() {
    let mk = |a0: u64| ExecRequest {
        pid: 1,
        nr: SYS_PERSONALITY as i32,
        prot: 0,
        flags: 0,
        fd: -1,
        addr: a0,
        len: 0,
        args: [a0, 0, 0, 0, 0, 0],
    };
    assert_eq!(
        policy_verify_fnbr(&mk(READ_IMPLIES_EXEC), &[]),
        Verdict::Deny(libc::EPERM)
    );
    assert_eq!(policy_verify_fnbr(&mk(0xffff_ffff), &[]), Verdict::Continue);
}

#[test]
fn policy_pkey_exec_denied() {
    let req = ExecRequest {
        pid: 1,
        nr: SYS_PKEY_MPROTECT as i32,
        prot: (libc::PROT_READ | libc::PROT_EXEC) as u64,
        flags: 0,
        fd: -1,
        addr: 0x1000,
        len: 4096,
        args: [0x1000, 4096, (libc::PROT_READ | libc::PROT_EXEC) as u64, u64::MAX, 0, 0],
    };
    assert_eq!(policy_verify_fnbr(&req, &[]), Verdict::Deny(libc::EPERM));
}

#[test]
fn policy_anon_mmap_exec_denied() {
    let req = ExecRequest {
        pid: 1,
        nr: SYS_MMAP as i32,
        prot: (libc::PROT_READ | libc::PROT_EXEC) as u64,
        flags: (libc::MAP_PRIVATE | libc::MAP_ANONYMOUS) as u64,
        fd: -1,
        addr: 0,
        len: 4096,
        args: [
            0,
            4096,
            (libc::PROT_READ | libc::PROT_EXEC) as u64,
            (libc::MAP_PRIVATE | libc::MAP_ANONYMOUS) as u64,
            u64::MAX,
            0,
        ],
    };
    assert_eq!(policy_verify_fnbr(&req, &[]), Verdict::Deny(libc::EPERM));
}

#[test]
fn elf_exec_gate_rejects_script() {
    assert!(elf_exec_gate(b"#!/bin/sh\n").is_err());
}

#[test]
fn is_proc_mem_path_matches() {
    assert!(is_proc_mem_path(Path::new("/proc/self/mem")));
    assert!(is_proc_mem_path(Path::new("/proc/1234/mem")));
    assert!(is_proc_mem_path(Path::new("/proc/1/task/2/mem")));
    assert!(!is_proc_mem_path(Path::new("/proc/self/maps")));
    assert!(!is_proc_mem_path(Path::new("/tmp/mem")));
}
