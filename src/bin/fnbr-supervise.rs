//! fnbr-supervise <pub.hex> <programa> [args…]:
//! lanza `programa` bajo seccomp USER_NOTIF y solo permite PROT_EXEC si el
//! archivo de respaldo verifica con la clave Ed25519 dada.

use anyhow::{Context, Result};
use ed25519_dalek::VerifyingKey;
use fnbr_elf_loader::supervisor::run_supervised_verify;
use fnbr_elf_loader::verify::{Ed25519Verifier, ZkUnimplemented};
use std::path::Path;

fn main() -> Result<()> {
    let a: Vec<String> = std::env::args().collect();
    if a.len() < 3 {
        eprintln!("uso: fnbr-supervise <pub.hex> <programa> [args…]");
        std::process::exit(2);
    }
    let pk_hex = std::fs::read_to_string(&a[1]).context("leer clave pública")?;
    let pk: [u8; 32] = hex::decode(pk_hex.trim())?.try_into().map_err(|_| anyhow::anyhow!("clave de 32 B"))?;
    let ed = Ed25519Verifier::new(vec![VerifyingKey::from_bytes(&pk)?]);
    let prog = Path::new(&a[2]);
    let args: Vec<&str> = a[3..].iter().map(String::as_str).collect();
    let (status, handled) = run_supervised_verify(prog, &args, &[&ed, &ZkUnimplemented])?;
    eprintln!("supervisor: {handled} notificaciones PROT_EXEC atendidas");
    if let Some(code) = status.code() {
        std::process::exit(code);
    }
    eprintln!("hijo terminó por señal: {status}");
    std::process::exit(128);
}
