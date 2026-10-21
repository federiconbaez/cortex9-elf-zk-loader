//! fnbr-load <pub.hex> <file.elf>: verifica, mapea y llama al entry.
//! Sale con 1 si se rechaza (sin haber mapeado nada ejecutable).

use anyhow::{Context, Result};
use ed25519_dalek::VerifyingKey;
use fnbr_elf_loader::loader::{load_path, LoadError};
use fnbr_elf_loader::verify::Ed25519Verifier;

fn main() -> Result<()> {
    let a: Vec<String> = std::env::args().collect();
    if a.len() != 3 {
        eprintln!("uso: fnbr-load <pub.hex> <file.elf>");
        std::process::exit(2);
    }
    let pk_hex = std::fs::read_to_string(&a[1]).context("leer clave pública")?;
    let pk: [u8; 32] = hex::decode(pk_hex.trim())?.try_into().map_err(|_| anyhow::anyhow!("clave de 32 B"))?;
    let ed = Ed25519Verifier::new(vec![VerifyingKey::from_bytes(&pk)?]);
    match load_path(std::path::Path::new(&a[2]), &[&ed]) {
        Ok(img) => {
            let (s, e) = img.range();
            println!("verificado y mapeado {s:#x}-{e:#x}, entry={:#x}", img.entry());
            for (a, b, p) in &img.segments {
                println!("  segmento {a:#x}-{b:#x} prot={p:#x}");
            }
            // SAFETY: binario con firma válida de una clave de confianza.
            let r = unsafe { img.call_entry() };
            println!("entry devolvió {r}");
        }
        Err(LoadError::Refused(e)) => {
            println!("RECHAZADO antes de mapear: {e}");
            std::process::exit(1);
        }
        Err(e) => {
            println!("ERROR de carga: {e}");
            std::process::exit(1);
        }
    }
    Ok(())
}
