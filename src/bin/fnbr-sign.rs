//! Paso post-link: prepara y firma `.fnbr.sig`.
//!
//!   fnbr-sign keygen <seed.hex> <pub.hex>
//!   fnbr-sign prepare <in.elf> <out.elf>      # agrega .fnbr.sig (128 B en cero) con objcopy
//!   fnbr-sign sign <seed.hex> <in.elf> <out.elf>
//!   fnbr-sign verify <pub.hex> <file.elf>

use std::process::Command;

use anyhow::{bail, Context, Result};
use ed25519_dalek::{Signer, SigningKey, VerifyingKey};
use fnbr_elf_loader::sigsection::{self, Alg, SigSection, SECTION_NAME, SECTION_SIZE};
use fnbr_elf_loader::verify::{key_id, verify_elf, Ed25519Verifier, ZkUnimplemented};

fn read_hex32(path: &str) -> Result<[u8; 32]> {
    let s = std::fs::read_to_string(path).with_context(|| format!("leer {path}"))?;
    let v = hex::decode(s.trim()).context("hex inválido")?;
    v.try_into().map_err(|_| anyhow::anyhow!("se esperaban 32 bytes en {path}"))
}

fn main() -> Result<()> {
    let a: Vec<String> = std::env::args().collect();
    match a.get(1).map(String::as_str) {
        Some("keygen") if a.len() == 4 => {
            let mut seed = [0u8; 32];
            std::fs::File::open("/dev/urandom")
                .and_then(|mut f| std::io::Read::read_exact(&mut f, &mut seed))?;
            let sk = SigningKey::from_bytes(&seed);
            std::fs::write(&a[2], hex::encode(seed) + "\n")?;
            std::fs::write(&a[3], hex::encode(sk.verifying_key().as_bytes()) + "\n")?;
            println!("clave generada; key_id={}", hex::encode(key_id(&sk.verifying_key())));
        }
        Some("prepare") if a.len() == 4 => {
            let zeros = std::env::temp_dir().join(format!("fnbr-zeros-{}", std::process::id()));
            std::fs::write(&zeros, [0u8; SECTION_SIZE])?;
            let st = Command::new("objcopy")
                .arg(format!("--add-section={SECTION_NAME}={}", zeros.display()))
                .arg(format!("--set-section-flags={SECTION_NAME}=readonly,contents"))
                .args([&a[2], &a[3]])
                .status()
                .context("ejecutar objcopy")?;
            let _ = std::fs::remove_file(&zeros);
            if !st.success() {
                bail!("objcopy falló");
            }
            println!("preparado {} (sección {SECTION_NAME} en cero, sin firmar)", a[3]);
        }
        Some("sign") if a.len() == 5 => {
            let sk = SigningKey::from_bytes(&read_hex32(&a[2])?);
            let mut bytes = std::fs::read(&a[3])?;
            let loc = sigsection::locate(&bytes).map_err(|e| anyhow::anyhow!("{e} (¿falta `prepare`?)"))?;
            let digest = sigsection::signing_digest(&bytes, loc);
            let sec = SigSection {
                alg: Alg::Ed25519 as u32,
                flags: 0,
                key_id: key_id(&sk.verifying_key()),
                proof: sk.sign(&digest).to_bytes(),
            };
            bytes[loc.offset..loc.offset + loc.size].copy_from_slice(&sec.to_bytes());
            std::fs::write(&a[4], &bytes)?;
            println!("firmado {} key_id={}", a[4], hex::encode(sec.key_id));
        }
        Some("verify") if a.len() == 4 => {
            let pk = VerifyingKey::from_bytes(&read_hex32(&a[2])?)?;
            let ed = Ed25519Verifier::new(vec![pk]);
            match verify_elf(std::fs::read(&a[3])?, &[&ed, &ZkUnimplemented]) {
                Ok(v) => println!("OK alg={:?} key_id={}", v.alg(), hex::encode(v.key_id())),
                Err(e) => {
                    println!("RECHAZADO: {e}");
                    std::process::exit(1);
                }
            }
        }
        _ => {
            eprintln!("uso: fnbr-sign keygen|prepare|sign|verify … (ver README)");
            std::process::exit(2);
        }
    }
    Ok(())
}
