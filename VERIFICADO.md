# VERIFICADO — criterio de aprobado del #9

Cuenta como **aprobado** solo si se cumplen todos:

1. `cargo build` y `cargo clippy --all-targets -- -D warnings` limpios.
2. `cargo test` en verde (≥ 38 tests), incluyendo:
   - Cargador Ed25519: firmado corre (entry=296), sin firma / otra clave /
     adulterado se rechazan; barrido de un byte.
   - Supervisor: firmado corre bajo USER_NOTIF; unsigned/other/tampered/JIT
     anónimo denegados con EPERM.
   - ZK Schnorr: prueba válida aceptada; clave incorrecta, sección adulterada
     y prueba adulterada rechazadas (`zk::tests::*`, `schnorr_*` en loader).
3. `bash scripts/demo.sh` → `RESULTADO: PASS`.

**Se afirma:** cumplimiento PROT_EXEC bajo supervisor sin root/BPF-LSM;
prueba ZK genuina (Schnorr/Ristretto Fiat-Shamir) con binding al hash.

**No se afirma:** perímetro LSM de kernel; eliminación total de TOCTOU de
CONTINUE; prueba de corrección del programa vía ZK.
