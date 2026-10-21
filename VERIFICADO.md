# VERIFICADO — criterio de aprobado del #9

Cuenta como **aprobado** solo si se cumplen todos:

1. `cargo build` y `cargo clippy --all-targets -- -D warnings` sin errores ni warnings.
2. `cargo test` en verde, incluyendo:
   - `signed_fixture_loads_and_runs`: el ELF firmado se mapea con W^X y su entry devuelve 296.
   - `unsigned_fixture_refused_without_mapping`: sin firma → `Refused`, y no queda nada mapeado.
   - `other_key_refused`, `tampered_text_is_bad_signature`, `tampered_signature_bytes_rejected`.
   - `every_single_byte_flip_outside_sig_is_rejected`: ningún byte adulterado pasa.
   - `zk_alg_is_never_accepted`: el marcador ZK v0.1 nunca acepta.
3. `bash scripts/demo.sh` imprime `RESULTADO: PASS`.

**No** se afirma: cumplimiento en kernel vía BPF-LSM, ni que un proceso fuera
del supervisor no pueda saltearse el cargador.
