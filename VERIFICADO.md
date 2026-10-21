# VERIFICADO — criterio de aprobado del #9

Cuenta como **aprobado** solo si se cumplen todos:

1. `cargo build` y `cargo clippy --all-targets -- -D warnings` sin errores ni warnings.
2. `cargo test` en verde, incluyendo:
   - Cargador: `signed_fixture_loads_and_runs`, `unsigned_fixture_refused_without_mapping`,
     `other_key_refused`, `tampered_*`, `every_single_byte_flip_outside_sig_is_rejected`,
     `zk_alg_is_never_accepted`.
   - Supervisor: `signed_elf_runs_under_supervisor_via_mmap`,
     `signed_elf_runs_under_supervisor_via_mprotect`,
     `unsigned_elf_mmap_denied`, `other_key_mmap_denied`, `tampered_elf_mmap_denied`,
     `anonymous_jit_denied`.
3. `bash scripts/demo.sh` imprime `RESULTADO: PASS`.

**Se afirma (con evidencia de tests):** un proceso lanzado bajo
`fnbr-supervise` / `run_supervised` no obtiene `PROT_EXEC` sobre un ELF sin
firma válida ni sobre memoria anónima (JIT), sin necesidad de root ni BPF-LSM.

**No** se afirma: perímetro de kernel vía BPF-LSM; que `CONTINUE` elimine
todo TOCTOU; ni que un proceso fuera del supervisor no pueda saltearse el
cargador tipado.
