# fnbr-elf-zk-loader

> **Status: experimental research code. Not production-ready and not a security boundary you should rely on.**
> Spanish documentation: [`README.es.md`](README.es.md), [`LIMITES.md`](LIMITES.md), [`VERIFICADO.md`](VERIFICADO.md).

## What it is

A Rust experiment in refusing to execute ELF binaries that do not carry a valid signature in a custom `.fnbr.sig` section. It has two parts:

- **Typed loader (`fnbr-load`)**: verifies the `.fnbr.sig` section, then maps the ELF with W^X. It supports only static `ET_EXEC` binaries without PIE. It does not set up a stack, auxv or TLS for glibc, so static glibc binaries are **outside its contract**: they verify but do not run.
- **Supervisor (`fnbr-supervise`)**: a seccomp `USER_NOTIF` supervisor (plus memfd/`execveat` and Landlock in v0.3). It denies `PROT_EXEC` mappings and execution of unverified code for the processes it supervises. It only covers processes started under it.
- **Signing (`fnbr-sign`)**: `alg=1` is Ed25519 over SHA-512. `alg=2` is a non-interactive Schnorr proof over Ristretto255 (Fiat-Shamir), bound to the file hash. It is zero-knowledge only with respect to the signer's secret key; mathematically it is a Schnorr signature. It proves **nothing** about the program's behaviour or correctness, and it is not a SNARK/STARK.
- `bpf/lsm_exec_guard.bpf.c`: a BPF-LSM guard that was **never loaded or tested**, because the test kernel lacks `CONFIG_BPF_LSM`.

## Build and test

Requirements: Linux x86_64, Rust ≥ 1.85, `gcc` and `objcopy` (to rebuild fixtures). For the optional BPF-LSM object: `clang`, `bpftool` and a kernel with BTF.

```bash
bash scripts/build-fixtures.sh   # rebuilds fixtures/*.elf and fixtures/rawload
cargo build --release
cargo test --release             # 17 + 16 + 23 = 56 tests
cargo clippy --all-targets -- -D warnings
bash scripts/demo.sh
bash scripts/experimento-valor.sh   # the value experiment (see Audit status)
```

## Audit status

These are internal audits done by the same team (AI agents working for the author). They are **not** independent third-party audits. All hashes refer to the rewritten history (see [`docs/HASHES.md`](docs/HASHES.md)).

### Audit 1: FAILED (`AUDIT-valor.md`, commit `0689cab`, formerly `64413db`)

The audit covered experiment commit `b14c2a0`. The threshold was 100 % of in-scope attacks blocked with 0 false positives on the valid corpus. **It failed in all four categories**: unsigned ELF, tampered ELF, ELF signed with another key, and anonymous RWX/JIT under the supervisor.

- 122/143 in-scope attacks were blocked (85.3 %). The loader rejected 100 % of the cryptographic cases. The supervisor, however, let unsigned, tampered and wrong-key static binaries run through `execve`, and also allowed code execution via `pkey_mprotect`, i386 `int $0x80` `mprotect`, and `READ_IMPLIES_EXEC`.
- 10 of 50 valid, signed static glibc binaries failed to run in the loader (20 % functional failure inside the contract documented at the time).
- Root cause: the cBPF filter only trapped `mmap` and `mprotect`. Everything else, including non-x86_64 syscalls, was allowed.

The audit listed **8 conditions for re-measuring**:
1. A new corpus with a fixed seed, committed **before** re-measuring, with genuinely different samples per seed and the raw evidence (`results.json`, logs) versioned.
2. The 7 existing hole families, plus variants: `execveat(AT_EMPTY_PATH)` and via a normal-path fd, `fexecve`, `binfmt_misc`/`binfmt_script` if applicable, nested shebang, and tampered and wrong-key binaries **via `execve`** under the supervisor.
3. Coverage beyond `mmap`/`mprotect`: `pkey_mprotect`, i386 (`int $0x80`) and x32 syscalls, `remap_file_pages`/`mremap` of executable VMAs, and `personality` (READ_IMPLIES_EXEC), including on an anonymous page.
4. Injection: `ptrace` (POKETEXT or regs) and `process_vm_writev` on a supervised child's `.text`, `/proc/pid/mem`, `userfaultfd` on a verified `mmap` range, and writing a `MAP_SHARED` file after verification (shared inode).
5. vDSO/vsyscall counts neither as a false positive nor as a bypass, but this must be stated explicitly.
6. False-positive rate over the **full** valid corpus, per surface: the loader with all static `ET_EXEC` binaries (including glibc), or a loader contract redefined and committed beforehand; the supervisor with everything, using a harness without a hard-coded return value.
7. p50/p99 exec latency under the supervisor versus plain exec of the same binary, plus the hashing cost per `execve`, with n stated.
8. The same threshold (100 % in scope, 0 false positives). Only what `LIMITES.md` excludes **before** measuring may be out of scope.

### Audit 2: v0.3 re-measurement PASSED on the measured corpus (`experimento/auditoria/AUDIT-valor-v03.md`, commit `388e569`)

Commits `198a7d4` (pre-measurement corpus and contract), `6953a3d` (supervisor v0.3) and `e1b9d79` ("PASS 149/149") were audited afterwards by the same internal auditor. An independent re-run reproduced 149/149 in-scope attacks blocked, 0/40 false positives for the loader and 0/55 for the supervisor, and 56/56 tests passing. Supervisor exec latency was p50 ≈ 4.25 ms versus ≈ 0.43 ms for plain exec (n = 30).

Caveats stated by that audit:
- `mremap` and `remap_file_pages` have a policy in the code, but **no attack in the corpus exercises them** (condition 3 is only partly met).
- The static-glibc failure was resolved by **narrowing the loader contract** (glibc static is now out of scope for the loader, in scope for the supervisor), **not by fixing the loader**.
- There is no positive control: the harness counts any errno as "blocked" and does not show that each attack works without the supervisor.
- The three v0.3 commits were made within about 30 seconds of each other. Their order does not prove that the fix was written after the corpus was fixed.
- Small n: 2–3 deterministic cases per family. There was one re-run, on a single shared machine.
- The auditor's confidence was medium-high that 149/149 is correct on the measured corpus, and medium on generalisation.

**Bottom line:** v1 failed its threshold. v0.3 passes **on the measured corpus only**, with the open gaps listed above. Treat this as a research prototype.

## Test keys

`fixtures/keys/test_seed.hex` and `fixtures/keys/other_seed.hex` are **Ed25519 private seeds published on purpose** so that the tests are reproducible. Anyone can sign with them. Never trust these keys for anything real.

## License

Licensed under either of

- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE))
- MIT license ([LICENSE-MIT](LICENSE-MIT))

at your option.

**Exception:** `bpf/lsm_exec_guard.bpf.c` is licensed **GPL-2.0** (`SPDX-License-Identifier: GPL-2.0`, `LICENSE[] = "GPL"`). The kernel requires a GPL-compatible license for the BPF helpers it uses. That file is built separately (`make lsm`) and is not linked into the Rust binaries.

Unless you explicitly state otherwise, any contribution you intentionally submit for inclusion in this work, as defined in the Apache-2.0 license, shall be dual licensed as above, without any additional terms or conditions.
