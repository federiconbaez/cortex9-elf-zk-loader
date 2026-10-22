# 09 — Cargador ELF con verificación de `.fnbr.sig` antes de `PROT_EXEC`

> **ES:** Cargador ELF en Rust que solo ejecuta binarios firmados, con supervisor seccomp. Compilar/probar: `make && cargo test`.
> **EN:** Rust ELF loader that only executes signed binaries, with a seccomp supervisor. Build/test: `make && cargo test`.
>
> **Estado / Status: el PASS 149/149 de v0.3 (`e1b9d79`) quedó auditado sobre el corpus medido / v0.3 PASS 149/149 audited on the measured corpus** (`experimento/auditoria/AUDIT-valor-v03.md`, commit `388e569`). Re-corrida en clon aparte: 149/149, loader 0/40 FP, supervisor 0/55 FP, tests 56/56.
>
> **Salvedades / Caveats:**
> 1. `mremap` y `remap_file_pages` no se probaron: tienen política pero ningún ataque del corpus / have policy but no attack in the corpus.
> 2. Los 10/50 binarios glibc estáticos salieron del contrato del loader y no están arreglados / 10/50 static glibc binaries were removed from the loader contract, not fixed.
> 3. Falta un control positivo: el harness no muestra que cada ataque funcione sin supervisor / no positive control.
> 4. Los tres commits (corpus `198a7d4`, arreglo `6953a3d`, medición `e1b9d79`) se hicieron en tanda en 30 s: el orden prueba la secuencia, no que el arreglo se haya escrito después de fijar el corpus / committed in one batch.
>
> **Historia / History:** la auditoría anterior (`AUDIT-valor.md`, commit `0689cab`, antes `64413db`) dio FAIL: 122/143 = 85,3 % contra un umbral de 100 %, y 10/50 glibc estáticos sin correr. Licencia / License: MIT OR Apache-2.0 (el programa eBPF en `bpf/` es GPL-2.0, ver README.md / the eBPF program in `bpf/` is GPL-2.0, see README.md).


**Dueña:** בֶּן הָאֱלֹהִים הַחַי (rol de auditoría de seguridad)
**Pedido de Federico (20/10/2026):** linker y cargador ELF que verifique
pruebas criptográficas Zero-Knowledge en una sección `.fnbr.sig` antes de
permitir que el kernel mapee las páginas como ejecutables (`PROT_EXEC`).

## Flujo (v0.3)
```
gcc/ld ──► ELF ──► fnbr-sign prepare
                ├► fnbr-sign sign      (alg=1 Ed25519 sobre SHA-512)
                └► fnbr-sign zk-sign   (alg=2 Schnorr/Ristretto Fiat-Shamir)

A) Cargador tipado: fnbr-load → verify_elf → VerifiedElf → mmap/mprotect W^X
B) Cumplimiento real sin BPF-LSM: fnbr-supervise (seccomp USER_NOTIF)
```

Formato `.fnbr.sig` (128 B):
`magic "FNBRSIG1" | alg u32 | flags u32 | key_id[32] | prueba[64] | reservado[16]`.

| alg | Prueba | Binding |
|-----|--------|---------|
| 1 | Ed25519 | SHA-512 del archivo con la sección en cero + dominio `FNBR-ELF-SIG-v1` |
| 2 | Schnorr no interactivo sobre Ristretto255 | transcript Fiat-Shamir SHA-512(`FNBR-ZK-SCHNORR-v1` ‖ R ‖ K ‖ SHA-256(archivo con sección en cero)) |

## Qué prueba el ZK (`alg=2`) — y qué no

**SE prueba:** conocimiento del logaritmo discreto `k` tal que `K = k·B`
(clave pública del publicador en Ristretto255), con el desafío atado al
SHA-256 de este binario (sección en cero) y a `K`. Quien verifica acepta
solo si el publicador conocía `k` para ese `K` ligado a ese hash.

**Dicho sin rodeos:** un Schnorr Fiat-Shamir atado a un mensaje es, matemáticamente, una **firma Schnorr**. Es zero-knowledge respecto de la clave secreta `k`, y solo prueba que el dueño de `K` respaldó este hash.

**NO se prueba:** corrección del programa, inocuidad, ausencia de bugs, ni
que el binario sea “el que uno quiere”. No es una zk-SNARK/STARK del código.
Es una prueba de conocimiento de clave atada al hash, no una prueba de
propiedades del programa.

## Supervisor seccomp
Intercepta `mmap`/`mprotect` con `PROT_EXEC`. Para `mmap` con archivo lee
bytes por `/proc/<pid>/fd/<n>` (mismo open file). Niega JIT anónimo.
Sin root (`NO_NEW_PRIVS`). TOCTOU de `CONTINUE`: ver `LIMITES.md`.

## Compilar y probar
```bash
bash scripts/build-fixtures.sh
cargo build && cargo test && cargo clippy --all-targets -- -D warnings
bash scripts/demo.sh
# ZK a mano:
cargo run --bin fnbr-sign -- zk-keygen /tmp/zk.seed /tmp/zk.pub
cargo run --bin fnbr-sign -- zk-sign /tmp/zk.seed fixtures/guest.unsigned.elf /tmp/g.zk.elf
cargo run --bin fnbr-sign -- zk-verify /tmp/zk.pub /tmp/g.zk.elf
```
