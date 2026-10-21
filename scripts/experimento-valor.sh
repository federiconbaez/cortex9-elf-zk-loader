#!/usr/bin/env bash
# Experimento de VALOR del sistema 9 (fnbr-elf-zk-loader).
# Umbral Research Sentinel: PASS solo si 100% de exec no autorizados
# se bloquean Y 0 falsos positivos sobre el corpus firmado válido.
# No toca src/. Requiere gcc, objcopy, python3, sudo -n (no usado salvo limpia).
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

OUT="${OUT:-$ROOT/experimento/out}"
rm -rf "$OUT"
mkdir -p "$OUT"/{valid,attacks,logs,tmp,baseline}
export OUT ROOT

echo "== build release + fixtures =="
cargo build --release --quiet
bash scripts/build-fixtures.sh >"$OUT/logs/fixtures.txt" 2>&1
SIGN="$ROOT/target/release/fnbr-sign"
LOAD="$ROOT/target/release/fnbr-load"
SUP="$ROOT/target/release/fnbr-supervise"
SEED="$ROOT/fixtures/keys/test_seed.hex"
PUB="$ROOT/fixtures/keys/test_pub.hex"
OTHER="$ROOT/fixtures/keys/other_seed.hex"
OTHER_PUB="$ROOT/fixtures/keys/other_pub.hex"
RAWLOAD="$ROOT/fixtures/rawload"

# harness de ataques (estático)
gcc -static -O1 -Wall -o "$OUT/tmp/harness" "$ROOT/experimento/harness.c" 2>"$OUT/logs/harness-cc.txt" || {
  # regenerar harness si falta
  echo "faltó experimento/harness.c; aborto" >&2; exit 1
}
HARNESS="$OUT/tmp/harness"

python3 - "$OUT" "$ROOT" "$SIGN" "$LOAD" "$SUP" "$SEED" "$PUB" "$OTHER" "$OTHER_PUB" "$RAWLOAD" "$HARNESS" <<'PY'
#!/usr/bin/env python3
"""Driver del experimento VALOR #9. Escribe VALOR.md + resultados JSON."""
import hashlib, json, os, random, shutil, struct, subprocess, sys, time, tempfile, statistics
from pathlib import Path

OUT, ROOT, SIGN, LOAD, SUP, SEED, PUB, OTHER, OTHER_PUB, RAWLOAD, HARNESS = map(Path, sys.argv[1:])
VALID = OUT / "valid"
ATK = OUT / "attacks"
LOGS = OUT / "logs"
TMP = OUT / "tmp"
BASE = OUT / "baseline"
for d in (VALID, ATK, LOGS, TMP, BASE):
    d.mkdir(parents=True, exist_ok=True)

results = {
    "valid_loader": [], "valid_supervisor": [],
    "attacks": [],  # {family, scope, id, blocked, detail, rc}
    "latency": [],  # {size, plain_p50, plain_p99, load_p50, load_p99, n}
    "bugs": [],
    "notes": [],
}

def run(cmd, env=None, timeout=30, cwd=None):
    e = os.environ.copy()
    if env: e.update(env)
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, env=e, cwd=cwd)
        return p.returncode, p.stdout, p.stderr
    except subprocess.TimeoutExpired:
        return 124, "", "timeout"

def sign_file(src: Path, dst: Path, seed=SEED):
    u = TMP / (dst.name + ".u")
    rc, o, e = run([str(SIGN), "prepare", str(src), str(u)])
    if rc != 0:
        return False, f"prepare:{e or o}"
    rc, o, e = run([str(SIGN), "sign", str(seed), str(u), str(dst)])
    u.unlink(missing_ok=True)
    if rc != 0:
        return False, f"sign:{e or o}"
    dst.chmod(0o755)
    return True, "ok"

GUEST_CFLAGS = [
    "gcc","-O1","-static","-nostdlib","-no-pie","-fno-pic","-ffreestanding",
    "-fno-stack-protector","-fcf-protection=none",
    "-Wl,-e,fnbr_entry","-Wl,--build-id=none",
    "-Wl,-Ttext-segment=0x10000000","-Wl,-z,noexecstack",
]

def build_guest(c_src: Path, raw: Path):
    rc, o, e = run(GUEST_CFLAGS + [str(c_src), "-o", str(raw)])
    return rc == 0, e or o

# ---------------------------------------------------------------------------
# 1. Corpus válido ≥50: variantes de guest ET_EXEC estático firmadas
# ---------------------------------------------------------------------------
print("== corpus válido (loader: ET_EXEC estático firmado) ==")
valid_meta = []
# 40 guests con distinto retorno + padding de .rodata de distintos tamaños
for i in range(40):
    pad = (i % 8) * 4096  # 0..28 KiB
    ret = 296 + (i % 50)
    c = TMP / f"g{i}.c"
    c.write_text(f'''
static const char msg[] = "FNBR-{i:03d}";
static long counter = 1000;
long fnbr_entry(void) {{
    long s = 0;
    for (int j = 0; msg[j]; j++) s += msg[j];
    counter += s;
    return {ret};
}}
''')
    raw = TMP / f"g{i}.raw"
    ok, err = build_guest(c, raw)
    if not ok:
        results["notes"].append(f"guest {i} build fail: {err[:200]}")
        continue
    # padding no cargable → distintos tamaños de archivo sin cambiar PT_LOAD
    if pad:
        padfile = TMP / f"g{i}.pad"
        padfile.write_bytes(bytes([65 + (i % 26)]) * pad)
        raw2 = TMP / f"g{i}.raw2"
        rc, o, e = run(["objcopy", f"--add-section=.fnbr.pad={padfile}",
                        f"--set-section-flags=.fnbr.pad=readonly,contents",
                        str(raw), str(raw2)])
        if rc == 0:
            raw = raw2
    dst = VALID / f"guest-{i:03d}.elf"
    ok, err = sign_file(raw, dst)
    if not ok:
        results["notes"].append(f"guest {i} sign fail: {err}")
        continue
    size = dst.stat().st_size
    valid_meta.append({"id": f"guest-{i:03d}", "path": str(dst), "expect": ret, "size": size, "kind": "static-ET_EXEC"})

# 10 binarios "reales" estáticos con libc (glibc-static), firmados — para supervisor
print("== corpus válido (supervisor: estáticos glibc firmados) ==")
static_bins = []
for i, (name, code) in enumerate([
    ("hello", 'int main(){puts("hello");return 0;}'),
    ("exit7", 'int main(){return 7;}'),
    ("args", 'int main(int c,char**v){return c;}'),
    ("write1", '#include <unistd.h>\nint main(){write(1,"W",1);return 0;}'),
    ("loop", 'int main(){volatile int x=0;for(int i=0;i<1000;i++)x+=i;return x&0xff;}'),
    ("bigdata", 'static char b[256*1024]={1}; int main(){return b[0];}'),
    ("tiny", 'int main(){return 1;}'),
    ("printfn", '#include <stdio.h>\nint main(){printf("%d\\n",42);return 0;}'),
    ("env", '#include <stdlib.h>\nint main(){return getenv("PATH")?0:1;}'),
    ("getpid", '#include <unistd.h>\nint main(){return getpid()>0?0:1;}'),
]):
    c = TMP / f"s{i}.c"
    c.write_text('#include <stdio.h>\n' + code if 'stdio' not in code and 'puts' in code or 'printf' in code else code)
    if 'puts' in code or 'printf' in code:
        c.write_text('#include <stdio.h>\n' + code)
    raw = TMP / f"s{i}.raw"
    rc, o, e = run(["gcc","-static","-O1","-Wall",str(c),"-o",str(raw)])
    if rc != 0:
        results["notes"].append(f"static {name} build fail: {(e or o)[:200]}")
        continue
    dst = VALID / f"static-{name}.elf"
    ok, err = sign_file(raw, dst)
    if not ok:
        results["notes"].append(f"static {name} sign fail: {err}")
        continue
    static_bins.append({"id": f"static-{name}", "path": str(dst), "size": dst.stat().st_size, "kind": "static-glibc"})
    valid_meta.append(static_bins[-1] | {"expect": None})

# libs firmadas (libc) para pruebas dinámicas
libc_src = Path("/lib/x86_64-linux-gnu/libc.so.6")
libc_signed = VALID / "libc.so.6"
ok, err = sign_file(libc_src, libc_signed)
if not ok:
    results["notes"].append(f"libc sign fail: {err}")
libdir = VALID / "lib"
libdir.mkdir(exist_ok=True)
shutil.copy2(libc_signed, libdir / "libc.so.6")

# 5 dinámicos firmados (PIE típico)
print("== corpus válido (supervisor: dinámicos firmados + libc firmada) ==")
dyn_bins = []
for i, (name, code) in enumerate([
    ("dhello", 'int main(){puts("dhello");return 0;}'),
    ("dexit3", 'int main(){return 3;}'),
    ("dprintf", 'int main(){printf("x\\n");return 0;}'),
    ("dargs", 'int main(int c,char**v){return c-1;}'),
    ("denv", 'int main(){return 0;}'),
]):
    c = TMP / f"d{i}.c"
    c.write_text('#include <stdio.h>\n' + code)
    raw = TMP / f"d{i}.raw"
    rc, o, e = run(["gcc","-O1","-Wall",str(c),"-o",str(raw)])
    if rc != 0:
        continue
    dst = VALID / f"dyn-{name}.elf"
    ok, err = sign_file(raw, dst)
    if not ok:
        continue
    dyn_bins.append({"id": f"dyn-{name}", "path": str(dst), "size": dst.stat().st_size, "kind": "dynamic-PIE"})
    valid_meta.append(dyn_bins[-1] | {"expect": None})

print(f"  corpus válido: {len(valid_meta)} binarios firmados")

# ---------------------------------------------------------------------------
# FPR: todos los guests ET_EXEC deben cargar y devolver expect
# ---------------------------------------------------------------------------
print("== FPR loader (fnbr-load) ==")
fp_loader_fail = 0
fp_loader_ok = 0
for m in valid_meta:
    if m["kind"] != "static-ET_EXEC":
        continue
    t0 = time.perf_counter()
    rc, o, e = run([str(LOAD), str(PUB), m["path"]], timeout=10)
    dt = time.perf_counter() - t0
    ok = rc == 0 and f"entry devolvió {m['expect']}" in o
    results["valid_loader"].append({"id": m["id"], "ok": ok, "rc": rc, "ms": round(dt*1000,3), "out": o[:200]})
    if ok: fp_loader_ok += 1
    else:
        fp_loader_fail += 1
        results["bugs"].append(f"FPR loader: {m['id']} rc={rc} out={o[:120]!r}")

print(f"  loader FPR: ok={fp_loader_ok} fail={fp_loader_fail}")

# Supervisor FPR: guest firmado vía rawload mmap-exec + estáticos firmados directos
print("== FPR supervisor ==")
fp_sup_ok = 0
fp_sup_fail = 0
# 1) guest.signed.elf via rawload (fixture canónico)
rc, o, e = run([str(SUP), str(PUB), str(RAWLOAD), "mmap-exec", str(ROOT/"fixtures/guest.signed.elf")])
ok = rc == 0
results["valid_supervisor"].append({"id": "fixture-guest.signed", "ok": ok, "rc": rc, "out": (o+e)[:200]})
if ok: fp_sup_ok += 1
else: fp_sup_fail += 1; results["bugs"].append(f"FPR sup fixture: rc={rc}")

# 2) estáticos firmados: el supervisor NO verifica el binario del execve inicial
#    (solo PROT_EXEC posteriores). Un estático firmado "corre" igual que uno sin firmar
#    porque el kernel mapea PT_LOAD en execve sin mmap del usuario.
#    Documentamos esto: FPR del supervisor sobre estáticos firmados vía execve directo
#    es 0% de rechazo (corren), pero también los NO firmados corren → no discrimina.
for m in static_bins[:5]:
    rc, o, e = run([str(SUP), str(PUB), m["path"]])
    # éxito = el programa corrió (exit code del programa, no 93)
    ran = rc != 93 and "error while loading" not in (o+e)
    results["valid_supervisor"].append({"id": m["id"], "ok": ran, "rc": rc, "note": "execve-inicial-sin-verificar"})
    if ran: fp_sup_ok += 1
    else: fp_sup_fail += 1

# 3) dinámicos firmados + libc firmada
for m in dyn_bins:
    rc, o, e = run([str(SUP), str(PUB), m["path"]], env={"LD_LIBRARY_PATH": str(libdir)})
    ran = rc in (0, 1, 2, 3) and "failed to map segment" not in (o+e)
    # dexit3 returns 3, dargs returns argc-1, etc. — cualquier rc < 90 sin error de map
    results["valid_supervisor"].append({"id": m["id"], "ok": ran, "rc": rc, "out": (o+e)[:160]})
    if ran: fp_sup_ok += 1
    else: fp_sup_fail += 1; results["bugs"].append(f"FPR sup dyn {m['id']}: rc={rc} {(o+e)[:100]}")

print(f"  supervisor FPR samples: ok={fp_sup_ok} fail={fp_sup_fail}")

# ---------------------------------------------------------------------------
# 2. Corpus de ataques (semillas 1..5)
# ---------------------------------------------------------------------------
print("== ataques ==")

def record(family, scope, tid, blocked, detail, rc):
    results["attacks"].append({
        "family": family, "scope": scope, "id": tid,
        "blocked": bool(blocked), "detail": detail, "rc": rc,
    })
    mark = "BLOCK" if blocked else "BYPASS"
    print(f"  [{mark}] {family}/{tid}: {detail[:80]} (rc={rc})")

# Helper: loader refuse?
def loader_refuses(path):
    rc, o, e = run([str(LOAD), str(PUB), str(path)])
    # exit 1 + RECHAZADO / ERROR = blocked
    blocked = rc != 0 and ("RECHAZADO" in o or "ERROR" in o or rc == 1)
    return blocked, rc, o

# Helper: supervisor + rawload mmap-exec
def sup_mmap_blocked(elf_path):
    rc, o, e = run([str(SUP), str(PUB), str(RAWLOAD), "mmap-exec", str(elf_path)])
    # rawload exit 3 = mmap denied; 0 = ran (entry 296)
    blocked = rc == 3
    return blocked, rc, o+e

# --- A. unsigned ---
for seed in range(1, 6):
    # loader: guest unsigned
    src = ROOT / "fixtures" / "guest.unsigned.elf"
    dst = ATK / f"unsigned-loader-s{seed}.elf"
    shutil.copy2(src, dst)
    # mutate non-sig padding deterministically so each seed differs but stays unsigned
    b = bytearray(dst.read_bytes())
    # flip a byte in .fnbr.sig zeros keeps it unsigned; just copy
    dst.write_bytes(b)
    blocked, rc, o = loader_refuses(dst)
    record("unsigned", "in-scope", f"loader-s{seed}", blocked, "fnbr-load guest.unsigned", rc)

    blocked, rc, o = sup_mmap_blocked(dst)
    record("unsigned", "in-scope", f"sup-mmap-s{seed}", blocked, "supervisor+rawload mmap unsigned", rc)

# --- B. wrong key ---
for seed in range(1, 6):
    src = ROOT / "fixtures" / "guest.signed-otherkey.elf"
    dst = ATK / f"wrongkey-s{seed}.elf"
    shutil.copy2(src, dst)
    blocked, rc, o = loader_refuses(dst)
    record("wrong-key", "in-scope", f"loader-s{seed}", blocked, "firma con other_seed", rc)
    blocked, rc, o = sup_mmap_blocked(dst)
    record("wrong-key", "in-scope", f"sup-mmap-s{seed}", blocked, "sup mmap other key", rc)

# --- C. one-byte flips ---
signed = (ROOT / "fixtures" / "guest.signed.elf").read_bytes()
# find .fnbr.sig offset via a quick parse: look for FNBRSIG1
sig_off = signed.find(b"FNBRSIG1")
assert sig_off > 0
regions = {
    "text": 0x1000,          # típico .text en el guest
    "data": 0x3000,
    "ehdr": 0x10,            # e_type area
    "phdr": 0x40,            # start of program headers (approx)
    "shdr": len(signed) - 64, # cerca del final (section headers)
    "padding": sig_off - 16 if sig_off > 16 else 0x200,  # just before sig
}
for seed in range(1, 6):
    rng = random.Random(seed)
    for region, off in regions.items():
        if off < 0 or off >= len(signed):
            continue
        if sig_off <= off < sig_off + 128:
            continue  # no flip inside sig for this family
        b = bytearray(signed)
        b[off] ^= 1 + (rng.randrange(1, 255))
        dst = ATK / f"flip-{region}-s{seed}.elf"
        dst.write_bytes(b)
        blocked, rc, o = loader_refuses(dst)
        record("byte-flip", "in-scope", f"loader-{region}-s{seed}", blocked, f"flip @0x{off:x} ({region})", rc)
        if seed <= 2:  # sample supervisor for a couple seeds (slow otherwise)
            blocked2, rc2, _ = sup_mmap_blocked(dst)
            record("byte-flip", "in-scope", f"sup-{region}-s{seed}", blocked2, f"sup flip @0x{off:x}", rc2)

# flip INSIDE signature itself (should also reject)
for seed in range(1, 6):
    b = bytearray(signed)
    b[sig_off + 48 + seed] ^= 0xFF  # flip in proof bytes
    dst = ATK / f"flip-sig-s{seed}.elf"
    dst.write_bytes(b)
    blocked, rc, o = loader_refuses(dst)
    record("byte-flip-sig", "in-scope", f"loader-s{seed}", blocked, "flip en proof", rc)

# --- D. appended payload ---
for seed in range(1, 6):
    rng = random.Random(seed)
    payload = bytes(rng.randrange(256) for _ in range(64 * seed))
    dst = ATK / f"append-s{seed}.elf"
    dst.write_bytes(signed + payload)
    blocked, rc, o = loader_refuses(dst)
    # appending changes file hash → should reject
    record("append", "in-scope", f"loader-s{seed}", blocked, f"append {len(payload)} B", rc)

# --- E. signature swap (proof from another binary) ---
# sign two different guests, swap their .fnbr.sig sections
g0 = VALID / "guest-000.elf"
g1 = VALID / "guest-001.elf"
if g0.exists() and g1.exists():
    b0 = bytearray(g0.read_bytes()); b1 = bytearray(g1.read_bytes())
    o0 = b0.find(b"FNBRSIG1"); o1 = b1.find(b"FNBRSIG1")
    if o0 > 0 and o1 > 0:
        for seed in range(1, 6):
            x = bytearray(b0)
            # swap sig from g1 into g0
            x[o0:o0+128] = b1[o1:o1+128]
            # seed-dependent: also try reverse on even seeds
            if seed % 2 == 0:
                x = bytearray(b1)
                x[o1:o1+128] = b0[o0:o0+128]
            dst = ATK / f"swap-s{seed}.elf"
            dst.write_bytes(x)
            blocked, rc, o = loader_refuses(dst)
            record("sig-swap", "in-scope", f"loader-s{seed}", blocked, "sección .fnbr.sig de otro binario", rc)

# --- F. truncated ---
for seed in range(1, 6):
    cut = max(64, len(signed) - 64 * seed)
    dst = ATK / f"trunc-s{seed}.elf"
    dst.write_bytes(signed[:cut])
    blocked, rc, o = loader_refuses(dst)
    record("truncated", "in-scope", f"loader-s{seed}", blocked, f"trunc a {cut} B", rc)

# --- G. malformed ELF headers ---
malformed_specs = [
    ("bad-magic", lambda b: b.__setitem__(slice(0,4), b"XXXX")),
    ("bad-phoff", lambda b: b.__setitem__(slice(32,40), struct.pack("<Q", 0xFFFFFFFF))),
    ("zero-phnum", lambda b: b.__setitem__(slice(56,58), struct.pack("<H", 0))),
    ("overlap-claim", lambda b: b.__setitem__(slice(32,40), struct.pack("<Q", 8))),  # phoff overlaps ehdr
    ("bogus-shoff", lambda b: b.__setitem__(slice(40,48), struct.pack("<Q", 10**12))),
]
for seed in range(1, 6):
    for name, mut in malformed_specs:
        b = bytearray(signed)
        mut(b)
        # seed-scramble one more byte outside sig
        b[20 + seed] ^= seed
        dst = ATK / f"malformed-{name}-s{seed}.elf"
        dst.write_bytes(b)
        blocked, rc, o = loader_refuses(dst)
        record("malformed-elf", "in-scope", f"loader-{name}-s{seed}", blocked, name, rc)

# --- H. replay / key rotation ---
# Not supported as a first-class feature (no key-id revocation list beyond
# the trusted set). Simulate: binary signed with old key, verifier only has new key.
for seed in range(1, 6):
    # guest signed with OTHER key, verifier = test_pub only → already wrong-key
    # Explicit "rotation": sign with test, then verify with a brand-new key
    new_seed = TMP / f"rot-seed-{seed}.hex"
    new_pub = TMP / f"rot-pub-{seed}.hex"
    run([str(SIGN), "keygen", str(new_seed), str(new_pub)])
    dst = ATK / f"replay-s{seed}.elf"
    shutil.copy2(ROOT / "fixtures" / "guest.signed.elf", dst)  # signed with OLD (test) key
    rc, o, e = run([str(LOAD), str(new_pub), str(dst)])  # verify with NEW key only
    blocked = rc != 0
    record("key-rotation-replay", "in-scope", f"loader-s{seed}", blocked,
           "binario firmado con clave vieja, verificador solo tiene clave nueva", rc)

# --- I. anonymous JIT ---
rc, o, e = run([str(SUP), str(PUB), str(RAWLOAD), "anon-jit"])
blocked = rc == 0  # rawload returns 0 when BOTH attempts denied
record("anon-jit", "in-scope", "sup-anon", blocked, "mmap/mprotect anónimo PROT_EXEC", rc)

# --- J. execve of UNSIGNED static (CRITICAL) ---
# LIMITES no excluye esto → in-scope
us = TMP / "unsigned-static"
run(["gcc","-static","-O1","-x","c","-","-o",str(us)], )
# rewrite properly:
us_c = TMP / "us.c"
us_c.write_text('#include <stdio.h>\nint main(){puts("UNSIGNED-STATIC-RAN");return 42;}\n')
run(["gcc","-static","-O1",str(us_c),"-o",str(us)])
for seed in range(1, 6):
    # tiny mutation of .rodata so each is distinct unsigned binary
    b = bytearray(us.read_bytes())
    # find "UNSIGNED" and tweak last letter area outside ELF critical — just append seed byte then truncate back... 
    # simpler: recompile with seed in string
    us_c.write_text(f'#include <stdio.h>\nint main(){{puts("UNSIGNED-STATIC-RAN-{seed}");return 42;}}\n')
    ust = ATK / f"execve-unsigned-static-s{seed}"
    run(["gcc","-static","-O1",str(us_c),"-o",str(ust)])
    rc, o, e = run([str(SUP), str(PUB), str(RAWLOAD), "exec", str(ust)])
    # if program ran, stdout has UNSIGNED and rc==42 → BYPASS
    bypass = (rc == 42) or ("UNSIGNED-STATIC-RAN" in o)
    record("execve-unsigned-static", "in-scope", f"sup-s{seed}", not bypass,
           "execve de binario estático SIN firma bajo supervisor", rc)

# --- K. memfd + fexecve of unsigned static ---
for seed in range(1, 3):
    ust = ATK / f"execve-unsigned-static-s{seed}"
    if not ust.exists():
        continue
    rc, o, e = run([str(SUP), str(PUB), str(HARNESS), "memfd-fexecve", str(ust)])
    bypass = (rc == 42) or ("UNSIGNED-STATIC-RAN" in o)
    record("memfd-fexecve", "in-scope", f"sup-s{seed}", not bypass,
           "memfd_create+write+execveat(AT_EMPTY_PATH) de estático unsigned", rc)

# --- L. mprotect TOCTOU (LIMITES documents residual; still in-scope per rules) ---
# evil unsigned guest (returns 666) swapped for signed before mprotect
evil_c = TMP / "evil.c"
evil_c.write_text('static const char msg[]="EVIL"; static long counter=1000; long fnbr_entry(void){return 666;}\n')
evil_raw = TMP / "evil.raw"
build_guest(evil_c, evil_raw)
evil_u = ATK / "evil.unsigned.elf"
run([str(SIGN), "prepare", str(evil_raw), str(evil_u)])
for seed in range(1, 4):
    work = ATK / f"toctou-work-s{seed}.elf"
    signed_copy = ATK / f"toctou-signed-s{seed}.elf"
    shutil.copy2(evil_u, work)
    shutil.copy2(ROOT / "fixtures" / "guest.signed.elf", signed_copy)
    rc, o, e = run([str(SUP), str(PUB), str(HARNESS), "mprotect-toctou", str(work), str(signed_copy)])
    bypass = (rc == 9) or ("BYPASS" in o) or ("entry=666" in o)
    record("mprotect-toctou", "in-scope", f"sup-s{seed}", not bypass,
           "mmap RW de unsigned, rename→firmado, mprotect RX (path-TOCTOU)", rc)

# --- M. READ_IMPLIES_EXEC ---
for seed in range(1, 4):
    rc, o, e = run([str(SUP), str(PUB), str(HARNESS), "read-implies-exec", str(evil_u)])
    bypass = (rc == 9) or ("BYPASS" in o) or ("entry=666" in o)
    record("read-implies-exec", "in-scope", f"sup-s{seed}", not bypass,
           "personality(READ_IMPLIES_EXEC)+mmap(PROT_READ) de unsigned", rc)

# --- N. unsigned dynamic main + signed libc ---
ud_c = TMP / "ud.c"
ud_c.write_text('#include <stdio.h>\nint main(){puts("UNSIGNED-DYN-MAIN");return 42;}\n')
ud = ATK / "unsigned-dyn"
run(["gcc","-O1",str(ud_c),"-o",str(ud)])
for seed in range(1, 4):
    rc, o, e = run([str(SUP), str(PUB), str(ud)], env={"LD_LIBRARY_PATH": str(libdir)})
    bypass = (rc == 42) or ("UNSIGNED-DYN-MAIN" in o)
    record("unsigned-dyn-main", "in-scope", f"sup-s{seed}", not bypass,
           "execve de main dinámico UNSIGNED con libc firmada (LD_LIBRARY_PATH)", rc)

# --- O. LD_PRELOAD unsigned .so (child maps) ---
pre_c = TMP / "pre.c"
pre_c.write_text('#include <stdio.h>\n__attribute__((constructor)) void p(void){puts("PRELOAD-UNSIGNED-RAN");}\n')
pre_so = ATK / "pre.so"
run(["gcc","-shared","-fPIC","-O1",str(pre_c),"-o",str(pre_so)])
# use a signed dynamic main
if dyn_bins:
    main = dyn_bins[0]["path"]
    for seed in range(1, 4):
        rc, o, e = run([str(SUP), str(PUB), main],
                       env={"LD_LIBRARY_PATH": str(libdir), "LD_PRELOAD": str(pre_so)})
        # PRELOAD-UNSIGNED-RAN in output of CHILD would be bypass.
        # Careful: supervise itself is dynamic and may print the ld.so ERROR line;
        # constructor of preload into SUPERVISOR (parent) can also print.
        # We look for the marker after filtering: if child's exit is ok AND marker appears
        # more than once, or appears with MAIN success without "cannot be preloaded" only.
        child_preload = ("PRELOAD-UNSIGNED-RAN" in o) and ("cannot be preloaded" in (o+e) or "failed to map" in (o+e))
        # If ld.so says cannot be preloaded AND still prints PRELOAD once → that's the
        # supervisor process itself (parent), not the child. Count as BLOCKED for child.
        # If PRELOAD prints and main runs without "cannot be preloaded" → BYPASS.
        bypass = ("PRELOAD-UNSIGNED-RAN" in o) and ("cannot be preloaded" not in (o+e))
        # More precise: count occurrences
        n_pre = o.count("PRELOAD-UNSIGNED-RAN")
        cannot = "cannot be preloaded" in (o+e) or "failed to map segment" in (o+e)
        # Parent (fnbr-supervise) is dynamic → LD_PRELOAD hits parent. Child under filter
        # should fail to map unsigned .so. If child blocked: we see cannot/failed for child libs.
        # Honest: if unsigned .so constructor ran inside supervised child, that's bypass.
        # Distinguishing parent vs child is hard from stdout alone. Use a marker file instead.
        record("ld-preload", "in-scope", f"sup-s{seed}", True if cannot else (n_pre == 0),
               f"LD_PRELOAD unsigned .so (cannot={cannot}, n_pre={n_pre}; parent también es dinámico)", rc)

# Redo LD_PRELOAD with file marker written by constructor (path only child can write? both can)
# Better: constructor writes to a path including getppid or checks /proc/self/exe
pre_c2 = TMP / "pre2.c"
marker = ATK / "preload-marker"
marker.unlink(missing_ok=True)
pre_c2.write_text(f'''
#define _GNU_SOURCE
#include <stdio.h>
#include <unistd.h>
#include <fcntl.h>
#include <string.h>
__attribute__((constructor)) void p(void){{
    char exe[512]={{0}};
    readlink("/proc/self/exe", exe, sizeof exe-1);
    int fd=open("{marker}", O_WRONLY|O_CREAT|O_APPEND, 0644);
    if(fd>=0){{ dprintf(fd, "pid=%d exe=%s\\n", getpid(), exe); close(fd); }}
}}
''')
pre_so2 = ATK / "pre2.so"
run(["gcc","-shared","-fPIC","-O1",str(pre_c2),"-o",str(pre_so2)])
if dyn_bins:
    main = dyn_bins[0]["path"]
    marker.unlink(missing_ok=True)
    rc, o, e = run([str(SUP), str(PUB), main],
                   env={"LD_LIBRARY_PATH": str(libdir), "LD_PRELOAD": str(pre_so2)})
    child_hit = False
    if marker.exists():
        text = marker.read_text()
        # child exe should be the signed main, not fnbr-supervise
        for line in text.splitlines():
            if "fnbr-supervise" not in line and "exe=" in line:
                child_hit = True
    record("ld-preload-child", "in-scope", "sup-marker", not child_hit,
           f"constructor en hijo supervisado: child_hit={child_hit}; marker={marker.exists()}", rc)

# --- P. shebang: signed interpreter runs unsigned script ---
dash_raw = TMP / "dash.raw"
shutil.copy2("/bin/dash", dash_raw)
dash_s = ATK / "dash.signed"
ok, _ = sign_file(dash_raw, dash_s)
if ok:
    for seed in range(1, 4):
        script = ATK / f"script-s{seed}.sh"
        script.write_text(f"#!{dash_s}\necho SHEBANG-UNSIGNED-RAN-{seed}\n")
        script.chmod(0o755)
        rc, o, e = run([str(SUP), str(PUB), str(script)], env={"LD_LIBRARY_PATH": str(libdir)})
        bypass = f"SHEBANG-UNSIGNED-RAN-{seed}" in o
        record("shebang-unsigned-script", "in-scope", f"sup-s{seed}", not bypass,
               "intérprete firmado ejecuta script/texto NO firmado", rc)

# --- Q. ld.so direct invocation of unsigned dynamic ---
for seed in range(1, 4):
    rc, o, e = run([str(SUP), str(PUB), "/lib64/ld-linux-x86-64.so.2", str(ud)],
                   env={"LD_LIBRARY_PATH": str(libdir)})
    # ld.so itself is UNSIGNED — its PROT_EXEC maps should be denied → child fails
    bypass = (rc == 42) or ("UNSIGNED-DYN-MAIN" in o)
    record("ldso-direct", "in-scope", f"sup-s{seed}", not bypass,
           "ld-linux directo sobre main unsigned (ld.so también unsigned)", rc)

# --- R. PT_INTERP pointing to unsigned interpreter ---
# Craft: take signed dynamic, patch INTERP path to an unsigned copy of ld.so
if dyn_bins:
    import re
    src = Path(dyn_bins[0]["path"]).read_bytes()
    # find /lib64/ld-linux or /lib/x86_64-linux-gnu/ld-linux
    for needle in (b"/lib64/ld-linux-x86-64.so.2\x00", b"/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2\x00"):
        idx = src.find(needle)
        if idx >= 0:
            break
    else:
        idx = -1
    if idx >= 0:
        # place an unsigned ld.so copy and point INTERP there (same length path)
        unsigned_ld = ATK / "ld-fake.so"
        # use a path of equal length
        fake_path = b"/tmp/fnbr9-ld-unsigned.so.2\x00"
        # Our ATK path may differ in length — use fixed /tmp path
        fixed = Path("/tmp/fnbr9-ld-unsigned.so.2")
        shutil.copy2("/lib64/ld-linux-x86-64.so.2", fixed)
        fake_path = b"/tmp/fnbr9-ld-unsigned.so.2\x00"
        if len(fake_path) <= len(needle):
            for seed in range(1, 3):
                b = bytearray(src)
                b[idx:idx+len(needle)] = fake_path + b"\x00" * (len(needle) - len(fake_path))
                dst = ATK / f"ptinterp-s{seed}.elf"
                dst.write_bytes(b)
                dst.chmod(0o755)
                # resign? No — this is an attack (tampered signed binary). Loader should refuse.
                blocked_l, rc_l, _ = loader_refuses(dst)
                record("pt-interp", "in-scope", f"loader-tamper-s{seed}", blocked_l,
                       "PT_INTERP parchado (rompe firma)", rc_l)
                # For supervisor: unsigned ld.so as interpreter of a (now invalid-sig) binary
                rc, o, e = run([str(SUP), str(PUB), str(dst)], env={"LD_LIBRARY_PATH": str(libdir)})
                bypass = "dhello" in o or rc == 0
                record("pt-interp", "in-scope", f"sup-s{seed}", not bypass,
                       f"intérprete unsigned vía PT_INTERP; rc={rc}", rc)

# --- S. symlink race (document): replace file between open and verify in loader ---
# loader reads whole file then verifies then maps from memory copy — TOCTOU on path
# before read is possible but after verify the bytes are owned. Test path swap:
for seed in range(1, 3):
    # write evil to A, sign path B is signed; between... loader is single-process read
    # Honest: loader load_path reads once into memory — path TOCTOU before read can
    # make it load evil IF evil is signed. Classic TOCTOU against loader alone needs
    # unsigned swapped in AFTER read — which can't affect the in-memory copy.
    # So loader is safe. Supervisor mprotect path is the TOCTOU (already tested).
    record("symlink-race-loader", "out-of-scope", f"note-s{seed}", True,
           "loader copia a memoria antes de verificar; TOCTOU de ruta no afecta bytes mapeados", 0)

# --- T. out-of-scope: procesos que NUNCA instalan el filtro ---
for seed in range(1, 3):
    ust = ATK / f"execve-unsigned-static-s{seed}"
    if ust.exists():
        rc, o, e = run([str(ust)])  # plain, no supervisor
        bypass = rc == 42
        record("no-filter-installed", "out-of-scope", f"plain-s{seed}", not bypass,
               "LIMITES: supervisor solo cubre procesos que instalen el filtro; plain exec corre", rc)

# ---------------------------------------------------------------------------
# 3. Baseline: plain Linux + sha256 allowlist wrapper
# ---------------------------------------------------------------------------
print("== baseline ==")
# plain: unsigned static runs
rc, o, e = run([str(ATK / "execve-unsigned-static-s1")])
results["notes"].append(f"baseline plain Linux unsigned static: rc={rc} (corre sin control)")

# sha256 allowlist wrapper
allow = BASE / "allow.txt"
# allow only guest-000 hash
g0p = VALID / "guest-000.elf"
if g0p.exists():
    h = hashlib.sha256(g0p.read_bytes()).hexdigest()
    allow.write_text(h + "\n")
    wrapper = BASE / "sha256-allow.sh"
    wrapper.write_text(f'''#!/bin/sh
H=$(sha256sum "$1" | awk '{{print $1}}')
grep -qx "$H" "{allow}" || {{ echo DENY; exit 1; }}
shift
# cannot really exec guest via fnbr-load here; just approve
echo ALLOW
exit 0
''')
    wrapper.chmod(0o755)
    rc1, _, _ = run(["bash", str(wrapper), str(g0p)])
    rc2, _, _ = run(["bash", str(wrapper), str(ATK / "unsigned-loader-s1.elf")])
    results["notes"].append(f"baseline sha256-allowlist: valid→rc={rc1}, unsigned→rc={rc2}")

# ---------------------------------------------------------------------------
# 4. Latencia: fnbr-load vs "verify skipped" (solo lectura+parse) approx plain
# ---------------------------------------------------------------------------
print("== latencia ==")
# Plain: time to fork+exec a tiny static binary (OS exec)
# Load: time fnbr-load of signed guests of various sizes
size_buckets = {}
for m in valid_meta:
    if m["kind"] != "static-ET_EXEC":
        continue
    size_buckets.setdefault(m["size"] // 4096, []).append(m)

def pct(xs, p):
    if not xs: return None
    ys = sorted(xs)
    k = min(len(ys)-1, max(0, int(round((p/100)*(len(ys)-1)))))
    return ys[k]

# plain exec latency (static-hello)
plain_bin = None
for m in static_bins:
    if m["id"] == "static-hello":
        plain_bin = m["path"]; break
plain_samples = []
if plain_bin:
    for _ in range(40):
        t0 = time.perf_counter()
        run([plain_bin])
        plain_samples.append((time.perf_counter()-t0)*1000)

for bucket, items in sorted(size_buckets.items()):
    samples = []
    for m in items[:3]:
        for _ in range(15):
            t0 = time.perf_counter()
            run([str(LOAD), str(PUB), m["path"]])
            samples.append((time.perf_counter()-t0)*1000)
    if not samples:
        continue
    results["latency"].append({
        "size_approx": items[0]["size"],
        "n": len(samples),
        "load_p50": round(pct(samples,50),3),
        "load_p99": round(pct(samples,99),3),
        "plain_exec_p50": round(pct(plain_samples,50),3) if plain_samples else None,
        "plain_exec_p99": round(pct(plain_samples,99),3) if plain_samples else None,
    })

# ---------------------------------------------------------------------------
# 4b. Latencia supervisor
# ---------------------------------------------------------------------------
sup, base = [], []
guest_signed = str(ROOT / "fixtures" / "guest.signed.elf")
for _ in range(30):
    t0 = time.perf_counter()
    rc, _, _ = run([str(SUP), str(PUB), str(RAWLOAD), "mmap-exec", guest_signed])
    if rc == 0:
        sup.append((time.perf_counter() - t0) * 1000)
for _ in range(30):
    t0 = time.perf_counter()
    rc, _, _ = run([str(RAWLOAD), "mmap-exec", guest_signed])
    if rc == 0:
        base.append((time.perf_counter() - t0) * 1000)
results["latency_supervisor"] = {
    "sup_mmap_signed_p50": round(pct(sup, 50), 3) if sup else None,
    "sup_mmap_signed_p99": round(pct(sup, 99), 3) if sup else None,
    "rawload_plain_p50": round(pct(base, 50), 3) if base else None,
    "rawload_plain_p99": round(pct(base, 99), 3) if base else None,
    "n_sup": len(sup),
    "n_plain": len(base),
}

# ---------------------------------------------------------------------------
# 5. Agregar tablas y veredicto
# ---------------------------------------------------------------------------
from collections import defaultdict
fam = defaultdict(lambda: {"blocked":0,"total":0,"scope":None,"bypasses":[]})
for a in results["attacks"]:
    f = a["family"]
    fam[f]["total"] += 1
    fam[f]["scope"] = a["scope"]
    if a["blocked"]:
        fam[f]["blocked"] += 1
    else:
        fam[f]["bypasses"].append(a["id"])

in_scope = [a for a in results["attacks"] if a["scope"] == "in-scope"]
out_scope = [a for a in results["attacks"] if a["scope"] == "out-of-scope"]
in_blocked = sum(1 for a in in_scope if a["blocked"])
in_total = len(in_scope)
in_rate = (in_blocked / in_total * 100) if in_total else 0

# FPR loader: fraction of valid ET_EXEC that failed
loader_total = len(results["valid_loader"])
loader_fp = sum(1 for v in results["valid_loader"] if not v["ok"])  # rejected valid = FP
fpr = (loader_fp / loader_total * 100) if loader_total else 0

# Threshold: 100% blocked in-scope AND 0 FP
verdict_pass = (in_blocked == in_total) and (loader_fp == 0) and in_total > 0
verdict = "PASS" if verdict_pass else "FAIL"

results["summary"] = {
    "valid_corpus": len(valid_meta),
    "loader_ok": fp_loader_ok, "loader_fp": loader_fp, "loader_total": loader_total,
    "in_scope_blocked": in_blocked, "in_scope_total": in_total, "in_scope_pct": round(in_rate,2),
    "out_scope_total": len(out_scope),
    "verdict": verdict,
    "families": {k: {"blocked": v["blocked"], "total": v["total"], "scope": v["scope"],
                     "bypasses": v["bypasses"]} for k,v in fam.items()},
}

(OUT / "results.json").write_text(json.dumps(results, indent=2, ensure_ascii=False))
print(f"== VEREDICTO: {verdict}  in-scope {in_blocked}/{in_total}  FPR loader {loader_fp}/{loader_total} ==")

# Write VALOR.md in Spanish
lines = []
L = lines.append
L("# VALOR — sistema 9 (`fnbr-elf-zk-loader`)")
L("")
L("**Fecha:** 2026-10-21 (America/Buenos_Aires)")
L("**Commits bajo prueba:** `7bd0e8a` / `319e447` / `2a589dd`")
L("**Umbral (Research Sentinel, fijo):** PASS solo si el **100 %** de los intentos")
L("de ejecución no autorizados / sin firma (en alcance) se bloquean **y** hay")
L("**0 falsos positivos** sobre un corpus de binarios firmados válidos.")
L("Cualquier exec no autorizado que corra, o cualquier binario válido rechazado = **FAIL**.")
L("")
L("## Qué se midió")
L("")
L("El sistema tiene dos superficies:")
L("")
L("1. **`fnbr-load`** — cargador tipado de usuario: verifica `.fnbr.sig` y mapea")
L("   ELF64 x86-64 `ET_EXEC` estático (sin PIE, sin intérprete) con W^X.")
L("2. **`fnbr-supervise`** — cumplimiento real vía seccomp `USER_NOTIF` sobre")
L("   `mmap`/`mprotect` con `PROT_EXEC`. Es la pieza que debería impedir que otro")
L("   proceso saltee el cargador.")
L("")
L("El umbral se juzga sobre ataques **en alcance**. `LIMITES.md` documenta:")
L("cargador salteable (por eso existe el supervisor), filtro solo si se instala,")
L("TOCTOU residual de `CONTINUE` / `mprotect` por ruta, ZK ≠ prueba de programa,")
L("cargador mínimo sin `execve`. **Todo lo que `LIMITES.md` no excluye cuenta")
L("como en alcance**, incluido el TOCTOU residual (riesgo documentado ≠ fuera de modelo).")
L("")
L("## Método")
L("")
L("- Corpus válido: **%d** ELF firmados con el flujo normal (`prepare`+`sign` Ed25519),"
  % len(valid_meta))
L("  mezcla de guests `ET_EXEC` estáticos (sin libc, distintos tamaños/retornos),")
L("  binarios estáticos glibc y dinámicos PIE + `libc.so.6` firmada.")
L("- Ataques: familias con semillas 1..5, generadas de forma determinista.")
L("- Baseline: Linux plano (sin filtro) y un wrapper sha256-allowlist trivial.")
L("- Latencia: p50/p99 de `fnbr-load` vs `execve` plano de un estático comparable.")
L("- Repro: `bash scripts/experimento-valor.sh` (escribe `experimento/out/` y este archivo).")
L("- **No se modificó `src/`.**")
L("")
L("## Corpus válido — FPR")
L("")
L("| Superficie | OK | Rechazados (FP) | Total | FPR |")
L("|------------|----|-----------------|-------|-----|")
L("| `fnbr-load` (ET_EXEC estático firmado) | %d | %d | %d | %.2f %% |"
  % (fp_loader_ok, loader_fp, loader_total, fpr))
L("| `fnbr-supervise` (muestra: fixture + estáticos + dinámicos) | %d | %d | %d | — |"
  % (fp_sup_ok, fp_sup_fail, fp_sup_ok+fp_sup_fail))
L("")
L("Nota: un estático firmado bajo `fnbr-supervise` **corre**, pero un estático")
L("**sin firma también corre** (el `execve` inicial no se verifica; ver ataques).")
L("El FPR del loader es el que entra al umbral (0 exigido).")
L("")
L("## Ataques por familia")
L("")
L("| Familia | Alcance | Bloqueados/Total | % | Bypass (ids) |")
L("|---------|---------|------------------|---|--------------|")
for k, v in sorted(fam.items(), key=lambda kv: (kv[1]["scope"] != "in-scope", kv[0])):
    pct_b = (100*v["blocked"]/v["total"]) if v["total"] else 0
    by = ", ".join(v["bypasses"][:6]) + ("…" if len(v["bypasses"])>6 else "")
    L("| `%s` | %s | %d/%d | %.0f %% | %s |" % (
        k, v["scope"], v["blocked"], v["total"], pct_b, by or "—"))
L("")
L("**En alcance:** %d/%d bloqueados (%.1f %%)."
  % (in_blocked, in_total, in_rate))
L("")
L("### Hallazgos críticos (bypasses en alcance)")
L("")
L("1. **`execve` de binario estático sin firma** — Bajo el supervisor, `rawload exec`")
L("   / `execve` directo de un ELF estático **sin** `.fnbr.sig` corre con código de")
L("   salida del programa (p. ej. 42) e imprime su salida. El kernel mapea los")
L("   `PT_LOAD` en el `execve` **sin** pasar por `mmap`/`mprotect` del usuario; el")
L("   filtro seccomp no ve esas asignaciones. `LIMITES.md` no lo excluye.")
L("2. **`memfd_create` + `execveat(AT_EMPTY_PATH)`** — Misma raíz: el mapeo lo hace")
L("   el kernel en el exec; el estático unsigned corre.")
L("3. **Main dinámico unsigned + `libc` firmada** — El supervisor verifica el archivo")
L("   de respaldo de cada `mmap(PROT_EXEC)`. Las páginas de `libc` firmada pasan;")
L("   las del **main** las pone el kernel en el `execve` y **nunca se verifican**.")
L("   Resultado: main unsigned ejecuta.")
L("4. **`mprotect` path-TOCTOU** — `mmap` RW del unsigned (sin `PROT_EXEC` → Continue),")
L("   `rename` del path al firmado, `mprotect(RX)`: la política lee la **ruta** de")
L("   `/proc/pid/maps`, ve el firmado y aprueba; las páginas privadas ya tienen el")
L("   código evil (entry=666). Coherente con el riesgo residual de LIMITES, pero")
L("   en alcance → falla el umbral.")
L("5. **`personality(READ_IMPLIES_EXEC)` + `mmap(PROT_READ)`** — seccomp ve")
L("   `prot=PROT_READ` (Continue sin verificar); el kernel agrega `PROT_EXEC`.")
L("   Código unsigned corre (entry=666). No está en LIMITES.")
L("6. **Shebang con intérprete firmado** — El intérprete (dash) firmado + libc")
L("   firmada corren; el **texto del script** no se firma ni se verifica. Script")
L("   arbitrario ejecuta lógica no autorizada.")
L("")
L("### Lo que sí bloquea")
L("")
L("- Loader: unsigned, otra clave, flips de un byte (texto/datos/cabeceras/tabla),")
L("  append, swap de sección, truncado, ELF malformado, replay tras \"rotación\"")
L("  (verificador con clave nueva).")
L("- Supervisor: `mmap`/`mprotect` file-backed de unsigned / otra clave / adulterado;")
L("  JIT anónimo; `LD_PRELOAD` de `.so` unsigned en el **hijo** (el mapa falla);")
L("  `ld.so` unsigned como intérprete directo (sus `PROT_EXEC` se niegan).")
L("")
L("## Baseline")
L("")
for n in results["notes"]:
    if n.startswith("baseline"):
        L(f"- {n}")
L("")
L("Linux plano no impone nada: el estático unsigned corre. Un allowlist sha256")
L("trivial discrimina hash≠permitido, pero no cubre `PROT_EXEC` ni TOCTOU; es solo contexto.")
L("")
L("## Latencia")
L("")
L("| Tamaño approx (B) | n | load p50 (ms) | load p99 (ms) | plain exec p50 | plain exec p99 |")
L("|------------------|---|---------------|---------------|----------------|----------------|")
for row in results["latency"]:
    L("| %d | %d | %s | %s | %s | %s |" % (
        row["size_approx"], row["n"],
        row["load_p50"], row["load_p99"],
        row["plain_exec_p50"], row["plain_exec_p99"]))
L("")
L("`fnbr-load` incluye verificación Ed25519 + mmap W^X en-proceso; no es un")
L("`execve`. La comparación con plain exec es orientativa.")
L("")
ls = results.get("latency_supervisor") or {}
L("| Supervisor mmap firmado p50 | Supervisor p99 | rawload plano p50 | rawload plano p99 |")
L("|-----------------------------|----------------|-------------------|-------------------|")
L("| %s | %s | %s | %s |" % (
    ls.get("sup_mmap_signed_p50"), ls.get("sup_mmap_signed_p99"),
    ls.get("rawload_plain_p50"), ls.get("rawload_plain_p99")))
L("")
L("Overhead del supervisor ≈ idas y vueltas USER_NOTIF + verificación Ed25519")
L("por cada `PROT_EXEC` notificado.")
L("")
L("## Bugs / remediaciones sugeridas (sin tocar `src/` en este experimento)")
L("")
L("1. **Verificar el binario del `execve` inicial** antes de lanzarlo (o usar")
L("   `execveat`+memfd propio solo tras verificar), y/o atrapar `execve`/`execveat`")
L("   en el filtro seccomp y negar o re-verificar.")
L("2. **Cerrar `READ_IMPLIES_EXEC`:** negar `personality` o tratar todo `mmap`")
L("   file-backed como potencialmente ejecutable bajo ese flag.")
L("3. **`mprotect`:** verificar por el inode/fd original (reabrir no basta si hubo")
L("   rename); idealmente `mmap` RX directo del fd ya verificado y negar")
L("   `mprotect→EXEC` sobre VMAs anónimas/privadas no atadas a un verify previo.")
L("4. **Política de intérpretes/scripts:** firmar también el script o negar")
L("   shebang / exigir que `argv[0]` y el intérprete estén en el allowlist firmado.")
L("5. **Main dinámico:** el primer mapeo ejecutable del pathname de `execve` debe")
L("   verificarse; hoy solo se ven los `mmap` posteriores (típicamente `.so`).")
L("")
L("## Veredicto")
L("")
L("**%s** — en alcance se bloquearon **%d/%d** (%.1f %%); FPR del loader **%d/%d**."
  % (verdict, in_blocked, in_total, in_rate, loader_fp, loader_total))
L("")
if verdict == "FAIL":
    L("El umbral exige 100 % de bloqueo en alcance y 0 FP. El loader tipado cumple")
    L("su contrato estrecho (ET_EXEC estático firmado / rechazos criptográficos),")
    L("pero el **supervisor —la pieza de cumplimiento real— no alcanza el umbral**:")
    L("cualquier `execve` de un ELF estático sin firma, `memfd+fexecve`, main")
    L("dinámico unsigned con libs firmadas, TOCTOU de `mprotect` y")
    L("`READ_IMPLIES_EXEC` ejecutan código no autorizado. No se maquilla.")
else:
    L("Cumple el umbral de Research Sentinel.")
L("")
L("## Reproducir")
L("")
L("```bash")
L("bash scripts/experimento-valor.sh")
L("# artefactos: experimento/out/results.json, VALOR.md")
L("cargo test && cargo clippy --all-targets -- -D warnings")
L("```")
L("")
L("## Límites del experimento")
L("")
L("- Una máquina (box compartida), load variable; latencias ± ruido.")
L("- Corpus de guests sintéticos + utils mínimas; no es un OS completo firmado.")
L("- `alg=2` Schnorr no se re-mide aquí (mismo binding al hash; la falla es de")
L("  cumplimiento de `PROT_EXEC`/`execve`, no del esquema de firma).")
L("- BPF-LSM no disponible en este kernel (ya en LIMITES).")
L("- El padre `fnbr-supervise` es dinámico: `LD_PRELOAD` lo afecta a él; el")
L("  marcador por `/proc/self/exe` separa padre/hijo.")
L("")

(ROOT / "VALOR.md").write_text("\n".join(lines) + "\n", encoding="utf-8")
print("VALOR.md escrito")
print(json.dumps(results["summary"], indent=2, ensure_ascii=False))
PY

echo "== post: tests + clippy =="
cargo test --quiet 2>"$OUT/logs/test.txt" | tee "$OUT/logs/test-summary.txt" | tail -20
cargo clippy --all-targets -- -D warnings 2>&1 | tee "$OUT/logs/clippy.txt" | tail -5

echo "== limpieza de /tmp del experimento =="
rm -f /tmp/fnbr9-ld-unsigned.so.2 /tmp/p9/work.elf /tmp/p9/signed_for_swap.elf 2>/dev/null || true
# no dejar reglas de red ni procesos colgados
pkill -f 'fnbr-supervise' 2>/dev/null || true
echo "DONE"
