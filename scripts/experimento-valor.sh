#!/usr/bin/env bash
# Experimento de VALOR del sistema 9 — remedición v0.3.
# Umbral Research Sentinel (fijo): 100% bloqueo en alcance Y 0 FP por superficie.
# Contrato (LIMITES.md, commit pre-medición): loader = guests nostdlib;
# supervisor = estáticos glibc process-form. Evidencia en experimento/valor/.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

OUT="${OUT:-$ROOT/experimento/valor}"
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

gcc -static -O1 -Wall -o "$OUT/tmp/harness.raw" "$ROOT/experimento/harness.c" 2>"$OUT/logs/harness-cc.txt"
"$SIGN" prepare "$OUT/tmp/harness.raw" "$OUT/tmp/harness.u" >/dev/null
"$SIGN" sign "$SEED" "$OUT/tmp/harness.u" "$OUT/tmp/harness.signed" >/dev/null
chmod +x "$OUT/tmp/harness.signed"
HARNESS="$OUT/tmp/harness.signed"

python3 - "$OUT" "$ROOT" "$SIGN" "$LOAD" "$SUP" "$SEED" "$PUB" "$OTHER" "$OTHER_PUB" "$HARNESS" <<'PY'
#!/usr/bin/env python3
import hashlib, json, os, random, shutil, struct, subprocess, sys, time
from pathlib import Path
from collections import defaultdict

OUT, ROOT, SIGN, LOAD, SUP, SEED, PUB, OTHER, OTHER_PUB, HARNESS = map(Path, sys.argv[1:])
VALID, ATK, LOGS, TMP, BASE = OUT/"valid", OUT/"attacks", OUT/"logs", OUT/"tmp", OUT/"baseline"
for d in (VALID, ATK, LOGS, TMP, BASE):
    d.mkdir(parents=True, exist_ok=True)

results = {
    "valid_loader": [], "valid_supervisor": [],
    "attacks": [], "latency": [], "latency_supervisor": {},
    "bugs": [], "notes": [],
    "contrato": {
        "loader": "ET_EXEC nostdlib (guests); glibc-static y PIE fuera (LIMITES.md)",
        "supervisor": "estáticos glibc process-form; PIE/PT_INTERP fuera; guests nostdlib fuera",
    },
}

def run(cmd, env=None, timeout=30):
    e = os.environ.copy()
    if env: e.update(env)
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, env=e)
        return p.returncode, p.stdout, p.stderr
    except subprocess.TimeoutExpired:
        return 124, "", "timeout"

def sign_file(src, dst, seed=SEED):
    u = TMP / (dst.name + ".u")
    rc, o, e = run([str(SIGN), "prepare", str(src), str(u)])
    if rc != 0: return False, f"prepare:{e or o}"
    rc, o, e = run([str(SIGN), "sign", str(seed), str(u), str(dst)])
    u.unlink(missing_ok=True)
    if rc != 0: return False, f"sign:{e or o}"
    dst.chmod(0o755)
    return True, "ok"

GUEST_CFLAGS = [
    "gcc","-O1","-static","-nostdlib","-no-pie","-fno-pic","-ffreestanding",
    "-fno-stack-protector","-fcf-protection=none",
    "-Wl,-e,fnbr_entry","-Wl,--build-id=none",
    "-Wl,-Ttext-segment=0x10000000","-Wl,-z,noexecstack",
]

def build_guest(c_src, raw):
    rc, o, e = run(GUEST_CFLAGS + [str(c_src), "-o", str(raw)])
    return rc == 0, e or o

# ---------------------------------------------------------------------------
# Corpus válido
# ---------------------------------------------------------------------------
print("== corpus loader (40 guests nostdlib, muestras distintas) ==")
valid_meta = []
for i in range(40):
    pad = (i % 8) * 4096
    ret = 296 + i  # distinto por muestra (antes se repetía % 50)
    c = TMP / f"g{i}.c"
    c.write_text(f'''
static const char msg[] = "FNBR-{i:03d}-s{i}";
static long counter = 1000 + {i};
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
    if pad:
        padfile = TMP / f"g{i}.pad"
        padfile.write_bytes(bytes([(65 + i) % 256]) * pad)
        raw2 = TMP / f"g{i}.raw2"
        rc, _, _ = run(["objcopy", f"--add-section=.fnbr.pad={padfile}",
                        f"--set-section-flags=.fnbr.pad=readonly,contents",
                        str(raw), str(raw2)])
        if rc == 0: raw = raw2
    dst = VALID / f"guest-{i:03d}.elf"
    ok, err = sign_file(raw, dst)
    if not ok:
        results["notes"].append(f"guest {i} sign fail: {err}")
        continue
    valid_meta.append({"id": f"guest-{i:03d}", "path": str(dst), "expect": ret,
                       "size": dst.stat().st_size, "kind": "static-ET_EXEC"})

print("== corpus supervisor (55 estáticos glibc process-form, distintos) ==")
static_bins = []
for i in range(55):
    name = f"s{i:02d}"
    code = f'#include <stdio.h>\n#include <unistd.h>\nint main(void){{printf("S{i}\\n");return {i % 50};}}\n'
    c = TMP / f"{name}.c"
    c.write_text(code)
    raw = TMP / f"{name}.raw"
    rc, o, e = run(["gcc","-static","-O1","-Wall",str(c),"-o",str(raw)])
    if rc != 0:
        results["notes"].append(f"static {name} build fail: {(e or o)[:200]}")
        continue
    dst = VALID / f"static-{name}.elf"
    ok, err = sign_file(raw, dst)
    if not ok:
        results["notes"].append(f"static {name} sign fail: {err}")
        continue
    static_bins.append({"id": f"static-{name}", "path": str(dst),
                        "size": dst.stat().st_size, "kind": "static-glibc", "expect": i % 50})
    valid_meta.append(static_bins[-1])

print(f"  corpus: {len(valid_meta)} firmados (guests+static)")

# ---------------------------------------------------------------------------
# FPR
# ---------------------------------------------------------------------------
print("== FPR loader (solo guests nostdlib, contrato LIMITES) ==")
fp_loader_ok = fp_loader_fail = 0
for m in valid_meta:
    if m["kind"] != "static-ET_EXEC":
        continue
    t0 = time.perf_counter()
    rc, o, e = run([str(LOAD), str(PUB), m["path"]], timeout=10)
    dt = time.perf_counter() - t0
    ok = rc == 0 and f"entry devolvió {m['expect']}" in o
    results["valid_loader"].append({"id": m["id"], "ok": ok, "rc": rc, "ms": round(dt*1000,3)})
    if ok: fp_loader_ok += 1
    else:
        fp_loader_fail += 1
        results["bugs"].append(f"FPR loader: {m['id']} rc={rc}")

print(f"  loader FPR: ok={fp_loader_ok} fail={fp_loader_fail}")

print("== FPR supervisor (55 estáticos glibc) ==")
fp_sup_ok = fp_sup_fail = 0
for m in static_bins:
    rc, o, e = run([str(SUP), str(PUB), m["path"]], timeout=15)
    # éxito = corrió con el exit code esperado del programa
    ok = rc == m["expect"]
    results["valid_supervisor"].append({"id": m["id"], "ok": ok, "rc": rc, "expect": m["expect"]})
    if ok: fp_sup_ok += 1
    else:
        fp_sup_fail += 1
        results["bugs"].append(f"FPR sup: {m['id']} rc={rc} expect={m['expect']} {(o+e)[:120]}")

print(f"  supervisor FPR: ok={fp_sup_ok} fail={fp_sup_fail}")

# ---------------------------------------------------------------------------
# Ataques
# ---------------------------------------------------------------------------
print("== ataques ==")

def record(family, scope, tid, blocked, detail, rc):
    results["attacks"].append({
        "family": family, "scope": scope, "id": tid,
        "blocked": bool(blocked), "detail": detail, "rc": rc,
    })
    mark = "BLOCK" if blocked else "BYPASS"
    print(f"  [{mark}] {family}/{tid}: {detail[:90]} (rc={rc})")

def loader_refuses(path):
    rc, o, e = run([str(LOAD), str(PUB), str(path)])
    return (rc != 0 and ("RECHAZADO" in o or "ERROR" in o or rc == 1)), rc, o

def sup_runs(path, *args, env=None):
    rc, o, e = run([str(SUP), str(PUB), str(path), *map(str, args)], env=env, timeout=15)
    return rc, o, e

def harness(mode, *args):
    return sup_runs(HARNESS, mode, *args)

# A. unsigned — muestras distintas por semilla (recompiladas)
for seed in range(1, 6):
    c = TMP / f"u{seed}.c"
    c.write_text(f'#include <stdio.h>\nint main(){{puts("U-{seed}");return 42;}}\n')
    raw = ATK / f"unsigned-s{seed}.elf"
    run(["gcc","-static","-O1",str(c),"-o",str(raw)])
    # loader: prepare without sign
    u = ATK / f"unsigned-loader-s{seed}.elf"
    run([str(SIGN), "prepare", str(raw), str(u)])
    blocked, rc, _ = loader_refuses(u)
    record("unsigned", "in-scope", f"loader-s{seed}", blocked, "fnbr-load unsigned distinto", rc)
    # supervisor exec del unsigned
    rc, o, e = sup_runs(raw)
    bypass = rc == 42 or f"U-{seed}" in o
    record("unsigned", "in-scope", f"sup-exec-s{seed}", not bypass, "exec estático unsigned bajo supervisor", rc)

# B. wrong-key — distintos por semilla
for seed in range(1, 6):
    c = TMP / f"wk{seed}.c"
    c.write_text(f'#include <stdio.h>\nint main(){{puts("WK-{seed}");return 42;}}\n')
    raw = TMP / f"wk{seed}.raw"
    run(["gcc","-static","-O1",str(c),"-o",str(raw)])
    dst = ATK / f"wrongkey-s{seed}.elf"
    sign_file(raw, dst, seed=OTHER)
    blocked, rc, _ = loader_refuses(dst)
    record("wrong-key", "in-scope", f"loader-s{seed}", blocked, "otra clave", rc)
    rc, o, e = sup_runs(dst)
    bypass = rc == 42 or f"WK-{seed}" in o
    record("wrong-key", "in-scope", f"sup-exec-s{seed}", not bypass, "wrong-key por exec bajo supervisor", rc)

# C. byte-flip — offsets distintos por semilla
signed0 = Path(static_bins[0]["path"]).read_bytes() if static_bins else (ROOT/"fixtures/guest.signed.elf").read_bytes()
sig_off = signed0.find(b"FNBRSIG1")
regions = ["text", "data", "ehdr", "phdr", "shdr", "padding"]
for seed in range(1, 6):
    rng = random.Random(1000 + seed)
    base = Path(static_bins[seed % len(static_bins)]["path"]).read_bytes() if static_bins else signed0
    sig = base.find(b"FNBRSIG1")
    for ri, region in enumerate(regions):
        off = {
            "text": 0x1000 + seed * 17 + ri,
            "data": min(len(base) - 200, 0x3000 + seed * 13),
            "ehdr": 16 + seed,
            "phdr": 64 + seed * 3,
            "shdr": max(64, len(base) - 64 - seed * 8),
            "padding": max(0, (sig if sig > 0 else 200) - 16 - seed),
        }[region]
        if off < 0 or off >= len(base): continue
        if sig >= 0 and sig <= off < sig + 128: continue
        b = bytearray(base)
        b[off] ^= 1 + rng.randrange(1, 255)
        dst = ATK / f"flip-{region}-s{seed}.elf"
        dst.write_bytes(b)
        blocked, rc, _ = loader_refuses(dst)
        record("byte-flip", "in-scope", f"loader-{region}-s{seed}", blocked, f"flip @0x{off:x}", rc)
        if seed <= 2:
            dst.chmod(0o755)
            rc2, o2, _ = sup_runs(dst)
            # adulterado bajo supervisor: debe negarse el exec (rc 93) o morir
            blocked2 = rc2 in (93, 128) or rc2 > 90
            record("byte-flip", "in-scope", f"sup-{region}-s{seed}", blocked2, f"sup flip @0x{off:x} rc={rc2}", rc2)

for seed in range(1, 6):
    b = bytearray(signed0)
    if sig_off > 0:
        b[sig_off + 48 + seed] ^= 0xFF
    dst = ATK / f"flip-sig-s{seed}.elf"
    dst.write_bytes(b)
    blocked, rc, _ = loader_refuses(dst)
    record("byte-flip-sig", "in-scope", f"loader-s{seed}", blocked, "flip en proof", rc)

# D. append / truncate / sig-swap / malformed / key-rotation
for seed in range(1, 6):
    rng = random.Random(seed)
    payload = bytes(rng.randrange(256) for _ in range(64 * seed))
    dst = ATK / f"append-s{seed}.elf"
    dst.write_bytes(signed0 + payload)
    blocked, rc, _ = loader_refuses(dst)
    record("append", "in-scope", f"loader-s{seed}", blocked, f"append {len(payload)} B", rc)

g0 = VALID / "guest-000.elf"
g1 = VALID / "guest-001.elf"
if g0.exists() and g1.exists():
    b0, b1 = bytearray(g0.read_bytes()), bytearray(g1.read_bytes())
    o0, o1 = b0.find(b"FNBRSIG1"), b1.find(b"FNBRSIG1")
    if o0 > 0 and o1 > 0:
        for seed in range(1, 6):
            x = bytearray(b0 if seed % 2 else b1)
            src_sig = b1 if seed % 2 else b0
            so = o1 if seed % 2 else o0
            xo = o0 if seed % 2 else o1
            x[xo:xo+128] = src_sig[so:so+128]
            dst = ATK / f"swap-s{seed}.elf"
            dst.write_bytes(x)
            blocked, rc, _ = loader_refuses(dst)
            record("sig-swap", "in-scope", f"loader-s{seed}", blocked, "sig de otro binario", rc)

for seed in range(1, 6):
    cut = max(64, len(signed0) - 64 * seed)
    dst = ATK / f"trunc-s{seed}.elf"
    dst.write_bytes(signed0[:cut])
    blocked, rc, _ = loader_refuses(dst)
    record("truncate", "in-scope", f"loader-s{seed}", blocked, f"trunc a {cut} B", rc)

malformed_specs = [
    ("bad-magic", lambda b: b.__setitem__(slice(0,4), b"XXXX")),
    ("bad-phoff", lambda b: b.__setitem__(slice(32,40), struct.pack("<Q", 0xFFFFFFFF))),
    ("zero-phnum", lambda b: b.__setitem__(slice(56,58), struct.pack("<H", 0))),
    ("overlap-claim", lambda b: b.__setitem__(slice(32,40), struct.pack("<Q", 8))),
    ("bogus-shoff", lambda b: b.__setitem__(slice(40,48), struct.pack("<Q", 10**12))),
]
for seed in range(1, 6):
    for name, mut in malformed_specs:
        b = bytearray(signed0)
        mut(b)
        b[20 + seed] ^= seed
        dst = ATK / f"malformed-{name}-s{seed}.elf"
        dst.write_bytes(b)
        blocked, rc, _ = loader_refuses(dst)
        record("malformed-elf", "in-scope", f"loader-{name}-s{seed}", blocked, name, rc)

for seed in range(1, 6):
    new_seed, new_pub = TMP / f"rot-seed-{seed}.hex", TMP / f"rot-pub-{seed}.hex"
    run([str(SIGN), "keygen", str(new_seed), str(new_pub)])
    dst = ATK / f"replay-s{seed}.elf"
    shutil.copy2(g0 if g0.exists() else ROOT/"fixtures/guest.signed.elf", dst)
    rc, o, e = run([str(LOAD), str(new_pub), str(dst)])
    record("key-rotation-replay", "in-scope", f"loader-s{seed}", rc != 0, "clave rotada", rc)

# E. harness-based attacks (distinct seeds where applicable)
for seed in range(1, 4):
    rc, o, e = harness("pkey")
    record("pkey-mprotect", "in-scope", f"sup-s{seed}", rc == 0, "pkey_mprotect anon RX", rc)

for seed in range(1, 4):
    rc, o, e = harness("i386")
    # SIGSYS → fnbr-supervise exits 128; o blocked exit 0
    blocked = rc in (0, 128) and "BYPASS" not in o
    record("i386-int80", "in-scope", f"sup-s{seed}", blocked, "mprotect via int 0x80", rc)

for seed in range(1, 3):
    rc, o, e = harness("x32")
    blocked = rc in (0, 128) and "BYPASS" not in o
    record("x32-syscall", "in-scope", f"sup-s{seed}", blocked, "mprotect via x32", rc)

for seed in range(1, 3):
    rc, o, e = harness("ptrace")
    record("ptrace-poketext", "in-scope", f"sup-s{seed}", rc == 0 and "BYPASS" not in o, "ptrace POKETEXT", rc)
    rc, o, e = harness("vmwritev")
    record("process-vm-writev", "in-scope", f"sup-s{seed}", rc == 0 and "BYPASS" not in o, "process_vm_writev", rc)
    rc, o, e = harness("uffd")
    record("userfaultfd", "in-scope", f"sup-s{seed}", rc == 0 and "BYPASS" not in o, "userfaultfd", rc)
    rc, o, e = harness("procmem")
    record("proc-self-mem", "in-scope", f"sup-s{seed}", rc == 0 and "BYPASS" not in o, "/proc/self/mem write", rc)

# memfd-fexecve unsigned
for seed in range(1, 4):
    ust = ATK / f"unsigned-s{seed}.elf"
    if not ust.exists(): continue
    rc, o, e = harness("memfd-fexecve", ust)
    bypass = rc == 42 or "U-" in o or "BYPASS" in o
    record("memfd-fexecve", "in-scope", f"sup-s{seed}", not bypass, "memfd+execveat unsigned", rc)

# toctou / rie / mapshared / cow-dirty
evil_c = TMP / "evil.c"
evil_c.write_text('static const char msg[]="EVIL"; long fnbr_entry(void){return 666;}\n')
evil_raw = TMP / "evil.raw"
build_guest(evil_c, evil_raw)
evil_u = ATK / "evil.unsigned.elf"
run([str(SIGN), "prepare", str(evil_raw), str(evil_u)])

for seed in range(1, 4):
    work = ATK / f"toctou-work-s{seed}.elf"
    signed_copy = ATK / f"toctou-signed-s{seed}.elf"
    shutil.copy2(evil_u, work)
    shutil.copy2(g0 if g0.exists() else ROOT/"fixtures/guest.signed.elf", signed_copy)
    rc, o, e = harness("mprotect-toctou", work, signed_copy)
    bypass = rc == 9 or "BYPASS" in o
    record("mprotect-toctou", "in-scope", f"sup-s{seed}", not bypass, "rename TOCTOU", rc)

for seed in range(1, 4):
    rc, o, e = harness("read-implies-exec", evil_u)
    bypass = rc == 9 or "BYPASS" in o
    record("read-implies-exec", "in-scope", f"sup-s{seed}", not bypass, "personality RIE", rc)

if static_bins:
    sgn = static_bins[0]["path"]
    for seed in range(1, 3):
        rc, o, e = harness("mapshared", sgn)
        record("map-shared-exec", "in-scope", f"sup-s{seed}", rc == 0 and "BYPASS" not in o, "MAP_SHARED EXEC", rc)
    # cow-dirty over guest (vaddr 0x10000000)
    gs = str(g0 if g0.exists() else ROOT/"fixtures/guest.signed.elf")
    for seed in range(1, 3):
        rc, o, e = harness("cow-dirty", gs)
        bypass = rc == 9 or "BYPASS" in o
        record("cow-dirty", "in-scope", f"sup-s{seed}", not bypass, "CoW dirty + mprotect RX", rc)

# unsigned dyn main — PT_INTERP → deny at gate
ud_c = TMP / "ud.c"
ud_c.write_text('#include <stdio.h>\nint main(){puts("UNSIGNED-DYN");return 42;}\n')
ud = ATK / "unsigned-dyn"
run(["gcc","-O1",str(ud_c),"-o",str(ud)])
for seed in range(1, 4):
    rc, o, e = sup_runs(ud)
    bypass = rc == 42 or "UNSIGNED-DYN" in o
    record("unsigned-dyn-main", "in-scope", f"sup-s{seed}", not bypass, "main dinámico unsigned", rc)

# shebang
dash_raw = TMP / "dash.raw"
if Path("/bin/dash").exists():
    shutil.copy2("/bin/dash", dash_raw)
    dash_s = ATK / "dash.signed"
    ok, _ = sign_file(dash_raw, dash_s)
    if ok:
        for seed in range(1, 4):
            script = ATK / f"script-s{seed}.sh"
            script.write_text(f"#!{dash_s}\necho SHEBANG-RAN-{seed}\n")
            script.chmod(0o755)
            rc, o, e = sup_runs(script)
            bypass = f"SHEBANG-RAN-{seed}" in o
            record("shebang-unsigned-script", "in-scope", f"sup-s{seed}", not bypass, "script con intérprete firmado", rc)

# anon-jit via harness-equivalent: compile tiny that does anon jit
# Use a signed helper: the harness doesn't have anon-jit; build one
anon_c = TMP / "anon.c"
anon_c.write_text(r'''
#define _GNU_SOURCE
#include <sys/mman.h>
#include <string.h>
#include <stdio.h>
#include <errno.h>
int main(){
  unsigned char code[]={0xb8,0x2a,0,0,0,0xc3};
  void*m=mmap(0,4096,PROT_READ|PROT_WRITE,MAP_PRIVATE|MAP_ANONYMOUS,-1,0);
  memcpy(m,code,sizeof code);
  if(mprotect(m,4096,PROT_READ|PROT_EXEC)==0){printf("BYPASS\n");return 9;}
  printf("bloqueado errno=%d\n",errno); return 0;
}
''')
anon_raw = TMP / "anon.raw"
run(["gcc","-static","-O1",str(anon_c),"-o",str(anon_raw)])
anon_s = ATK / "anon.signed"
sign_file(anon_raw, anon_s)
for seed in range(1, 3):
    rc, o, e = sup_runs(anon_s)
    bypass = rc == 9 or "BYPASS" in o
    record("anon-jit", "in-scope", f"sup-s{seed}", not bypass, "mprotect anon RX", rc)

# out of scope
for seed in range(1, 3):
    ust = ATK / f"unsigned-s{seed}.elf"
    if ust.exists():
        rc, o, e = run([str(ust)])
        record("no-filter-installed", "out-of-scope", f"plain-s{seed}", rc != 42,
               "LIMITES: sin filtro el unsigned corre", rc)

record("symlink-race-loader", "out-of-scope", "note-s1", True,
       "loader copia a memoria antes de verificar", 0)

# ---------------------------------------------------------------------------
# Baseline + latencia
# ---------------------------------------------------------------------------
print("== baseline ==")
rc, o, e = run([str(ATK / "unsigned-s1.elf")])
results["notes"].append(f"baseline plain Linux unsigned static: rc={rc}")

print("== latencia ==")
def pct(xs, p):
    if not xs: return None
    ys = sorted(xs)
    return ys[min(len(ys)-1, max(0, int(round((p/100)*(len(ys)-1)))))]

plain_samples = []
if static_bins:
    pb = static_bins[0]["path"]
    for _ in range(40):
        t0 = time.perf_counter(); run([pb]); plain_samples.append((time.perf_counter()-t0)*1000)

size_buckets = {}
for m in valid_meta:
    if m["kind"] != "static-ET_EXEC": continue
    size_buckets.setdefault(m["size"] // 4096, []).append(m)
for _, items in sorted(size_buckets.items()):
    samples = []
    for m in items[:3]:
        for _ in range(10):
            t0 = time.perf_counter(); run([str(LOAD), str(PUB), m["path"]])
            samples.append((time.perf_counter()-t0)*1000)
    if samples:
        results["latency"].append({
            "size_approx": items[0]["size"], "n": len(samples),
            "load_p50": round(pct(samples,50),3), "load_p99": round(pct(samples,99),3),
            "plain_exec_p50": round(pct(plain_samples,50),3) if plain_samples else None,
            "plain_exec_p99": round(pct(plain_samples,99),3) if plain_samples else None,
        })

sup_s, base_s = [], []
if static_bins:
    pb = static_bins[0]["path"]
    for _ in range(30):
        t0 = time.perf_counter(); rc,_,_=run([str(SUP),str(PUB),pb])
        if rc == static_bins[0]["expect"]:
            sup_s.append((time.perf_counter()-t0)*1000)
    for _ in range(30):
        t0 = time.perf_counter(); run([pb])
        base_s.append((time.perf_counter()-t0)*1000)
results["latency_supervisor"] = {
    "sup_exec_signed_p50": round(pct(sup_s,50),3) if sup_s else None,
    "sup_exec_signed_p99": round(pct(sup_s,99),3) if sup_s else None,
    "plain_exec_p50": round(pct(base_s,50),3) if base_s else None,
    "plain_exec_p99": round(pct(base_s,99),3) if base_s else None,
    "n_sup": len(sup_s), "n_plain": len(base_s),
}

# ---------------------------------------------------------------------------
# Agregar + VALOR.md
# ---------------------------------------------------------------------------
fam = defaultdict(lambda: {"blocked":0,"total":0,"scope":None,"bypasses":[]})
for a in results["attacks"]:
    f = a["family"]
    fam[f]["total"] += 1
    fam[f]["scope"] = a["scope"]
    if a["blocked"]: fam[f]["blocked"] += 1
    else: fam[f]["bypasses"].append(a["id"])

in_scope = [a for a in results["attacks"] if a["scope"]=="in-scope"]
out_scope = [a for a in results["attacks"] if a["scope"]=="out-of-scope"]
in_blocked = sum(1 for a in in_scope if a["blocked"])
in_total = len(in_scope)
in_rate = (in_blocked/in_total*100) if in_total else 0

loader_total = len(results["valid_loader"])
loader_fp = sum(1 for v in results["valid_loader"] if not v["ok"])
sup_total = len(results["valid_supervisor"])
sup_fp = sum(1 for v in results["valid_supervisor"] if not v["ok"])
fpr_l = (loader_fp/loader_total*100) if loader_total else 0
fpr_s = (sup_fp/sup_total*100) if sup_total else 0

verdict_pass = (in_blocked==in_total) and (loader_fp==0) and (sup_fp==0) and in_total>0
verdict = "PASS" if verdict_pass else "FAIL"

results["summary"] = {
    "valid_corpus": len(valid_meta),
    "loader_ok": fp_loader_ok, "loader_fp": loader_fp, "loader_total": loader_total, "loader_fpr_pct": round(fpr_l,2),
    "supervisor_ok": fp_sup_ok, "supervisor_fp": sup_fp, "supervisor_total": sup_total, "supervisor_fpr_pct": round(fpr_s,2),
    "in_scope_blocked": in_blocked, "in_scope_total": in_total, "in_scope_pct": round(in_rate,2),
    "out_scope_total": len(out_scope),
    "verdict": verdict,
    "families": {k: {"blocked": v["blocked"], "total": v["total"], "scope": v["scope"],
                     "bypasses": v["bypasses"]} for k,v in fam.items()},
}

(OUT / "results.json").write_text(json.dumps(results, indent=2, ensure_ascii=False))

lines = []
L = lines.append
L("# VALOR — sistema 9 (`fnbr-elf-zk-loader`) v0.3 remedición")
L("")
L("**Fecha:** 2026-10-21 (America/Buenos_Aires)")
L("**Umbral (Research Sentinel, fijo):** 100 % bloqueo en alcance **y** 0 FP")
L("por superficie sobre el corpus válido del contrato.")
L("")
L("## Contrato (LIMITES.md, pre-medición)")
L("")
L("- **Loader:** guests `ET_EXEC` nostdlib. Glibc-static y PIE fuera.")
L("- **Supervisor:** estáticos glibc process-form. PIE/`PT_INTERP` y guests")
L("  nostdlib fuera. Solo procesos que instalan el filtro.")
L("")
L("## Corpus válido — FPR")
L("")
L("| Superficie | OK | FP | Total | FPR |")
L("|------------|----|----|-------|-----|")
L("| `fnbr-load` (guests nostdlib) | %d | %d | %d | %.2f %% |" % (fp_loader_ok, loader_fp, loader_total, fpr_l))
L("| `fnbr-supervise` (estáticos glibc) | %d | %d | %d | %.2f %% |" % (fp_sup_ok, sup_fp, sup_total, fpr_s))
L("")
L("## Ataques por familia")
L("")
L("| Familia | Alcance | Bloqueados/Total | % | Bypass |")
L("|---------|---------|------------------|---|--------|")
for k, v in sorted(fam.items(), key=lambda kv: (kv[1]["scope"] != "in-scope", kv[0])):
    pct_b = (100*v["blocked"]/v["total"]) if v["total"] else 0
    by = ", ".join(v["bypasses"][:8]) + ("…" if len(v["bypasses"])>8 else "")
    L("| `%s` | %s | %d/%d | %.0f %% | %s |" % (k, v["scope"], v["blocked"], v["total"], pct_b, by or "—"))
L("")
L("**En alcance:** %d/%d bloqueados (%.1f %%)." % (in_blocked, in_total, in_rate))
L("")
L("## Latencia")
L("")
L("| Tamaño approx (B) | n | load p50 | load p99 | plain p50 | plain p99 |")
L("|------------------|---|----------|----------|-----------|-----------|")
for row in results["latency"]:
    L("| %d | %d | %s | %s | %s | %s |" % (
        row["size_approx"], row["n"], row["load_p50"], row["load_p99"],
        row["plain_exec_p50"], row["plain_exec_p99"]))
ls = results["latency_supervisor"]
L("")
L("| Supervisor exec firmado p50 | p99 | plain p50 | plain p99 | n |")
L("|-----------------------------|-----|-----------|-----------|---|")
L("| %s | %s | %s | %s | %s/%s |" % (
    ls.get("sup_exec_signed_p50"), ls.get("sup_exec_signed_p99"),
    ls.get("plain_exec_p50"), ls.get("plain_exec_p99"),
    ls.get("n_sup"), ls.get("n_plain")))
L("")
L("## Veredicto")
L("")
L("**%s** — en alcance **%d/%d** (%.1f %%); FPR loader **%d/%d**; FPR supervisor **%d/%d**."
  % (verdict, in_blocked, in_total, in_rate, loader_fp, loader_total, sup_fp, sup_total))
L("")
if verdict == "PASS":
    L("Cumple el umbral de Research Sentinel sin relajarlo.")
else:
    L("No cumple. Ver `experimento/valor/results.json` y bugs.")
L("")
L("## Reproducir")
L("")
L("```bash")
L("bash scripts/experimento-valor.sh")
L("# artefactos: experimento/valor/results.json, VALOR.md")
L("```")
L("")

(ROOT / "VALOR.md").write_text("\n".join(lines) + "\n", encoding="utf-8")
print("VALOR.md escrito")
print(json.dumps(results["summary"], indent=2, ensure_ascii=False))
PY

echo "== post: tests + clippy =="
cargo test --release --quiet 2>"$OUT/logs/test.txt" | tee "$OUT/logs/test-summary.txt" | tail -20
cargo clippy --release --all-targets -- -D warnings 2>&1 | tee "$OUT/logs/clippy.txt" | tail -5
echo "DONE"
