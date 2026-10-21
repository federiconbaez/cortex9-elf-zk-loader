#!/usr/bin/env bash
# Repro mínimo de la auditoría de Research (#9). No toca src/.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"; cd "$(dirname "$0")"
T="$(mktemp -d)"; trap 'rm -rf "$T"' EXIT
cargo build --release --quiet --manifest-path "$ROOT/Cargo.toml"
S="$ROOT/target/release/fnbr-supervise"; L="$ROOT/target/release/fnbr-load"; G="$ROOT/target/release/fnbr-sign"
P="$ROOT/fixtures/keys/test_pub.hex"
for x in us pkey i386; do gcc -static -O1 "$x.c" -o "$T/$x"; done
"$G" prepare "$T/us" "$T/us.u" >/dev/null
"$G" sign "$ROOT/fixtures/keys/other_seed.hex" "$T/us.u" "$T/us.wk" >/dev/null
"$G" sign "$ROOT/fixtures/keys/test_seed.hex" "$T/us.u" "$T/us.ok" >/dev/null
python3 -c "import sys;b=bytearray(open(sys.argv[1],'rb').read());i=b.find(b'AUD-UNSIGNED-RAN');b[i+4]=88;open(sys.argv[2],'wb').write(b)" "$T/us.ok" "$T/us.flip"
chmod +x "$T"/us.wk "$T"/us.flip
for c in "us" "us.wk" "us.flip" "pkey" "i386"; do
  echo "== supervisor: $c"; set +e; "$S" "$P" "$T/$c"; echo "rc=$?"; set -e
done
echo "== loader sobre us.wk / us.flip (debe rechazar)"; "$L" "$P" "$T/us.wk" | tail -1 || true; "$L" "$P" "$T/us.flip" | tail -1 || true
