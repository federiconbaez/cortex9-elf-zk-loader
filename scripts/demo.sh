#!/usr/bin/env bash
# Demo: firmado carga y corre; sin firma, otra clave y adulterado se rechazan.
set -uo pipefail
cd "$(dirname "$0")/.."
cargo build --quiet
L=target/debug/fnbr-load; K=fixtures/keys/test_pub.hex; T=$(mktemp)
cp fixtures/guest.signed.elf "$T"; printf '\x90' | dd of="$T" bs=1 seek=$((0x1000)) conv=notrunc status=none
ok=1
run() { local name=$1 want=$2 f=$3; out=$($L $K "$f"); rc=$?; echo "[$name] rc=$rc :: $(echo "$out" | tr '\n' ' ')"; [ "$rc" = "$want" ] || ok=0; }
run firmado        0 fixtures/guest.signed.elf
run sin_firma      1 fixtures/guest.unsigned.elf
run otra_clave     1 fixtures/guest.signed-otherkey.elf
run adulterado     1 "$T"
rm -f "$T"
[ $ok = 1 ] && echo "RESULTADO: PASS" || { echo "RESULTADO: FAIL"; exit 1; }
