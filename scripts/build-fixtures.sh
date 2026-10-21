#!/usr/bin/env bash
# Regenera fixtures/*.elf y fixtures/rawload. Requiere gcc y binutils (objcopy).
# La clave en fixtures/keys/ es SOLO DE PRUEBA y está publicada en el repo.
set -euo pipefail
cd "$(dirname "$0")/.."
F=fixtures
gcc -O1 -static -nostdlib -no-pie -fno-pic -ffreestanding -fno-stack-protector \
    -fcf-protection=none -Wl,-e,fnbr_entry -Wl,--build-id=none \
    -Wl,-Ttext-segment=0x10000000 -Wl,-z,noexecstack \
    "$F/src/guest.c" -o "$F/guest.raw.elf"
gcc -O1 -static -Wall -Wextra -o "$F/rawload" "$F/src/rawload.c"
cargo build --quiet --bin fnbr-sign
S=target/debug/fnbr-sign
[ -f "$F/keys/test_seed.hex" ] || $S keygen "$F/keys/test_seed.hex" "$F/keys/test_pub.hex"
[ -f "$F/keys/other_seed.hex" ] || $S keygen "$F/keys/other_seed.hex" "$F/keys/other_pub.hex"
$S prepare "$F/guest.raw.elf" "$F/guest.unsigned.elf"
$S sign "$F/keys/test_seed.hex" "$F/guest.unsigned.elf" "$F/guest.signed.elf"
$S sign "$F/keys/other_seed.hex" "$F/guest.unsigned.elf" "$F/guest.signed-otherkey.elf"
rm -f "$F/guest.raw.elf"
echo "fixtures listos:"; ls -la "$F"/*.elf "$F/rawload"
