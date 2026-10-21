.PHONY: build test clippy fixtures demo lsm clean
build:
	cargo build
test:
	cargo test
clippy:
	cargo clippy --all-targets -- -D warnings
fixtures:  ## regenera fixtures/*.elf (gcc + objcopy)
	bash scripts/build-fixtures.sh
demo: build
	bash scripts/demo.sh
lsm:  ## compila el guard BPF-LSM (no carga en la compartida: ver LIMITES.md)
	sudo -n bpftool btf dump file /sys/kernel/btf/vmlinux format c > bpf/vmlinux.h
	clang -O2 -g -Wall -target bpf -D__TARGET_ARCH_x86 -Ibpf -c bpf/lsm_exec_guard.bpf.c -o target/lsm_exec_guard.bpf.o
clean:
	cargo clean
