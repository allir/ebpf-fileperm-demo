package main

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang -cflags "-g -O2 -Wall" -target arm64 -no-global-types FilePerm bpf/fileperm.bpf.c -- -I./bpf -I./bpf/vmlinux -I./bpf/libbpf -D __TARGET_ARCH_x86_64
