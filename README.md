# File Permission Monitor (eBPF Demo)

This is a minimal eBPF demo that traces file permission checks using a kprobe on `security_file_permission`, implemented with the Cilium eBPF library in Go.

It monitors for when files named `passwd`, `shadow` or `profile` are opened or written to.

Note: *This is a simple educational demo and does not even deal with full-paths. Real-world file monitoring would require a lot more work for full coverage*

## Features

- Hooks `security_file_permission` to monitor file accesses
- Logs **PID**, **requested permission mask**, and **filename**
- Uses **BPF CO-RE** (Compile Once, Run Everywhere)
- Built as a pure Go application with embedded BPF programs
- Supports both `amd64` and `arm64`

## Requirements

- Linux Kernel 5.8
- `bpftool` for generating `vmlinux.h` (for CO-RE)
- `clang` and `llvm` for BPF compilation
- `curl` for downloading *libbpf* headers
- Go 1.19+

## How It Works

1. **Entry Hook**: Save the file pointer and access mask.
2. **Exit Hook**: Capture the result of the permission check.
3. **Event Output**: Send details to userspace via a ring buffer.

**Note:**

- Only monitors accesses where a valid `file` struct is available.
- Permission denials occurring before file open (e.g., at path resolution) are **not captured**.

## Building

```bash
make build
```

## Running

```bash
sudo ./fileperm-demo
```

## Output Example

```bash
ALERT: PID 21491 accessed passwd (mask: READ)
```

## License

Apache 2.0
