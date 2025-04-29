PROGRAM=fileperm-demo

OS := $(shell uname -s)
ARCH ?= $(shell uname -m)
ARCH := $(subst x86_64,amd64,$(ARCH))
ARCH := $(subst aarch64,arm64,$(ARCH))

BPFTOOL ?= $(shell which bpftool || false)

vmlinux_dir := bpf/vmlinux
vmlinux := $(vmlinux_dir)/vmlinux_$(ARCH).h

# LIBBPF Headers
LIBBPF_VERSION = 1.4.7
libbpf_dir = bpf/libbpf
libbpf_headers := $(libbpf_dir)/LICENSE.BSD-2-Clause
libbpf_headers := $(libbpf_headers) $(libbpf_dir)/bpf_core_read.h $(libbpf_dir)/bpf_endian.h
libbpf_headers := $(libbpf_headers) $(libbpf_dir)/bpf_helper_defs.h $(libbpf_dir)/bpf_helpers.h
libbpf_headers := $(libbpf_headers) $(libbpf_dir)/bpf_tracing.h

.PHONY: all clean
all: vmlinux libbpf generate build

.PHONY: build
build: $(PROGRAM)
	@echo "Build complete. Run './$(PROGRAM)' to execute."

.PHONY: generate
generate: vmlinux libbpf
	go generate ./...

.PHONY: vmlinux
vmlinux: $(vmlinux) ## Generate vmlinux header files

$(vmlinux):
ifeq ($(OS),Darwin)
	$(error "Can not build on MacOs. Run on Linux\nFor example, use Docker or Lima VM")
endif
ifeq (, $(BPFTOOL))
	$(error "No bpftool in $$PATH, make sure it is installed.")
endif
	$(BPFTOOL) btf dump file /sys/kernel/btf/vmlinux format c > $@

.PHONY: update-libbpf-headers
update-libbpf-headers: ## Update libbpf headers
	@LIBBPF_VERSION=$(LIBBPF_VERSION) scripts/update-libbpf-headers.sh

.PHONY: libbpf
libbpf: $(libbpf_headers)

$(libbpf_headers):
	@LIBBPF_VERSION=$(LIBBPF_VERSION) scripts/update-libbpf-headers.sh

$(PROGRAM): vmlinux libbpf generate
	GOOS=linux CGO_ENABLED=0 go build -o $@ ./...

.PHONY: clean
clean:
	@echo "Cleaning up..."
	rm -f $(PROGRAM)
	rm -f fileperm_*.o
	rm -f $(vmlinux)
	rm -rf bpf/libbpf 
	@echo "Clean complete."
