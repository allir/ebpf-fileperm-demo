package main

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"log"
	"strings"

	_ "embed"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
)

type FilePermEvent struct {
	Pid      uint32
	Mask     uint32
	Ret      int32
	Filename [128]byte
}

func main() {
	objs := FilePermObjects{}
	if err := LoadFilePermObjects(&objs, nil); err != nil {
		log.Fatalf("loading objects: %v", err)
	}
	defer objs.Close()

	kp, err := link.Kprobe("security_file_permission", objs.SecurityFilePermissionEntry, nil)
	if err != nil {
		log.Fatalf("opening kprobe: %s", err)
	}
	defer kp.Close()

	kpExit, err := link.Kretprobe("security_file_permission", objs.SecurityFilePermissionExit, nil)
	if err != nil {
		log.Fatalf("opening kprobe: %s", err)
	}
	defer kpExit.Close()

	rd, err := ringbuf.NewReader(objs.Events)
	if err != nil {
		log.Fatalf("opening ring buffer: %s", err)
	}
	defer rd.Close()

	log.Println("Waiting for events...")

	for {
		record, err := rd.Read()
		if err != nil {
			log.Fatalf("reading from ring buffer: %s", err)
		}

		var e FilePermEvent
		if err := binary.Read(bytes.NewBuffer(record.RawSample), binary.LittleEndian, &e); err != nil {
			log.Printf("parsing event: %s", err)
			continue
		}

		// Trim null bytes from the filename
		filename := string(bytes.Trim(e.Filename[:], "\x00"))

		if e.Ret < 0 {
			fmt.Printf("ALERT: PID %d failed to access %s (mask: %s)\n", e.Pid, filename, decodeMask(e.Mask))
		} else {
			if strings.HasPrefix(filename, "passwd") || filename == "shadow" || filename == "profile" {
				fmt.Printf("ALERT: PID %d accessed %s (mask: %s)\n", e.Pid, filename, decodeMask(e.Mask))
			}
		}
	}
}

func decodeMask(mask uint32) string {
	flags := []string{}
	if mask&0x4 != 0 {
		flags = append(flags, "READ")
	}
	if mask&0x2 != 0 {
		flags = append(flags, "WRITE")
	}
	if mask&0x1 != 0 {
		flags = append(flags, "EXECUTE")
	}
	if len(flags) == 0 {
		return "UNKNOWN"
	}
	return strings.Join(flags, "|")
}
