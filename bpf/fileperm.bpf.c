#include "vmlinux.h"
#include "bpf_helpers.h"
#include "bpf_tracing.h"
#include "bpf_core_read.h"

char LICENSE[] SEC("license") = "Dual BSD/GPL";

#define MAX_FILENAME_LEN 256

struct event {
    u32 pid;
    u32 mask;
    s32 ret;
    char filename[MAX_FILENAME_LEN];
};

struct fileinfo {
    struct file *file;
    u32 mask;
};

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 24);
} events SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, u32);
    __type(value, struct fileinfo);
} active_files SEC(".maps");


SEC("kprobe/security_file_permission")
int BPF_KPROBE(security_file_permission_entry, struct file *file, int mask)
{
	struct fileinfo fi = { 0 };

	u64 id = bpf_get_current_pid_tgid();
	u32 tid = (u32)id;

	fi.file = file;
	fi.mask = (u32)mask;

	bpf_map_update_elem(&active_files, &tid, &fi, BPF_ANY);

	return 0;
}


SEC("kretprobe/security_file_permission")
int BPF_KRETPROBE(security_file_permission_exit, int ret)
{
    struct fileinfo *fi = NULL;
    struct event *e = NULL;

    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 tid = (u32)pid_tgid;
    u32 pid = pid_tgid >> 32;

    fi = bpf_map_lookup_elem(&active_files, &tid);
    if (!fi)
        return 0;
    
    bpf_map_delete_elem(&active_files, &tid);

    e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e)
        return 0;

    struct file *file = fi->file;
    struct dentry *dentry = BPF_CORE_READ(file, f_path.dentry);
    struct qstr d_name = BPF_CORE_READ(dentry, d_name);

    e->pid = pid;
    e->mask = fi->mask;
    e->ret = ret;

    bpf_core_read_str(e->filename, sizeof(e->filename), d_name.name);

    bpf_ringbuf_submit(e, 0);

    return 0;
}
