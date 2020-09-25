#!/usr/bin/python


from bcc import BPF
from time import sleep

# define BPF program
bpf_text = """
#include <uapi/linux/ptrace.h>
#include <linux/mm.h>

struct key_t{
    char file[TASK_COMM_LEN];
};
struct val_t{
    u32 fpid;
    u64 count;
    char file[TASK_COMM_LEN];
};

BPF_HASH(hashbykey, struct key_t);

void kprobe__handle_mm_fault(struct pt_regs *ctx, struct vm_area_struct *vma,
		unsigned long address, unsigned int flags)
{
    u64 zero = 0;
    struct key_t key = {};
    struct dentry *dentry = vma->vm_file->f_path.dentry;
    u32 pid = bpf_get_current_pid_tgid() >> 32;

    bpf_probe_read_kernel(&key.file, sizeof(key.file), dentry->d_name.name);
    (void)hashbykey.lookup_or_try_init(&key, &zero);
    
    // increase count
    hashbykey.increment(key);

    
}
"""

# initialize BPF
b = BPF(text=bpf_text)
print("Tracing page faults... Ctrl-C to print.")
while 1:
    try:
        sleep(999999999)
    except KeyboardInterrupt:
        print("Ctrl-C")
    
    print(("%-32s %-8s") % ("FILE", "PAGE FAULT"))
    event = b["hashbykey"]

    for k, v in sorted(event.items(),key=lambda event: -event[1].value):
        print(("%-32s %-8d") % (k.file, v.value))
    exit()
