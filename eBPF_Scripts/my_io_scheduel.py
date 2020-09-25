#!/usr/bin/python

from bcc import BPF
from time import strftime

# define BPF program
bpf_text = """
#include <uapi/linux/ptrace.h>
#include <linux/sched.h>

struct data_t {
    char comm[TASK_COMM_LEN];
    u32 pid;
    u64 ns;
    u64 oldNs;
    u64 newNs;
};

BPF_PERF_OUTPUT(events);
BPF_HASH(entryPoint,u32, struct data_t);

void kprobe__io_schedule(struct pt_regs *ctx)
{
    struct data_t data = {};
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    data.pid = pid;
    data.oldNs = bpf_ktime_get_ns();
    bpf_get_current_comm(&data.comm, sizeof(data.comm));
    entryPoint.update(&pid, &data);
}

int kretprobe__io_schedule(struct pt_regs *ctx)
{
    struct data_t *data;
    struct data_t buffer = {};
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    data = entryPoint.lookup(&pid);
    if(data == 0)
    {
        bpf_trace_printk("bpf wrong");
        return 0;
    }
    data->newNs = bpf_ktime_get_ns();
    data->ns = data->newNs - data->oldNs;
    bpf_probe_read_kernel(&buffer, sizeof(buffer), data);
    events.perf_submit(ctx, &buffer, sizeof(buffer));
    return 0;
}
"""

# process event
def print_event(cpu, data, size):
    event = b["events"].event(data)
    print("%-16s %6d %16d" % (event.comm.decode('utf-8', 'replace'), event.pid,
        event.ns))

# initialize BPF
b = BPF(text=bpf_text)
print("%-16s %-6s %-16s" % ("PCOMM", "PID", "Time(ns)"))

# loop with callback to print_event
b["events"].open_perf_buffer(print_event)
while 1:
    try:
        b.perf_buffer_poll()
    except KeyboardInterrupt:
        exit()
