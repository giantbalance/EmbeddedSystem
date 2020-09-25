#!/usr/bin/python

from __future__ import print_function
from bcc import BPF
from time import strftime

# define BPF program
bpf_text="""
#include <uapi/linux/ptrace.h>
#include <linux/blkdev.h>

#define SEC_SHIFT 9

struct data_t {
    u64 sec;
    u64 len;
    u32 rw;
    u32 seq;
    char disk_name[DISK_NAME_LEN];
    char name[TASK_COMM_LEN];
};

struct val_t{
    u64 rsec;
    u64 rlen;
    u64 rseqc;
    u64 rrandc;    
    u64 wsec;
    u64 wlen;
    u64 wseqc;
    u64 wrandc;
    char name[TASK_COMM_LEN];
};

struct key_t{
    char disk_name[DISK_NAME_LEN];
};
BPF_HASH(hashbydisk, struct key_t, struct val_t);

static int isSeq(u64 sec, u64 len, u64 bsec, u64 blen)
{
    int ret = 0;
    //Using 512 sector, needs to divide to sector size(512B)
    len = len >> SEC_SHIFT;
    blen = blen >> SEC_SHIFT;
    if (((sec + len) >= bsec) && ((sec - blen) <= bsec))
        ret = 1;
    return ret;
}


BPF_PERF_OUTPUT(events);

int kprobe__blk_mq_start_request(struct pt_regs *ctx, struct request *req)
{
    struct val_t *valp, zero = {};
    struct data_t data = {};
    struct key_t disk_key = {};
    bool rwflag;
    u64 sec,len,blen,bsec;

    struct gendisk *rq_disk = req->rq_disk;
    bpf_probe_read_kernel(&disk_key, sizeof(key_t),
                       rq_disk->disk_name);

    valp = hashbydisk.lookup_or_try_init(&disk_key, &zero);
    
    if (valp == 0)
    {
        bpf_trace_printk("no valp");
        return 0;
    }

    /*
    * The following deals with a kernel version change (in mainline 4.7, although
    * it may be backported to earlier kernels) with how block request write flags
    * are tested. We handle both pre- and post-change versions here. Please avoid
    * kernel version tests like this as much as possible: they inflate the code,
    * test, and maintenance burden.
    */
#ifdef REQ_WRITE
    rwflag = !!(req->cmd_flags & REQ_WRITE);
#elif defined(REQ_OP_SHIFT)
    rwflag = !!((req->cmd_flags >> REQ_OP_SHIFT) == REQ_OP_WRITE);
#else
    rwflag = !!((req->cmd_flags & REQ_OP_MASK) == REQ_OP_WRITE);
#endif
    bsec = req->__sector;
    blen = req->__data_len;
    
    if(0 == rwflag)
    {
        // write
        sec = valp->wsec;
        len = valp->wlen;
        // Seq check
        if(isSeq(sec,len,bsec,blen) == 1)
        {
            data.seq = 1;
            valp->wseqc++;
        }
        else
        {
            valp->wrandc++;
        }
        // update
        valp->wsec = bsec;
        valp->wlen = blen;
        data.rw = 0;
    }
else
    {
        // read
        sec = valp->rsec;
        len = valp->rlen;
        // Seq check
        if(isSeq(sec,len,bsec,blen) == 1)
        {
            valp->rseqc++;
            data.seq = 1;
        }
        else
        {
            valp->rrandc++;
        }
        // update
        valp->rsec = bsec;
        valp->rlen = blen;
        data.rw = 1;
    }

    // copy to data and print
    data.sec = bsec;
    data.len = blen;
    bpf_get_current_comm(valp->name, sizeof(valp->name));
    bpf_probe_read_kernel(&data.name, sizeof(data.name), valp->name);
    bpf_probe_read_kernel(&data.disk_name, sizeof(data.disk_name),
                       &disk_key);
    
    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
}

"""

rwflg = ""
seqflg = ""

# process event
def print_event(cpu, data, size):
    event = b["events"].event(data)

    if event.rw == 0:
        rwflg = "R"
    else:
        rwflg = "W"

    if event.seq == 1:
        seqflg = "SEQ"
    else:
        seqflg = "RAND"

    print("%-11s %-14s %-14s %-4s %-8s %-16d %-8d" % (strftime("%H:%M:%S"), event.name.decode('utf-8', 'replace'), event.disk_name.decode('utf-8', 'replace'),rwflg, seqflg, event.sec, event.len))


# initialize BPF
b = BPF(text=bpf_text)

# header
print("%-11s %-14s %-14s %-4s %-4s, %-16s %-8s" % 
("TIME(s)", "COMM", "DISK", "RW", "SEQ", "SECTOR", "BYTES"))

# loop with callback to print_event
b["events"].open_perf_buffer(print_event, page_cnt=64)
while 1:
    try:
        b.perf_buffer_poll()
    except KeyboardInterrupt:
        exit()
