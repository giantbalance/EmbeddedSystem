#!/usr/bin/python

from bcc import BPF
from time import sleep

# define BPF program
bpf_text = """
#include <uapi/linux/ptrace.h>
#include <linux/fs.h>

struct data_t{
    u32 pid;
    char comm[TASK_COMM_LEN];
    u32 rc[8];
    u32 wc[8];
};

BPF_HASH(hashbypid, u32 ,struct data_t);

static int snoop(struct file *file, u32 rw)
{
    struct data_t *data, zero = {};
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    data = hashbypid.lookup_or_try_init(&pid, &zero);
    if(!data)
        return -1;
    u32 *temp;
    if(0 == rw)
    {
        temp = data->rc;
    }
    else
    {
        temp = data->wc;
    }
    struct inode *inode = file->f_inode;
    switch(inode->i_mode & S_IFMT)
    {
        case S_IFDIR:
            temp[7]++;
            break;
        case S_IFCHR:
            temp[6]++;
            break;
        case S_IFBLK:
            temp[5]++;
            break;
        case S_IFREG:
            temp[4]++;
            break;
        case S_IFIFO:      
            temp[3]++;
            break;
        case S_IFLNK:      
            temp[2]++;
            break;
        case S_IFSOCK:
            temp[1]++;
            break;
        case S_IFMT:
            temp[0]++;
            break;
        default:
            return -1;
    }

    data->pid = pid;
    bpf_get_current_comm(&data->comm, sizeof(data->comm));
    return 0;
}

void kprobe__vfs_read(struct pt_regs *ctx, struct file *file, char __user *buf, size_t count, loff_t *pos)
{
    snoop(file, 0);
}
void kprobe__vfs_write(struct pt_regs *ctx, struct file *file, const char __user *buf, size_t count, loff_t *pos)
{
    snoop(file, 1);
}
void kprobe__vfs_readv(struct pt_regs *ctx, struct file *file, const struct iovec __user *vec,
		  unsigned long vlen, loff_t *pos, rwf_t flags)
          {
              snoop(file, 0);
          }
void kprobe__vfs_writev(struct pt_regs *ctx, struct file *file, const struct iovec __user *vec,
		   unsigned long vlen, loff_t *pos, rwf_t flags)
           {
               snoop(file, 1);
           }
"""

dict = {7 : 'S_IFDIR', 6 : 'S_IFCHR', 5:'S_IFBLK', 4: 'S_IFREG',
3 : 'S_IFIFO', 2 : 'S_IFLNK', 1 :'S_IFSOCK', 0 : 'S_IFMT'}

# initialize BPF
b = BPF(text=bpf_text)
print("Tracing vfs... Ctrl-C to print.")
while 1:
    try:
        sleep(999999999)
    except KeyboardInterrupt:
        print("Ctrl-C")
    
    print(("%-8s %-16s %-4s %-8s %-8s") % ("PID", "COMM", "RW", "TYPE", "COUNT"))
    event = b["hashbypid"]

    for k, v in sorted(event.items(),key=lambda event: -event[1].pid):
        for i, count in enumerate(v.rc):
            if count:
                print(("%-8s %-16s %-4s %-8s %-8s") % (v.pid, v.comm.decode('utf-8', 'replace'), "R", dict.get(i), count))
            else:
                print(("%-8s %-16s %-4s %-8s %-8s") % (v.pid, v.comm.decode('utf-8', 'replace'), "W", dict.get(i), count))
exit()
