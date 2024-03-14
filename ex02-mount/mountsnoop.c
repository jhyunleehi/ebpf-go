//go:build ignore

#include "vmlinux.h"

#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#define __MOUNTSNOOP_H

#define TASK_COMM_LEN 16
#define FS_NAME_LEN 8
#define DATA_LEN 512
#define PATH_MAX 4096

#define MAX_EVENT_SIZE 10240
#define RINGBUF_SIZE (1024 * 256)
#define MAX_ENTRIES 10240

const volatile pid_t target_pid = 0;
struct {
  __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
  __uint(max_entries, 1);
  __uint(key_size, sizeof(__u32));
  __uint(value_size, MAX_EVENT_SIZE);
} heap SEC(".maps");

// struct {
// 	__uint(type, BPF_MAP_TYPE_RINGBUF);
// 	__uint(max_entries, RINGBUF_SIZE);
// } events SEC(".maps");

struct {
  __uint(type, BPF_MAP_TYPE_RINGBUF);
  __uint(max_entries, 1 << 24);
} events SEC(".maps");

static __always_inline void *reserve_buf(__u64 size) {
  static const int zero = 0;

  if (bpf_core_type_exists(struct bpf_ringbuf))
    return bpf_ringbuf_reserve(&events, size, 0);

  return bpf_map_lookup_elem(&heap, &zero);
}

static __always_inline long submit_buf(void *ctx, void *buf, __u64 size) {
  if (bpf_core_type_exists(struct bpf_ringbuf)) {
    bpf_ringbuf_submit(buf, 0);
    return 0;
  }

  return bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, buf, size);
}

enum op {
  MOUNT,
  UMOUNT,
};

struct arg {
  __u64 ts;
  __u64 flags;
  __u64 src;
  __u64 dest;
  __u64 fs;
  __u64 data;
  enum op op;
};

struct event {
  __u64 delta;
  __u64 flags;
  __u32 pid;
  __u32 tid;
  unsigned int mnt_ns;
  int ret;
  char comm[TASK_COMM_LEN];
  char fs[FS_NAME_LEN];
  char src[PATH_MAX];
  char dest[PATH_MAX];
  char data[DATA_LEN];
  enum op op;
};
const struct event *unused __attribute__((unused));

struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __uint(max_entries, MAX_ENTRIES);
  __type(key, __u32);
  __type(value, struct arg);
} args SEC(".maps");

static int probe_exit(void *ctx, int ret) {
  __u64 pid_tgid = bpf_get_current_pid_tgid();
  __u32 pid = pid_tgid >> 32;
  __u32 tid = (__u32)pid_tgid;
  struct task_struct *task;
  struct event *eventp;
  struct arg *argp;

  argp = bpf_map_lookup_elem(&args, &tid);
  if (!argp)
    return 0;

  eventp = reserve_buf(sizeof(*eventp));
  if (!eventp)
    goto cleanup;

  task = (struct task_struct *)bpf_get_current_task();
  eventp->delta = bpf_ktime_get_ns() - argp->ts;
  eventp->flags = argp->flags;
  eventp->pid = pid;
  eventp->tid = tid;
  eventp->mnt_ns = BPF_CORE_READ(task, nsproxy, mnt_ns, ns.inum);
  eventp->ret = ret;
  eventp->op = argp->op;
  bpf_get_current_comm(&eventp->comm, sizeof(eventp->comm));
  if (argp->src)
    bpf_probe_read_user_str(eventp->src, sizeof(eventp->src),
                            (const void *)argp->src);
  else
    eventp->src[0] = '\0';
  if (argp->dest)
    bpf_probe_read_user_str(eventp->dest, sizeof(eventp->dest),
                            (const void *)argp->dest);
  else
    eventp->dest[0] = '\0';
  if (argp->fs)
    bpf_probe_read_user_str(eventp->fs, sizeof(eventp->fs),
                            (const void *)argp->fs);
  else
    eventp->fs[0] = '\0';
  if (argp->data)
    bpf_probe_read_user_str(eventp->data, sizeof(eventp->data),
                            (const void *)argp->data);
  else
    eventp->data[0] = '\0';

// submit_buf(ctx, eventp, sizeof(*eventp));
// bpf_ringbuf_submit(eventp, 0);
cleanup:
  bpf_map_delete_elem(&args, &tid);
  return 0;
}

static int probe_entry(const char *src, const char *dest, const char *fs,
                       __u64 flags, const char *data, enum op op) {
  __u64 pid_tgid = bpf_get_current_pid_tgid();
  __u32 pid = pid_tgid >> 32;
  __u32 tid = (__u32)pid_tgid;
  struct arg arg = {};

  struct event *eventp;
  eventp = bpf_ringbuf_reserve(&events, sizeof(struct event), 0);
  if (!eventp) {
    return 0;
  }

  eventp->pid = tid;
  bpf_get_current_comm(&eventp->comm, 80);

  // bpf_trace_printk("Hello from eBPF program! Process (PID: %d\n",  0 );

  if (src)
    bpf_probe_read_user_str(eventp->src, sizeof(eventp->src),
                            (const void *)src);
  else
    eventp->src[0] = '\0';

  if (dest)
    bpf_probe_read_user_str(eventp->dest, sizeof(eventp->dest),
                            (const void *)dest);
  else
    eventp->dest[0] = '\0';

  if (fs)
    bpf_probe_read_user_str(eventp->fs, sizeof(eventp->fs), (const void *)fs);
  else
    eventp->fs[0] = '\0';

  if (data)
    bpf_probe_read_user_str(eventp->data, sizeof(eventp->data),
                            (const void *)data);
  else
    eventp->data[0] = '\0';

  eventp->op = op;

  bpf_ringbuf_submit(eventp, 0);
  return 0;
};

SEC("tracepoint/syscalls/sys_enter_mount")
int mount_entry(struct trace_event_raw_sys_enter *ctx) {
  const char *src = (const char *)ctx->args[0];
  const char *dest = (const char *)ctx->args[1];
  const char *fs = (const char *)ctx->args[2];
  __u64 flags = (__u64)ctx->args[3];
  const char *data = (const char *)ctx->args[4];

  int pid = bpf_get_current_pid_tgid() >> 32;
  const char fmt_str[] = "Hello, world, from BPF! My PID is [%d]";
  bpf_trace_printk(fmt_str, sizeof(fmt_str), pid);

  bpf_printk("sys_enter_mount===>> [%d]", pid);
  return probe_entry(src, dest, fs, flags, data, MOUNT);
}

SEC("tracepoint/syscalls/sys_exit_mount")
int mount_exit(struct trace_event_raw_sys_exit *ctx)
{
  int pid = bpf_get_current_pid_tgid() >> 32;
  const char fmt_str[] = "sys_exit_mount===>> [%d]";
  bpf_trace_printk(fmt_str, sizeof(fmt_str), pid);  
	//return probe_exit(ctx, (int)ctx->ret);
  return 0;
}


SEC("tracepoint/syscalls/sys_enter_umount")
int umount_entry(struct trace_event_raw_sys_enter *ctx) {
  const char *dest = (const char *)ctx->args[0];

  __u64 flags = (__u64)ctx->args[1];

  int pid = bpf_get_current_pid_tgid() >> 32;
  bpf_printk("sys_enter_umount===>> [%d]",pid); 

  return probe_entry(NULL, dest, NULL, flags, NULL, UMOUNT);
}



SEC("tracepoint/syscalls/sys_exit_umount")
int umount_exit(struct trace_event_raw_sys_exit *ctx) {
  int pid = bpf_get_current_pid_tgid() >> 32;  
  bpf_printk("sys_exit_umount===>> [%d]",pid);  
  
  //return probe_exit(ctx, (int)ctx->ret);
  return 0;
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";
