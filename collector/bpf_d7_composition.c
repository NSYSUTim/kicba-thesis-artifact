#include <uapi/linux/ptrace.h>

BPF_HASH(monitored_pids, u32, u8, 1024);
BPF_HASH(start_times, u32, u64, 1024);
BPF_HASH(call_counts, u32, u32, 1024);
BPF_HASH(first_durations, u32, u64, 1024);
BPF_HASH(last_durations, u32, u64, 1024);
BPF_HASH(filldir64_counts, u32, u32, 1024);
BPF_ARRAY(collection_enabled, u8, 1);

static __always_inline int target_enabled(u32 pid) {
    u32 key = 0;
    u8 *enabled = collection_enabled.lookup(&key);
    return enabled && *enabled && monitored_pids.lookup(&pid);
}

int trace_iterate_dir_enter(struct pt_regs *ctx) {
    u32 pid = (u32)bpf_get_current_pid_tgid();
    if (!target_enabled(pid)) {
        return 0;
    }
    u64 now = bpf_ktime_get_ns();
    start_times.update(&pid, &now);
    return 0;
}

int trace_iterate_dir_return(struct pt_regs *ctx) {
    u32 pid = (u32)bpf_get_current_pid_tgid();
    if (!target_enabled(pid)) {
        return 0;
    }
    u64 *start = start_times.lookup(&pid);
    if (!start) {
        return 0;
    }
    u64 now = bpf_ktime_get_ns();
    u64 duration = now - *start;
    u32 zero = 0;
    u32 *count = call_counts.lookup_or_try_init(&pid, &zero);
    if (count) {
        (*count)++;
        if (*count == 1) {
            first_durations.update(&pid, &duration);
        }
        last_durations.update(&pid, &duration);
    }
    start_times.delete(&pid);
    return 0;
}

int trace_filldir64_enter(struct pt_regs *ctx) {
    u32 pid = (u32)bpf_get_current_pid_tgid();
    if (!target_enabled(pid)) {
        return 0;
    }
    u32 zero = 0;
    u32 *count = filldir64_counts.lookup_or_try_init(&pid, &zero);
    if (count) {
        (*count)++;
    }
    return 0;
}
