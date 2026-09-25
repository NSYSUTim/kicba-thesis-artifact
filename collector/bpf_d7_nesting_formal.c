#include <uapi/linux/ptrace.h>

/* Frozen D7 collector: structural nesting plus same-run timing comparator. */
BPF_HASH(monitored_pids, u32, u8, 1024);
BPF_ARRAY(collection_enabled, u8, 1);

BPF_HASH(depth_by_pid, u32, u32, 1024);
BPF_HASH(top_has_child, u32, u8, 1024);
BPF_HASH(top_level_calls, u32, u32, 1024);
BPF_HASH(forwarded_top_calls, u32, u32, 1024);
BPF_HASH(short_circuit_top_calls, u32, u32, 1024);
BPF_HASH(max_depth_by_pid, u32, u32, 1024);
BPF_HASH(return_underflows, u32, u32, 1024);

BPF_HASH(iterate_start, u32, u64, 1024);
BPF_HASH(iterate_calls, u32, u32, 1024);
BPF_HASH(first_iterate_ns, u32, u64, 1024);
BPF_HASH(last_iterate_ns, u32, u64, 1024);

static __always_inline int target_enabled(u32 pid)
{
    u32 key = 0;
    u8 *enabled = collection_enabled.lookup(&key);
    return enabled && *enabled && monitored_pids.lookup(&pid);
}

int trace_filldir64_enter(struct pt_regs *ctx)
{
    u32 pid = (u32)bpf_get_current_pid_tgid();
    u32 zero = 0;
    u32 *depth;
    u32 *maximum;
    u32 next;

    if (!target_enabled(pid))
        return 0;
    depth = depth_by_pid.lookup_or_try_init(&pid, &zero);
    if (!depth)
        return 0;
    next = *depth + 1;
    if (*depth == 1) {
        u8 one = 1;
        top_has_child.update(&pid, &one);
    }
    *depth = next;
    maximum = max_depth_by_pid.lookup_or_try_init(&pid, &zero);
    if (maximum && next > *maximum)
        *maximum = next;
    return 0;
}

int trace_filldir64_return(struct pt_regs *ctx)
{
    u32 pid = (u32)bpf_get_current_pid_tgid();
    u32 zero = 0;
    u32 *depth;

    if (!target_enabled(pid))
        return 0;
    depth = depth_by_pid.lookup(&pid);
    if (!depth || *depth == 0) {
        u32 *underflows = return_underflows.lookup_or_try_init(&pid, &zero);
        if (underflows)
            (*underflows)++;
        return 0;
    }
    if (*depth > 1) {
        (*depth)--;
        return 0;
    }
    {
        u32 *total = top_level_calls.lookup_or_try_init(&pid, &zero);
        u8 *has_child = top_has_child.lookup(&pid);
        if (total)
            (*total)++;
        if (has_child && *has_child) {
            u32 *forwarded = forwarded_top_calls.lookup_or_try_init(&pid, &zero);
            if (forwarded)
                (*forwarded)++;
        } else {
            u32 *shorted = short_circuit_top_calls.lookup_or_try_init(&pid, &zero);
            if (shorted)
                (*shorted)++;
        }
    }
    top_has_child.delete(&pid);
    depth_by_pid.delete(&pid);
    return 0;
}

int trace_iterate_dir_enter(struct pt_regs *ctx)
{
    u32 pid = (u32)bpf_get_current_pid_tgid();
    u64 now;
    if (!target_enabled(pid))
        return 0;
    now = bpf_ktime_get_ns();
    iterate_start.update(&pid, &now);
    return 0;
}

int trace_iterate_dir_return(struct pt_regs *ctx)
{
    u32 pid = (u32)bpf_get_current_pid_tgid();
    u32 zero = 0;
    u32 *count;
    u64 *start;
    u64 duration;
    if (!target_enabled(pid))
        return 0;
    start = iterate_start.lookup(&pid);
    if (!start)
        return 0;
    duration = bpf_ktime_get_ns() - *start;
    count = iterate_calls.lookup_or_try_init(&pid, &zero);
    if (count) {
        (*count)++;
        if (*count == 1)
            first_iterate_ns.update(&pid, &duration);
        last_iterate_ns.update(&pid, &duration);
    }
    iterate_start.delete(&pid);
    return 0;
}
