#include <uapi/linux/ptrace.h>

/*
 * Per-PID structural summary for recursive/nested filldir64 invocations.
 *
 * The CARAXES-style ftrace wrapper redirects the outer filldir64 call to a
 * wrapper.  A forwarded directory entry then invokes the original symbol as
 * a nested call; a suppressed entry returns from the wrapper without that
 * child.  We aggregate only this shape and never read names or module state.
 */
BPF_HASH(monitored_pids, u32, u8, 1024);
BPF_ARRAY(collection_enabled, u8, 1);
BPF_HASH(depth_by_pid, u32, u32, 1024);
BPF_HASH(top_has_child, u32, u8, 1024);
BPF_HASH(top_level_calls, u32, u32, 1024);
BPF_HASH(forwarded_top_calls, u32, u32, 1024);
BPF_HASH(short_circuit_top_calls, u32, u32, 1024);
BPF_HASH(max_depth_by_pid, u32, u32, 1024);
BPF_HASH(return_underflows, u32, u32, 1024);

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
