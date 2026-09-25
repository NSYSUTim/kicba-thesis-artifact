#include <uapi/linux/ptrace.h>
#include <linux/sched.h>

#define EVENT_TARGET_ENTER 1
#define EVENT_TARGET_RETURN 2
#define EVENT_SCHED_SWITCH 3
#define EVENT_HARDIRQ_ENTER 4
#define EVENT_HARDIRQ_EXIT 5
#define EVENT_SOFTIRQ_ENTER 6
#define EVENT_SOFTIRQ_EXIT 7
#define EVENT_CPU_FREQUENCY 8

#define FUNCTION_ITERATE_DIR 1
#define FUNCTION_FILLDIR64 2
#define FUNCTION_VERIFY_DIRENT_NAME 3
#define FUNCTION_TOUCH_ATIME 4

struct event_t {
    u64 ts;
    u64 aux;
    u32 kind;
    u32 function_id;
    u32 pid;
    u32 tgid;
    s32 other_pid;
    u32 cpu;
    char comm[TASK_COMM_LEN];
};

struct target_key_t {
    u32 pid;
    u32 function_id;
};

BPF_HASH(monitored_pids, u32, u8, 1024);
BPF_HASH(target_depth, u32, u32, 1024);
BPF_HASH(target_function_depth, struct target_key_t, u32, 4096);
BPF_PERCPU_ARRAY(active_target_pid, u32, 1);
BPF_ARRAY(collection_enabled, u8, 1);
BPF_PERF_OUTPUT(events);

static __always_inline int is_enabled(void) {
    u32 key = 0;
    u8 *enabled = collection_enabled.lookup(&key);
    return enabled && *enabled;
}

static __always_inline int is_monitored(u32 pid) {
    return monitored_pids.lookup(&pid) != 0;
}

static __always_inline int target_is_active_on_this_cpu(void) {
    u32 key = 0;
    u32 *pid = active_target_pid.lookup(&key);
    return pid && *pid != 0;
}

static __always_inline int submit_target(
    struct pt_regs *ctx, u32 kind, u32 function_id
) {
    if (!is_enabled()) {
        return 0;
    }
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 pid = (u32)pid_tgid;
    if (!is_monitored(pid)) {
        return 0;
    }
    struct target_key_t target_key = {};
    target_key.pid = pid;
    target_key.function_id = function_id;
    u32 zero = 0;
    u32 *function_depth = target_function_depth.lookup(&target_key);
    if (kind == EVENT_TARGET_ENTER) {
        function_depth = target_function_depth.lookup_or_try_init(
            &target_key, &zero
        );
        if (!function_depth) {
            return 0;
        }
        (*function_depth)++;
    } else if (!function_depth || *function_depth == 0) {
        /*
         * The userspace collector adds a blocked child to monitored_pids.
         * Under load, a kernel call that began before that boundary can return
         * afterwards.  Do not emit that boundary-only return: it has no entry
         * in this collection window and is not a perf-buffer loss.
         */
        return 0;
    } else if (*function_depth > 1) {
        (*function_depth)--;
    } else {
        target_function_depth.delete(&target_key);
    }
    struct event_t event = {};
    event.ts = bpf_ktime_get_ns();
    event.kind = kind;
    event.function_id = function_id;
    event.pid = pid;
    event.tgid = pid_tgid >> 32;
    event.other_pid = -1;
    event.cpu = bpf_get_smp_processor_id();
    bpf_get_current_comm(&event.comm, sizeof(event.comm));
    events.perf_submit(ctx, &event, sizeof(event));
    u32 key = 0;
    u32 *active = active_target_pid.lookup(&key);
    if (kind == EVENT_TARGET_ENTER) {
        u32 *depth = target_depth.lookup_or_try_init(&pid, &zero);
        if (depth) {
            (*depth)++;
        }
        if (active) {
            *active = pid;
        }
    } else if (kind == EVENT_TARGET_RETURN) {
        u32 *depth = target_depth.lookup(&pid);
        if (depth && *depth > 1) {
            (*depth)--;
        } else {
            target_depth.delete(&pid);
            if (active && *active == pid) {
                *active = 0;
            }
        }
    }
    return 0;
}

int trace_iterate_dir_enter(struct pt_regs *ctx) {
    return submit_target(ctx, EVENT_TARGET_ENTER, FUNCTION_ITERATE_DIR);
}
int trace_iterate_dir_return(struct pt_regs *ctx) {
    return submit_target(ctx, EVENT_TARGET_RETURN, FUNCTION_ITERATE_DIR);
}
int trace_filldir64_enter(struct pt_regs *ctx) {
    return submit_target(ctx, EVENT_TARGET_ENTER, FUNCTION_FILLDIR64);
}
int trace_filldir64_return(struct pt_regs *ctx) {
    return submit_target(ctx, EVENT_TARGET_RETURN, FUNCTION_FILLDIR64);
}
int trace_verify_dirent_name_enter(struct pt_regs *ctx) {
    return submit_target(ctx, EVENT_TARGET_ENTER, FUNCTION_VERIFY_DIRENT_NAME);
}
int trace_verify_dirent_name_return(struct pt_regs *ctx) {
    return submit_target(ctx, EVENT_TARGET_RETURN, FUNCTION_VERIFY_DIRENT_NAME);
}
int trace_touch_atime_enter(struct pt_regs *ctx) {
    return submit_target(ctx, EVENT_TARGET_ENTER, FUNCTION_TOUCH_ATIME);
}
int trace_touch_atime_return(struct pt_regs *ctx) {
    return submit_target(ctx, EVENT_TARGET_RETURN, FUNCTION_TOUCH_ATIME);
}

TRACEPOINT_PROBE(sched, sched_switch) {
    if (!is_enabled()) {
        return 0;
    }
    u32 prev_pid = (u32)args->prev_pid;
    u32 next_pid = (u32)args->next_pid;
    if (!is_monitored(prev_pid) && !is_monitored(next_pid)) {
        return 0;
    }
    struct event_t event = {};
    event.ts = bpf_ktime_get_ns();
    event.kind = EVENT_SCHED_SWITCH;
    event.pid = prev_pid;
    event.other_pid = (s32)next_pid;
    event.cpu = bpf_get_smp_processor_id();
    events.perf_submit(args, &event, sizeof(event));
    u32 key = 0;
    u32 *active = active_target_pid.lookup(&key);
    if (active && *active == prev_pid) {
        *active = 0;
    }
    u32 *next_depth = target_depth.lookup(&next_pid);
    if (active && next_depth && *next_depth > 0) {
        *active = next_pid;
    }
    return 0;
}

TRACEPOINT_PROBE(irq, irq_handler_entry) {
    if (!is_enabled() || !target_is_active_on_this_cpu()) {
        return 0;
    }
    struct event_t event = {};
    event.ts = bpf_ktime_get_ns();
    event.kind = EVENT_HARDIRQ_ENTER;
    event.aux = args->irq;
    event.other_pid = -1;
    event.cpu = bpf_get_smp_processor_id();
    events.perf_submit(args, &event, sizeof(event));
    return 0;
}

TRACEPOINT_PROBE(irq, irq_handler_exit) {
    if (!is_enabled() || !target_is_active_on_this_cpu()) {
        return 0;
    }
    struct event_t event = {};
    event.ts = bpf_ktime_get_ns();
    event.kind = EVENT_HARDIRQ_EXIT;
    event.aux = args->irq;
    event.other_pid = -1;
    event.cpu = bpf_get_smp_processor_id();
    events.perf_submit(args, &event, sizeof(event));
    return 0;
}

TRACEPOINT_PROBE(irq, softirq_entry) {
    if (!is_enabled() || !target_is_active_on_this_cpu()) {
        return 0;
    }
    struct event_t event = {};
    event.ts = bpf_ktime_get_ns();
    event.kind = EVENT_SOFTIRQ_ENTER;
    event.aux = args->vec;
    event.other_pid = -1;
    event.cpu = bpf_get_smp_processor_id();
    events.perf_submit(args, &event, sizeof(event));
    return 0;
}

TRACEPOINT_PROBE(irq, softirq_exit) {
    if (!is_enabled() || !target_is_active_on_this_cpu()) {
        return 0;
    }
    struct event_t event = {};
    event.ts = bpf_ktime_get_ns();
    event.kind = EVENT_SOFTIRQ_EXIT;
    event.aux = args->vec;
    event.other_pid = -1;
    event.cpu = bpf_get_smp_processor_id();
    events.perf_submit(args, &event, sizeof(event));
    return 0;
}

TRACEPOINT_PROBE(power, cpu_frequency) {
    if (!is_enabled()) {
        return 0;
    }
    struct event_t event = {};
    event.ts = bpf_ktime_get_ns();
    event.kind = EVENT_CPU_FREQUENCY;
    event.aux = args->state;
    event.other_pid = -1;
    event.cpu = args->cpu_id;
    events.perf_submit(args, &event, sizeof(event));
    return 0;
}
