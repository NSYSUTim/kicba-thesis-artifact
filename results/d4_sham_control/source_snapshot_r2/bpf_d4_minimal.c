#include <uapi/linux/ptrace.h>
#include <linux/sched.h>

#define EVENT_TARGET_ENTER 1
#define EVENT_TARGET_RETURN 2
#define FUNCTION_ITERATE_DIR 1
#define FUNCTION_FILLDIR64 2

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
BPF_HASH(target_function_depth, struct target_key_t, u32, 4096);
BPF_ARRAY(collection_enabled, u8, 1);
BPF_PERF_OUTPUT(events);

static __always_inline int submit_target(
    struct pt_regs *ctx, u32 kind, u32 function_id
) {
    u32 key = 0;
    u8 *enabled = collection_enabled.lookup(&key);
    if (!enabled || !*enabled) {
        return 0;
    }
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 pid = (u32)pid_tgid;
    if (!monitored_pids.lookup(&pid)) {
        return 0;
    }

    struct target_key_t target_key = {};
    target_key.pid = pid;
    target_key.function_id = function_id;
    u32 zero = 0;
    u32 *depth = target_function_depth.lookup(&target_key);
    if (kind == EVENT_TARGET_ENTER) {
        depth = target_function_depth.lookup_or_try_init(&target_key, &zero);
        if (!depth) {
            return 0;
        }
        (*depth)++;
    } else if (!depth || *depth == 0) {
        return 0;
    } else if (*depth > 1) {
        (*depth)--;
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
