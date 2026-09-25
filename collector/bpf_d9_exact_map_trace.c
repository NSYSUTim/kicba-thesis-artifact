#include <uapi/linux/ptrace.h>

#define D9_EXACT_NAME_MAX 255

struct exact_event {
    u64 inode;
    u32 d_type;
    u32 name_length;
    char name[D9_EXACT_NAME_MAX + 1];
};

struct exact_key {
    u32 pid;
    u32 index;
};

struct exact_stats {
    u64 accepted;
    u64 rejected;
    u64 read_errors;
    u64 map_failures;
    u64 return_underflows;
};

BPF_HASH(monitored_pids, u32, u8, 1024);
BPF_ARRAY(collection_enabled, u8, 1);
BPF_HASH(pending_by_pid, u32, struct exact_event, 1024);
BPF_HASH(sequence_by_pid, u32, u32, 1024);
BPF_HASH(events_by_pid, struct exact_key, struct exact_event, 131072);
BPF_HASH(stats_by_pid, u32, struct exact_stats, 1024);

static __always_inline int exact_enabled(u32 pid)
{
    u32 zero = 0;
    u8 *enabled = collection_enabled.lookup(&zero);
    return enabled && *enabled && monitored_pids.lookup(&pid);
}

static __always_inline struct exact_stats *exact_stats_for(u32 pid)
{
    struct exact_stats zero = {};
    return stats_by_pid.lookup_or_try_init(&pid, &zero);
}

int exact_filldir64_enter(struct pt_regs *ctx)
{
    u32 pid = (u32)bpf_get_current_pid_tgid();
    struct exact_event event = {};
    struct exact_stats *stats;
    const char *name;
    int name_length;
    long copied;

    if (!exact_enabled(pid))
        return 0;
    stats = exact_stats_for(pid);
    name = (const char *)PT_REGS_PARM2(ctx);
    name_length = (int)PT_REGS_PARM3(ctx);
    if (name_length < 0 || name_length > D9_EXACT_NAME_MAX) {
        if (stats)
            stats->read_errors++;
        return 0;
    }
    event.inode = (u64)PT_REGS_PARM5(ctx);
    event.d_type = (u32)PT_REGS_PARM6(ctx) & 15U;
    event.name_length = (u32)name_length;
    copied = bpf_probe_read_kernel_str(event.name, sizeof(event.name), name);
    if (copied < name_length + 1) {
        if (stats)
            stats->read_errors++;
        return 0;
    }
    if (pending_by_pid.update(&pid, &event) && stats)
        stats->map_failures++;
    return 0;
}

int exact_filldir64_return(struct pt_regs *ctx)
{
    u32 pid = (u32)bpf_get_current_pid_tgid();
    u32 zero = 0;
    struct exact_stats *stats;
    struct exact_event *event;

    if (!exact_enabled(pid))
        return 0;
    stats = exact_stats_for(pid);
    event = pending_by_pid.lookup(&pid);
    if (!event) {
        if (stats)
            stats->return_underflows++;
        return 0;
    }
    if (PT_REGS_RC(ctx)) {
        u32 *sequence = sequence_by_pid.lookup_or_try_init(&pid, &zero);
        if (sequence) {
            struct exact_key key = {.pid = pid, .index = *sequence};
            if (events_by_pid.update(&key, event)) {
                if (stats)
                    stats->map_failures++;
            } else {
                (*sequence)++;
                if (stats)
                    stats->accepted++;
            }
        } else if (stats) {
            stats->map_failures++;
        }
    } else if (stats) {
        stats->rejected++;
    }
    pending_by_pid.delete(&pid);
    return 0;
}
