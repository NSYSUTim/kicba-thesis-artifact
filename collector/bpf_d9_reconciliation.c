#include <uapi/linux/ptrace.h>
#include "d9_reconciliation_hash.h"

#define D9_NAME_MAX 255
#define D9_S_DT_MASK 15U

#define D9_HASH_ONE(N)                                                   \
    do {                                                                 \
        if (name_length > (N))                                           \
            value = d9_entry_hash_byte(                                  \
                value, (unsigned char)raw[(N)]);                          \
    } while (0)
#define D9_HASH_BYTE_AT(N)                                               \
    value = d9_entry_hash_byte(value, (unsigned char)raw[(N)])
#define D9_HASH_EIGHT(B)                                                 \
    do {                                                                 \
        if (name_length >= (B) + 8) {                                   \
            D9_HASH_BYTE_AT((B) + 0); D9_HASH_BYTE_AT((B) + 1);          \
            D9_HASH_BYTE_AT((B) + 2); D9_HASH_BYTE_AT((B) + 3);          \
            D9_HASH_BYTE_AT((B) + 4); D9_HASH_BYTE_AT((B) + 5);          \
            D9_HASH_BYTE_AT((B) + 6); D9_HASH_BYTE_AT((B) + 7);          \
        } else if (name_length > (B)) {                                 \
            D9_HASH_ONE((B) + 0); D9_HASH_ONE((B) + 1);                 \
            D9_HASH_ONE((B) + 2); D9_HASH_ONE((B) + 3);                 \
            D9_HASH_ONE((B) + 4); D9_HASH_ONE((B) + 5);                 \
            D9_HASH_ONE((B) + 6); D9_HASH_ONE((B) + 7);                 \
        }                                                                \
    } while (0)

struct d9_token {
    u64 key_hash;
    u64 inode;
    u32 d_type;
    u32 name_length;
};

struct d9_fingerprint {
    u64 count;
    u64 sum1;
    u64 sum2;
};

struct d9_cell_key {
    u32 pid;
    u32 index;
};

struct d9_cell {
    s32 count;
    u32 pad;
    u64 key_xor;
    u64 inode_xor;
    u64 type_xor;
    u64 check_xor;
};

struct d9_stats {
    u64 outer_entries;
    u64 accepted_entries;
    u64 rejected_entries;
    u64 name_read_errors;
    u64 invalid_name_lengths;
    u64 pending_update_failures;
    u64 fingerprint_update_failures;
    u64 iblt_update_failures;
    u64 return_underflows;
};

BPF_HASH(monitored_pids, u32, u8, 1024);
BPF_ARRAY(collection_enabled, u8, 1);
BPF_ARRAY(hash_seeds, u64, 2);
BPF_ARRAY(iblt_cell_count, u32, 1);

BPF_HASH(depth_by_pid, u32, u32, 1024);
BPF_HASH(pending_by_pid, u32, struct d9_token, 1024);
BPF_HASH(kernel_fingerprints, u32, struct d9_fingerprint, 1024);
BPF_HASH(kernel_iblt, struct d9_cell_key, struct d9_cell, 65536);
BPF_HASH(stats_by_pid, u32, struct d9_stats, 1024);

static __always_inline int d9_target_enabled(u32 pid)
{
    u32 zero = 0;
    u8 *enabled = collection_enabled.lookup(&zero);
    return enabled && *enabled && monitored_pids.lookup(&pid);
}

static __always_inline struct d9_stats *d9_stats_for(u32 pid)
{
    struct d9_stats zero = {};
    return stats_by_pid.lookup_or_try_init(&pid, &zero);
}

static __always_inline int d9_update_cell(
    u32 pid, u32 index, const struct d9_token *token,
    u64 seed1, u64 seed2)
{
    struct d9_cell_key key = {.pid = pid, .index = index};
    struct d9_cell zero = {};
    struct d9_cell *cell = kernel_iblt.lookup_or_try_init(&key, &zero);
    if (!cell)
        return -1;
    cell->count += 1;
    cell->key_xor ^= token->key_hash;
    cell->inode_xor ^= token->inode;
    cell->type_xor ^= token->d_type;
    cell->check_xor ^= d9_token_check(
        token->key_hash, token->inode, token->d_type, seed1, seed2);
    return 0;
}

static __always_inline void d9_commit(u32 pid, const struct d9_token *token)
{
    u32 zero_key = 0;
    u32 one_key = 1;
    struct d9_fingerprint zero_fp = {};
    struct d9_fingerprint *fp;
    struct d9_stats *stats;
    u64 *seed1_ptr = hash_seeds.lookup(&zero_key);
    u64 *seed2_ptr = hash_seeds.lookup(&one_key);
    u32 *cell_count_ptr = iblt_cell_count.lookup(&zero_key);
    u32 cell_count;
    u32 mask;
    u32 first;
    u32 second;
    u32 third;

    stats = d9_stats_for(pid);
    if (!seed1_ptr || !seed2_ptr || !cell_count_ptr) {
        if (stats)
            stats->iblt_update_failures++;
        return;
    }
    fp = kernel_fingerprints.lookup_or_try_init(&pid, &zero_fp);
    if (!fp) {
        if (stats)
            stats->fingerprint_update_failures++;
        return;
    }
    fp->count++;
    fp->sum1 += token->key_hash;
    fp->sum2 += d9_fingerprint_second(
        token->key_hash, token->inode, token->d_type);
    if (stats)
        stats->accepted_entries++;

    cell_count = *cell_count_ptr;
    if (cell_count < 4 || (cell_count & (cell_count - 1U))) {
        if (stats)
            stats->iblt_update_failures++;
        return;
    }
    mask = cell_count - 1U;
    first = d9_position_1(token->key_hash, *seed1_ptr, mask);
    second = d9_position_2(token->key_hash, *seed2_ptr, mask, first);
    third = d9_position_3(
        token->key_hash, *seed1_ptr, *seed2_ptr,
        mask, first, second);
    if (d9_update_cell(pid, first, token, *seed1_ptr, *seed2_ptr) ||
        d9_update_cell(pid, second, token, *seed1_ptr, *seed2_ptr) ||
        d9_update_cell(pid, third, token, *seed1_ptr, *seed2_ptr)) {
        if (stats)
            stats->iblt_update_failures++;
    }
}

int d9_filldir64_enter(struct pt_regs *ctx)
{
    u32 pid = (u32)bpf_get_current_pid_tgid();
    u32 zero = 0;
    u32 *depth;

    if (!d9_target_enabled(pid))
        return 0;
    depth = depth_by_pid.lookup_or_try_init(&pid, &zero);
    if (!depth)
        return 0;
    if (*depth == 0) {
        const char *name = (const char *)PT_REGS_PARM2(ctx);
        int name_length = (int)PT_REGS_PARM3(ctx);
        u64 inode = (u64)PT_REGS_PARM5(ctx);
        u32 d_type = (u32)PT_REGS_PARM6(ctx) & D9_S_DT_MASK;
        struct d9_stats *stats = d9_stats_for(pid);
        struct d9_token token = {};
        u32 zero_key = 0;
        u32 one_key = 1;
        u64 *seed1_ptr = hash_seeds.lookup(&zero_key);
        u64 *seed2_ptr = hash_seeds.lookup(&one_key);
        char raw[D9_NAME_MAX + 1] = {};
        u64 value;
        long copied;

        if (stats)
            stats->outer_entries++;
        if (!seed1_ptr || !seed2_ptr || name_length < 0 ||
            name_length > D9_NAME_MAX) {
            if (stats)
                stats->invalid_name_lengths++;
            goto increment_depth;
        }
        copied = bpf_probe_read_kernel_str(raw, sizeof(raw), name);
        if (copied < name_length + 1) {
            if (stats)
                stats->name_read_errors++;
            goto increment_depth;
        }
        value = d9_entry_hash_begin(*seed1_ptr);
        D9_HASH_EIGHT(0);
        D9_HASH_EIGHT(8);
        D9_HASH_EIGHT(16);
        D9_HASH_EIGHT(24);
        D9_HASH_EIGHT(32);
        D9_HASH_EIGHT(40);
        D9_HASH_EIGHT(48);
        D9_HASH_EIGHT(56);
        D9_HASH_EIGHT(64);
        D9_HASH_EIGHT(72);
        D9_HASH_EIGHT(80);
        D9_HASH_EIGHT(88);
        D9_HASH_EIGHT(96);
        D9_HASH_EIGHT(104);
        D9_HASH_EIGHT(112);
        D9_HASH_EIGHT(120);
        D9_HASH_EIGHT(128);
        D9_HASH_EIGHT(136);
        D9_HASH_EIGHT(144);
        D9_HASH_EIGHT(152);
        D9_HASH_EIGHT(160);
        D9_HASH_EIGHT(168);
        D9_HASH_EIGHT(176);
        D9_HASH_EIGHT(184);
        D9_HASH_EIGHT(192);
        D9_HASH_EIGHT(200);
        D9_HASH_EIGHT(208);
        D9_HASH_EIGHT(216);
        D9_HASH_EIGHT(224);
        D9_HASH_EIGHT(232);
        D9_HASH_EIGHT(240);
        D9_HASH_EIGHT(248);
        token.key_hash = d9_entry_hash_finish(
            value, inode, d_type, name_length, *seed1_ptr, *seed2_ptr);
        token.inode = inode;
        token.d_type = d_type;
        token.name_length = name_length;
        if (pending_by_pid.update(&pid, &token) && stats)
            stats->pending_update_failures++;
    }

increment_depth:
    (*depth)++;
    return 0;
}

int d9_filldir64_return(struct pt_regs *ctx)
{
    u32 pid = (u32)bpf_get_current_pid_tgid();
    u32 *depth;
    struct d9_stats *stats;

    if (!d9_target_enabled(pid))
        return 0;
    depth = depth_by_pid.lookup(&pid);
    stats = d9_stats_for(pid);
    if (!depth || *depth == 0) {
        if (stats)
            stats->return_underflows++;
        return 0;
    }
    if (*depth > 1) {
        (*depth)--;
        return 0;
    }
    if (PT_REGS_RC(ctx)) {
        struct d9_token *token = pending_by_pid.lookup(&pid);
        if (token)
            d9_commit(pid, token);
        else if (stats)
            stats->pending_update_failures++;
    } else if (stats) {
        stats->rejected_entries++;
    }
    pending_by_pid.delete(&pid);
    depth_by_pid.delete(&pid);
    return 0;
}
