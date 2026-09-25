/*
 * Controlled equal-cardinality getdents64 transformation for D9 validation.
 *
 * A matching name is replaced in place by a same-length name.  The number of
 * returned records and bytes is unchanged.  This is intentionally a research
 * fixture: it tests the case that a count-only detector cannot distinguish.
 */

#include <linux/atomic.h>
#include <linux/dirent.h>
#include <linux/errno.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/sched.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/uaccess.h>
#include <linux/vmalloc.h>

#include "../d7_controls_r2/ftrace_helper.h"

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("KICBA D9 controlled equal-cardinality dirent substitution");

static char *target_comm = "d9_enum_probe";
module_param(target_comm, charp, 0444);
MODULE_PARM_DESC(target_comm, "Only transform getdents64 calls from this comm");

static char *match_prefix = "d9_swap_a_";
module_param(match_prefix, charp, 0444);
MODULE_PARM_DESC(match_prefix, "Same-length source prefix");

static char *replacement_prefix = "d9_swap_b_";
module_param(replacement_prefix, charp, 0444);
MODULE_PARM_DESC(replacement_prefix, "Same-length replacement prefix");

static atomic64_t target_syscalls = ATOMIC64_INIT(0);
static atomic64_t records_seen = ATOMIC64_INIT(0);
static atomic64_t records_rewritten = ATOMIC64_INIT(0);
static atomic64_t parse_errors = ATOMIC64_INIT(0);

static int d9_param_get_atomic64(char *buffer, const struct kernel_param *kp)
{
	const atomic64_t *value = kp->arg;

	return sysfs_emit(buffer, "%lld\n", (long long)atomic64_read(value));
}

static const struct kernel_param_ops d9_atomic64_ro_ops = {
	.get = d9_param_get_atomic64,
};

#define D9_COUNTER(_name) \
	module_param_cb(_name, &d9_atomic64_ro_ops, &_name, 0444)

D9_COUNTER(target_syscalls);
D9_COUNTER(records_seen);
D9_COUNTER(records_rewritten);
D9_COUNTER(parse_errors);

static long (*d9_orig_getdents64)(const struct pt_regs *regs);

static asmlinkage long d9_hook_getdents64(const struct pt_regs *regs)
{
	struct linux_dirent64 __user *user_dirents;
	char *buffer;
	unsigned long offset = 0;
	long result;
	size_t source_len = strlen(match_prefix);
	size_t replacement_len = strlen(replacement_prefix);

	result = d9_orig_getdents64(regs);
	if (result <= 0 || strcmp(current->comm, target_comm) != 0)
		return result;

	atomic64_inc(&target_syscalls);
	user_dirents = (struct linux_dirent64 __user *)regs->si;
	buffer = kvmalloc(result, GFP_KERNEL);
	if (!buffer)
		return result;
	if (copy_from_user(buffer, user_dirents, result)) {
		atomic64_inc(&parse_errors);
		kvfree(buffer);
		return result;
	}

	while (offset < result) {
		struct linux_dirent64 *entry =
			(struct linux_dirent64 *)(buffer + offset);
		size_t header = offsetof(struct linux_dirent64, d_name);
		size_t room;
		size_t name_len;

		if (entry->d_reclen < header + 1 ||
		    offset + entry->d_reclen > result) {
			atomic64_inc(&parse_errors);
			kvfree(buffer);
			return result;
		}
		room = entry->d_reclen - header;
		name_len = strnlen(entry->d_name, room);
		if (name_len == room) {
			atomic64_inc(&parse_errors);
			kvfree(buffer);
			return result;
		}
		atomic64_inc(&records_seen);
		if (name_len >= source_len &&
		    strncmp(entry->d_name, match_prefix, source_len) == 0) {
			memcpy(entry->d_name, replacement_prefix, replacement_len);
			atomic64_inc(&records_rewritten);
		}
		offset += entry->d_reclen;
	}

	if (copy_to_user(user_dirents, buffer, result))
		atomic64_inc(&parse_errors);
	kvfree(buffer);
	return result;
}

static struct ftrace_hook d9_hook =
	HOOK("sys_getdents64", d9_hook_getdents64, &d9_orig_getdents64);

static int __init d9_init(void)
{
	if (!target_comm || !*target_comm || !match_prefix || !*match_prefix ||
	    !replacement_prefix || !*replacement_prefix)
		return -EINVAL;
	if (strlen(match_prefix) != strlen(replacement_prefix))
		return -EINVAL;
	return fh_install_hook(&d9_hook);
}

static void __exit d9_exit(void)
{
	fh_remove_hook(&d9_hook);
}

module_init(d9_init);
module_exit(d9_exit);
