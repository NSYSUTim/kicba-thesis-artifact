#include <linux/fs.h>
#include <linux/kernel.h>
#include <linux/module.h>

#include "../caraxes_continue/ftrace_helper.h"

MODULE_LICENSE("GPL");

static bool (*orig_filldir64)(struct dir_context *ctx, const char *name,
                              int namlen, loff_t offset, u64 ino,
                              unsigned int d_type);

static bool sham_filldir64(struct dir_context *ctx, const char *name,
                           int namlen, loff_t offset, u64 ino,
                           unsigned int d_type)
{
    return orig_filldir64(ctx, name, namlen, offset, ino, d_type);
}

static struct ftrace_hook hooks[] = {
    HOOK_NOSYS("filldir64", sham_filldir64, &orig_filldir64),
};

static int __init sham_init(void)
{
    return fh_install_hooks(hooks, ARRAY_SIZE(hooks));
}

static void __exit sham_exit(void)
{
    fh_remove_hooks(hooks, ARRAY_SIZE(hooks));
}

module_init(sham_init);
module_exit(sham_exit);
