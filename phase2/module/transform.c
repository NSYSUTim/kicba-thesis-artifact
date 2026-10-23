/* Controlled, explicitly named getdents64 output fixture for consistency tests.
 * Uses the project's ilammy-derived ftrace helper; no privilege or persistence hooks.
 */
#include <linux/atomic.h>
#include <linux/dirent.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/sched.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/uaccess.h>
#include <linux/vmalloc.h>
#include "../../attack_variants/d7_controls_r2/ftrace_helper.h"

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("Controlled directory-output transformations for isolated validation");
static int mode;
module_param(mode, int, 0444);
static atomic64_t changed=ATOMIC64_INIT(0), skipped=ATOMIC64_INIT(0), errors=ATOMIC64_INIT(0);
static int get_counter(char *buf,const struct kernel_param *kp)
{ return sysfs_emit(buf,"%lld\n",(long long)atomic64_read((atomic64_t *)kp->arg)); }
static const struct kernel_param_ops counter_ops={.get=get_counter};
module_param_cb(changed,&counter_ops,&changed,0444);
module_param_cb(skipped,&counter_ops,&skipped,0444);
module_param_cb(errors,&counter_ops,&errors,0444);

static long (*original_getdents64)(const struct pt_regs *);
static asmlinkage long transformed_getdents64(const struct pt_regs *regs)
{
    long result=original_getdents64(regs), offset=0, subject=-1;
    unsigned long capacity=regs->dx;
    struct linux_dirent64 __user *user=(void *)regs->si;
    char *data, *reversed=NULL;
    const size_t header=offsetof(struct linux_dirent64,d_name);
    struct linux_dirent64 *entry;
    if (result<=0 || strcmp(current->comm,"d9_enum_probe")) return result;
    if ((unsigned long)result>capacity) { atomic64_inc(&errors); return result; }
    data=kvmalloc(result+512,GFP_KERNEL);
    if (!data) { atomic64_inc(&errors); return result; }
    if (copy_from_user(data,user,result)) { atomic64_inc(&errors); goto done; }
    while (offset<result) {
        size_t room,length;
        if (result-offset<header+1) { atomic64_inc(&errors); goto done; }
        entry=(void *)(data+offset);
        if (entry->d_reclen<header+1 || entry->d_reclen%8 || offset+entry->d_reclen>result) {
            atomic64_inc(&errors); goto done;
        }
        room=entry->d_reclen-header;
        length=strnlen(entry->d_name,room);
        if (length==room) { atomic64_inc(&errors); goto done; }
        if (length==14 && !memcmp(entry->d_name,"phase2_subject",14)) subject=offset;
        offset+=entry->d_reclen;
    }
    if (subject<0) goto done;
    entry=(void *)(data+subject);
    if (mode==1) {
        long cursor=result;
        reversed=kvmalloc(result,GFP_KERNEL);
        if (!reversed) { atomic64_inc(&errors); goto done; }
        for (offset=0;offset<result;) {
            struct linux_dirent64 *record=(void *)(data+offset);
            cursor-=record->d_reclen;
            memcpy(reversed+cursor,record,record->d_reclen);
            offset+=record->d_reclen;
        }
        memcpy(data,reversed,result);
    } else if (mode==2) {
        struct linux_dirent64 *added;
        size_t size=ALIGN(header+strlen("phase2_inserted")+1,8);
        if (result+size>capacity) { atomic64_inc(&skipped); goto done; }
        added=(void *)(data+result);
        memset(added,0,size);
        added->d_ino=0x7fff000000000123ULL;
        added->d_off=entry->d_off;
        added->d_reclen=size;
        added->d_type=8;
        memcpy(added->d_name,"phase2_inserted",strlen("phase2_inserted")+1);
        result+=size;
    } else if (mode==3 || mode==4) {
        const char *name=mode==3 ? "phase2_subject_much_longer_name" : "p2x";
        unsigned short old_size=entry->d_reclen,new_size=ALIGN(header+strlen(name)+1,8);
        long delta=(long)new_size-(long)old_size;
        if (result+delta>capacity) { atomic64_inc(&skipped); goto done; }
        memmove(data+subject+new_size,data+subject+old_size,result-subject-old_size);
        entry->d_reclen=new_size;
        memset(entry->d_name,0,new_size-header);
        memcpy(entry->d_name,name,strlen(name));
        result+=delta;
    } else if (mode==5) entry->d_ino^=1ULL<<62;
    else if (mode==6) entry->d_type=4;
    else if (mode==7) {
        unsigned short old_size=entry->d_reclen;
        memmove(data+subject,data+subject+old_size,result-subject-old_size);
        result-=old_size;
    }
    if (copy_to_user(user,data,result)) atomic64_inc(&errors);
    else atomic64_inc(&changed);
done:
    kvfree(reversed);
    kvfree(data);
    return result;
}

static struct ftrace_hook hook=HOOK("sys_getdents64",transformed_getdents64,&original_getdents64);
static int __init start(void)
{
    if (mode<1 || mode>7) return -EINVAL;
    return fh_install_hook(&hook);
}
static void __exit stop(void) { fh_remove_hook(&hook); }
module_init(start);
module_exit(stop);
