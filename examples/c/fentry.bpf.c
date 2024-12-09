// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
/* Copyright (c) 2021 Sartura */
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

char LICENSE[] SEC("license") = "Dual BSD/GPL";

// fentry/fexit 对 do_sys_openat2
SEC("fentry/do_sys_openat2")
int do_sys_openat2_entry(struct pt_regs *ctx)
{
	pid_t pid = bpf_get_current_pid_tgid() >> 32;
	int dfd = (int)PT_REGS_PARM1(ctx);
	const struct filename *filename = (const struct filename *)PT_REGS_PARM2(ctx);
	struct open_how *how = (struct open_how *)PT_REGS_PARM3(ctx);

	if (filename) {
		bpf_printk("open: pid = %d, filename = %s\n", pid, filename->name);
	} else {
		bpf_printk("open: pid = %d, filename = (null)\n", pid);
	}

	return 0;
}

SEC("fexit/do_sys_openat2")
int do_sys_openat2_exit(struct pt_regs *ctx)
{
	pid_t pid = bpf_get_current_pid_tgid() >> 32;
	int dfd = (int)PT_REGS_PARM1(ctx);
	const struct filename *filename = (const struct filename *)PT_REGS_PARM2(ctx);
	struct open_how *how = (struct open_how *)PT_REGS_PARM3(ctx);
	long ret = PT_REGS_RC(ctx);

	if (filename) {
		bpf_printk("open_exit: pid = %d, filename = %s, ret = %ld\n", pid, filename->name,
			   ret);
	} else {
		bpf_printk("open_exit: pid = %d, filename = (null), ret = %ld\n", pid, ret);
	}

	return 0;
}

// fentry/fexit 对 ksys_read
SEC("fentry/ksys_read")
int ksys_read_entry(struct pt_regs *ctx)
{
	pid_t pid = bpf_get_current_pid_tgid() >> 32;
	unsigned int fd = (unsigned int)PT_REGS_PARM1(ctx);
	char *buf = (char *)PT_REGS_PARM2(ctx);
	size_t count = (size_t)PT_REGS_PARM3(ctx);

	bpf_printk("read: pid = %d, fd = %d, count = %lu\n", pid, fd, (unsigned long)count);
	return 0;
}

SEC("fexit/ksys_read")
int ksys_read_exit(struct pt_regs *ctx)
{
	pid_t pid = bpf_get_current_pid_tgid() >> 32;
	unsigned int fd = (unsigned int)PT_REGS_PARM1(ctx);
	long ret = PT_REGS_RC(ctx);

	bpf_printk("read_exit: pid = %d, fd = %d, ret = %ld\n", pid, fd, ret);
	return 0;
}

// fentry/fexit 对 ksys_write
SEC("fentry/ksys_write")
int ksys_write_entry(struct pt_regs *ctx)
{
	pid_t pid = bpf_get_current_pid_tgid() >> 32;
	unsigned int fd = (unsigned int)PT_REGS_PARM1(ctx);
	char *buf = (char *)PT_REGS_PARM2(ctx);
	size_t count = (size_t)PT_REGS_PARM3(ctx);

	bpf_printk("write: pid = %d, fd = %d, count = %lu\n", pid, fd, (unsigned long)count);
	return 0;
}

SEC("fexit/ksys_write")
int ksys_write_exit(struct pt_regs *ctx)
{
	pid_t pid = bpf_get_current_pid_tgid() >> 32;
	unsigned int fd = (unsigned int)PT_REGS_PARM1(ctx);
	long ret = PT_REGS_RC(ctx);

	bpf_printk("write_exit: pid = %d, fd = %d, ret = %ld\n", pid, fd, ret);
	return 0;
}

// fentry/fexit 对 ksys_close
SEC("fentry/ksys_close")
int ksys_close_entry(struct pt_regs *ctx)
{
	pid_t pid = bpf_get_current_pid_tgid() >> 32;
	unsigned int fd = (unsigned int)PT_REGS_PARM1(ctx);

	bpf_printk("close: pid = %d, fd = %d\n", pid, fd);
	return 0;
}

SEC("fexit/ksys_close")
int ksys_close_exit(struct pt_regs *ctx)
{
	pid_t pid = bpf_get_current_pid_tgid() >> 32;
	unsigned int fd = (unsigned int)PT_REGS_PARM1(ctx);
	long ret = PT_REGS_RC(ctx);

	bpf_printk("close_exit: pid = %d, fd = %d, ret = %ld\n", pid, fd, ret);
	return 0;
}
