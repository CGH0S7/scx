/* SPDX-License-Identifier: GPL-2.0 */
/*
 * scx_hpc - HPC-dedicated scheduler for MPI/OpenMP scientific computing.
 *
 * Shared interface between BPF and userspace.
 */
#ifndef __INTF_H
#define __INTF_H

#define MAX(x, y) ((x) > (y) ? (x) : (y))
#define MIN(x, y) ((x) < (y) ? (x) : (y))

#ifndef __VMLINUX_H__
typedef unsigned char u8;
typedef unsigned short u16;
typedef unsigned int u32;
typedef unsigned long u64;
typedef signed char s8;
typedef signed short s16;
typedef signed int s32;
typedef signed long s64;
typedef int pid_t;
#endif /* __VMLINUX_H__ */

enum hpc_consts {
	MAX_CPUS		= 1024,
	MAX_NUMA_NODES		= 64,
	MAX_HPC_TGIDS		= 4096,
	MAX_COMM_PREFIXES	= 16,
	COMM_PREFIX_LEN		= 16,

	/* DSQ for service core tasks (fair scheduling) */
	SERVICE_DSQ		= 0,

	/* Time constants */
	MSEC_PER_SEC		= 1000LLU,
	USEC_PER_MSEC		= 1000LLU,
	NSEC_PER_USEC		= 1000LLU,
	NSEC_PER_MSEC		= USEC_PER_MSEC * NSEC_PER_USEC,
	USEC_PER_SEC		= USEC_PER_MSEC * MSEC_PER_SEC,
	NSEC_PER_SEC		= NSEC_PER_USEC * USEC_PER_SEC,
};

/*
 * Task classification.
 */
enum task_class {
	TASK_CLASS_SERVICE	= 0,
	TASK_CLASS_HPC		= 1,
};

/*
 * Argument for syscall programs that configure CPU masks.
 */
struct cpu_arg {
	s32 cpu_id;
};

/*
 * Argument for registering/unregistering HPC tgids.
 */
struct tgid_arg {
	s32 tgid;
};

#endif /* __INTF_H */
