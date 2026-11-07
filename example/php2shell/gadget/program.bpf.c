// Maintainer: Constanze Roedig <constanze.roedig@gmail.com>
// SPDX-License-Identifier: Apache-2.0
//
// php2shell UAF inspector gadget (Inspektor Gadget, image-based).
// Catches the php2shell (CVE-2026-109618 / CVE-2026-109619) use-after-free at
// the moment it reaches code execution: a uprobe on libphp zif_system (PHP core
// system()). The target app has no system/exec sink and benign PHP reaches
// zif_system only from the VM dispatch, so ANY hit here is the forged
// pDestructor firing = UAF exploited, BEFORE /bin/sh forks (strictly earlier and
// more specific than the R0001/R1505 process-spawn signals).
#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

#include <gadget/buffer.h>
#include <gadget/macros.h>
#include <gadget/mntns.h>
#include <gadget/types.h>

#define TASK_COMM_LEN 16

struct event {
	gadget_mntns_id mntns_id;
	__u32 pid;
	__u32 tid;
	__u32 uid;
	__u64 execute_data; // arg0 of zif_system = the forged zend_execute_data*
	char comm[TASK_COMM_LEN];
};

GADGET_TRACER_MAP(events, 1024 * 256);
GADGET_TRACER(uaf, events, event);

SEC("uprobe//usr/lib/apache2/modules/libphp.so:zif_system")
int BPF_UPROBE(trace_zif_system, void *execute_data)
{
	struct event *event;
	__u64 id = bpf_get_current_pid_tgid();

	event = gadget_reserve_buf(&events, sizeof(*event));
	if (!event)
		return 0;

	event->mntns_id = gadget_get_current_mntns_id();
	event->pid = id >> 32;
	event->tid = (__u32)id;
	event->uid = (__u32)bpf_get_current_uid_gid();
	event->execute_data = (__u64)execute_data;
	bpf_get_current_comm(&event->comm, sizeof(event->comm));

	gadget_submit_buf(ctx, &events, event, sizeof(*event));
	return 0;
}

char LICENSE[] SEC("license") = "GPL";
