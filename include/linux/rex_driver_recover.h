/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Rex driver-side panic recovery.
 *
 * rex_driver_protected_call() runs a function under a setjmp-style
 * recovery point: if a Rust panic fires inside it, the Rust-for-Linux
 * panic handler calls rex_driver_try_recover(), which longjmps back to
 * the protected-call site and makes it return -EIO instead of escalating
 * to BUG() (and, with panic_on_oops, a full kernel panic).
 *
 * This extends the Rex exception-handling idea (rex_dispatcher_func /
 * rex_landingpad for Rex extensions) to code in Rust *driver bodies*.
 * Differences from the extension path:
 *
 *   - no stack switch: driver code runs on the normal kernel stack in
 *     (possibly sleepable) process context, so the recovery point is
 *     per-task (current->rex_recovery_ctx), not per-CPU;
 *   - no resource ledger yet: values alive inside the protected region
 *     do NOT have their destructors run on recovery.  The caller must
 *     keep the region free of resource acquisition (locks, allocations,
 *     refcounts), or leak them.  A cleanup ledger integrated with the
 *     Rust-for-Linux RAII types is future work.
 *
 * Safety guards in rex_driver_try_recover():
 *   - only recovers in task context (never from irq/softirq/NMI);
 *   - refuses to recover if preempt_count or irq state changed since the
 *     recovery point was armed (a lock would be leaked) — the panic then
 *     falls through to BUG() as before.
 */
#ifndef _LINUX_REX_DRIVER_RECOVER_H
#define _LINUX_REX_DRIVER_RECOVER_H

#include <linux/types.h>

/*
 * Setjmp-style snapshot taken at the protected-call site.  The register
 * fields are written by asm (__rex_driver_protected_call) and must stay
 * at the head of the struct in this exact order; the bookkeeping fields
 * below them are written by the C wrapper.
 */
struct rex_driver_recovery_ctx {
	u64 rsp;
	u64 rbp;
	u64 rbx;
	u64 r12;
	u64 r13;
	u64 r14;
	u64 r15;
	/* context sanity checks, filled by rex_driver_protected_call() */
	u32 preempt_cnt;
	u32 irqs_disabled;
};

/*
 * Run func(arg) with a panic recovery point armed for the current task.
 * Returns func's return value, or -EIO if func panicked and the panic
 * was recovered.
 */
s64 rex_driver_protected_call(s64 (*func)(void *arg), void *arg);

/*
 * Called from the Rust-for-Linux panic handler before BUG().  If the
 * current task has a recovery point armed (and the guards pass), this
 * does not return; otherwise it returns and the panic escalates as
 * usual.
 */
void rex_driver_try_recover(void);

#endif /* _LINUX_REX_DRIVER_RECOVER_H */
