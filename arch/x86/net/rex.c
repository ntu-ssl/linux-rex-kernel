/* SPDX-License-Identifier: GPL-2.0 */
/*
 * X86-specific code for Rex support
 */
#define pr_fmt(fmt) "rex: " fmt

#include <linux/bpf.h>
#include <linux/compiler_types.h>
#include <linux/module.h>
#include <linux/objtool.h>
#include <linux/percpu.h>
#include <linux/printk.h>
#include <linux/vmalloc.h>

#include <asm/page.h>
#include <asm/pgtable.h>
#include <asm/rex.h>

/* Align to page size, since the stack trace is broken anyway */
struct rex_stack {
	char stack[REX_STACK_SIZE];
} __aligned(PAGE_SIZE);

DEFINE_PER_CPU_PAGE_ALIGNED(struct rex_stack, rex_stack_backing_store)
__visible;
DEFINE_PER_CPU(void *, rex_stack_ptr);

DECLARE_PER_CPU(const struct bpf_prog *, rex_curr_prog);

/*
 * Not supposed to be called by other kernel code, therefore keep prototype
 * private
 */
void rex_landingpad(void) __noreturn;

static int map_rex_stack(unsigned int cpu)
{
	char *stack = (char *)per_cpu_ptr(&rex_stack_backing_store, cpu);
	struct page *pages[REX_STACK_SIZE / PAGE_SIZE];
	void *va;
	int i;

	for (i = 0; i < REX_STACK_SIZE / PAGE_SIZE; i++) {
		phys_addr_t pa = per_cpu_ptr_to_phys(stack + (i << PAGE_SHIFT));

		pages[i] = pfn_to_page(pa >> PAGE_SHIFT);
	}

	va = vmap(pages, REX_STACK_SIZE / PAGE_SIZE, VM_MAP, PAGE_KERNEL);
	if (!va)
		return -ENOMEM;

	/* Store actual TOS to avoid adjustment in the hotpath */
	per_cpu(rex_stack_ptr, cpu) = va + REX_STACK_SIZE - 8;

	pr_info("Initialize rex_stack on CPU %d at 0x%llx\n", cpu,
		((u64)va) + REX_STACK_SIZE);

	return 0;
}

int arch_init_rex_stack(void)
{
	int i, ret = 0;
	for_each_online_cpu(i) {
		ret = map_rex_stack(i);
		if (ret < 0) {
			pr_err("Failed to initialize rex stack on CPU %d\n", i);
			break;
		}
	}
	return ret;
}

/* Do not declare rex_landingpad_asm() in header file since it should only be
 * called from rex_landingpad() 
 */
asmlinkage void __noreturn rex_landingpad_asm(void);

void __noreturn rex_landingpad(void)
{
	struct task_struct *loader;
	DEFINE_RATELIMIT_STATE(rex_rs, DEFAULT_RATELIMIT_INTERVAL,
			       DEFAULT_RATELIMIT_BURST);

	/* Report error */
	if (__ratelimit(&rex_rs)) {
		pr_err("%s\n", this_cpu_ptr(rex_log_buf));
		dump_stack();
	}

	loader = find_task_by_pid_ns(
		this_cpu_read_stable(rex_curr_prog)->saved_state->loader_pid,
		&init_pid_ns);

	/* Reuse the seccomp signal for now */
	if (loader)
		force_sig_fault_to_task(SIGSYS, SYS_SECCOMP, NULL, loader);

	/* Reset the rex_termination_state set in rex panic handler */
	this_cpu_write(rex_termination_state, 0);

	/* Handle the rest fixups */
	rex_landingpad_asm();
}

/*
 * ── Driver-side panic recovery ──────────────────────────────────────
 *
 * See include/linux/rex_driver_recover.h for the design.  The asm
 * halves live in rex_64.S; this file owns the per-task arming and the
 * safety guards.
 */
#include <linux/preempt.h>
#include <linux/rex_driver_recover.h>
#include <linux/sched.h>

/* Errno a recovered (panicked) protected call returns. */
#define REX_DRIVER_RECOVER_ERRNO (-EIO)

asmlinkage s64 __rex_driver_protected_call(s64 (*func)(void *arg), void *arg,
					   struct rex_driver_recovery_ctx *ctx);
asmlinkage void __noreturn
rex_driver_recovery_landing(struct rex_driver_recovery_ctx *ctx, s64 retval);

noinline s64 rex_driver_protected_call(s64 (*func)(void *arg), void *arg)
{
	struct rex_driver_recovery_ctx ctx, *old;
	s64 ret;

	ctx.preempt_cnt = preempt_count();
	ctx.irqs_disabled = irqs_disabled();

	/* Arm; keep any outer recovery point so calls can nest. */
	old = current->rex_recovery_ctx;
	current->rex_recovery_ctx = &ctx;

	ret = __rex_driver_protected_call(func, arg, &ctx);

	current->rex_recovery_ctx = old;
	return ret;
}
EXPORT_SYMBOL_GPL(rex_driver_protected_call);

void rex_driver_try_recover(void)
{
	struct rex_driver_recovery_ctx *ctx = current->rex_recovery_ctx;

	if (!ctx)
		return;

	/*
	 * Only recover a panic raised in task context.  A panic in an
	 * interrupt that happens to hit while this task has a recovery
	 * point armed belongs to the interrupted context, not to the
	 * protected call.
	 */
	if (!in_task())
		return;

	/*
	 * The longjmp skips every cleanup between the panic site and the
	 * protected-call site.  If the region took a lock or disabled
	 * interrupts, "recovering" would leak that state and wedge the
	 * system later; refuse and let the panic escalate to BUG().
	 */
	if (preempt_count() != ctx->preempt_cnt ||
	    (u32)irqs_disabled() != ctx->irqs_disabled) {
		pr_err("driver recovery refused: atomic state changed inside protected region (preempt %u->%u, irqs_disabled %u->%u)\n",
		       ctx->preempt_cnt, preempt_count(),
		       ctx->irqs_disabled, (u32)irqs_disabled());
		return;
	}

	/* One-shot: disarm before leaving the panic context. */
	current->rex_recovery_ctx = NULL;

	pr_warn("recovered Rust driver panic in %s[%d]; protected call returns %d\n",
		current->comm, task_pid_nr(current), REX_DRIVER_RECOVER_ERRNO);

	rex_driver_recovery_landing(ctx, REX_DRIVER_RECOVER_ERRNO);
}
EXPORT_SYMBOL_GPL(rex_driver_try_recover);
