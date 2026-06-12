/* SPDX-License-Identifier: GPL-2.0 */
/*
 * X86 asm for Rex support
 */
#include <linux/export.h>
#include <linux/linkage.h>
#include <asm/errno.h>
#include <asm/nospec-branch.h>
#include <asm/percpu.h>

	.code64
	.section .text, "ax"

/*
 * Dispatcher func for Rex
 *
 * %rdi: ctx argument of the Rex program
 * %rsi: pointer to the Rex program struct
 * %rdx: fucntion pointer to the entry of the Rex program
 */
SYM_FUNC_START(rex_dispatcher_func)
	/* save the callee-saved registers and the frame pointer*/
	pushq %rbp
	pushq %rbx
	pushq %r12
	pushq %r13
	pushq %r14
	pushq %r15

	/* switch stack and save old rsp*/
	movq PER_CPU_VAR(rex_stack_ptr), %rbp
	movq %rsp, (%rbp)
	movq %rbp, %rsp

	/* record start time */
	movq jiffies(%rip), %r11
	movq %r11, PER_CPU_VAR(rex_prog_start_time)

	/* let the timer know we are in */
	movq %rsi, PER_CPU_VAR(rex_curr_prog)

	/* invoke bpf func */
	CALL_NOSPEC rdx

/* 
 * Exit path: rex_landingpad also redirects the control flow here
 *
 * %rax: program return value or default return value in case of a panic
 * %rsp: top entry of the Rex stack
 */
SYM_INNER_LABEL(rex_exit, SYM_L_GLOBAL)
	/* let the timer know we are out */
	movq $0, PER_CPU_VAR(rex_curr_prog)

	/* pop old stack pointer into rsp */
	popq %rsp

	/* restore the callee-saved registers and the frame pointer */
	popq %r15
	popq %r14
	popq %r13
	popq %r12
	popq %rbx
	popq %rbp

	/* return */
	RET
SYM_FUNC_END(rex_dispatcher_func)
EXPORT_SYMBOL(rex_dispatcher_func)

/*
 * Low-level fixups for Rust panics
 */
SYM_FUNC_START(rex_landingpad_asm)
	/* set an return value of 0 */
	movq $0, %rax

	/* reset stack */
	movq PER_CPU_VAR(rex_stack_ptr), %rsp

	/* jump to exit path */
	jmp rex_exit
SYM_FUNC_END(rex_landingpad_asm)
STACK_FRAME_NON_STANDARD(rex_landingpad_asm);

/*
 * Driver-side panic recovery (see include/linux/rex_driver_recover.h).
 *
 * Setjmp half of the trampoline:
 *
 * %rdi: function to protect: s64 (*func)(void *)
 * %rsi: opaque argument passed through to func
 * %rdx: pointer to struct rex_driver_recovery_ctx
 *
 * Saves the callee-saved register state (the resume point) into the ctx,
 * then calls func(arg).  On the normal path this returns func's return
 * value.  If func panics, rex_driver_try_recover() enters
 * rex_driver_recovery_landing below, which restores the saved state and
 * "returns" from here with the supplied errno in %rax.
 *
 * Unlike rex_dispatcher_func there is no stack switch: driver code runs
 * on the normal kernel stack in possibly-sleepable process context, so a
 * shared per-CPU stack cannot be used.
 */
SYM_FUNC_START(__rex_driver_protected_call)
	/* setjmp: %rsp points at our return address */
	movq %rsp,  0(%rdx)
	movq %rbp,  8(%rdx)
	movq %rbx, 16(%rdx)
	movq %r12, 24(%rdx)
	movq %r13, 32(%rdx)
	movq %r14, 40(%rdx)
	movq %r15, 48(%rdx)

	/* call func(arg) */
	movq %rdi, %rax
	movq %rsi, %rdi
	CALL_NOSPEC rax

	RET
SYM_FUNC_END(__rex_driver_protected_call)
STACK_FRAME_NON_STANDARD(__rex_driver_protected_call);

/*
 * Longjmp half: jumped into from rex_driver_try_recover() while the
 * panicking frames are still live below us on the stack.
 *
 * %rdi: pointer to struct rex_driver_recovery_ctx (the resume point)
 * %rsi: value to return from __rex_driver_protected_call (negative errno)
 *
 * Restoring %rsp discards every frame between the panic site and the
 * protected-call site; the final RET pops the return address saved at
 * __rex_driver_protected_call entry, resuming in
 * rex_driver_protected_call() as if func had returned normally.
 */
SYM_FUNC_START(rex_driver_recovery_landing)
	movq  0(%rdi), %rsp
	movq  8(%rdi), %rbp
	movq 16(%rdi), %rbx
	movq 24(%rdi), %r12
	movq 32(%rdi), %r13
	movq 40(%rdi), %r14
	movq 48(%rdi), %r15
	movq %rsi, %rax
	RET
SYM_FUNC_END(rex_driver_recovery_landing)
STACK_FRAME_NON_STANDARD(rex_driver_recovery_landing);
