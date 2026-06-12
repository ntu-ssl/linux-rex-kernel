// SPDX-License-Identifier: GPL-2.0

//! Rex driver-side panic recovery.
//!
//! [`protected_call`] runs a closure under a recovery point: if the
//! closure panics, the panic is unwound back to the call site (via
//! `rex_driver_try_recover()` in the kernel panic handler) and the call
//! returns `-EIO` instead of escalating to `BUG()`.
//!
//! This brings the Rex exception-handling idea to Rust *driver bodies*:
//! a latent panic in a driver file operation becomes a plain errno to
//! userspace rather than a kernel oops/panic.
//!
//! # Limitations (current prototype)
//!
//! - **No cleanup**: destructors of values alive inside the closure at
//!   panic time do *not* run.  Keep the protected region free of
//!   resource acquisition (locks, allocations, refcounts) or they leak.
//!   Integrating a cleanup ledger with the kernel RAII types is future
//!   work.
//! - The kernel side refuses to recover if `preempt_count` or the irq
//!   state changed inside the region (a lock would be leaked); the panic
//!   then escalates to `BUG()` as before.
//! - Recovery only triggers for panics raised in task context.

use crate::bindings;

/// Runs `f` with a panic recovery point armed for the current task.
///
/// Returns `f`'s return value on the normal path.  By convention `f`
/// returns a non-negative value on success and a negative errno on
/// failure; a recovered panic returns `-EIO`, so callers can funnel the
/// result through a single errno check.
///
/// See the module documentation for the safety limitations of the
/// protected region.
///
/// # Examples
///
/// ```ignore
/// let ret = kernel::rex_recover::protected_call(|| {
///     // fallible / panicky driver logic
///     0
/// });
/// if ret < 0 {
///     return Err(Error::from_errno(ret as i32));
/// }
/// ```
pub fn protected_call<F>(f: F) -> i64
where
    F: FnOnce() -> i64,
{
    extern "C" fn shim<F>(arg: *mut core::ffi::c_void) -> i64
    where
        F: FnOnce() -> i64,
    {
        // SAFETY: `arg` points at the `Option<F>` slot owned by the
        // enclosing `protected_call` frame, which outlives this call;
        // the trampoline invokes the shim exactly once.
        let f = unsafe { (*arg.cast::<Option<F>>()).take() };
        match f {
            Some(f) => f(),
            // Unreachable: the slot is always `Some` on entry.
            None => -(bindings::EINVAL as i64),
        }
    }

    let mut slot: Option<F> = Some(f);
    // SAFETY: `shim::<F>` matches the expected C signature and `slot`
    // lives across the whole call; the kernel trampoline passes the
    // pointer straight through to the shim on the same task.
    unsafe {
        bindings::rex_driver_protected_call(
            Some(shim::<F>),
            core::ptr::addr_of_mut!(slot).cast(),
        )
    }
}
