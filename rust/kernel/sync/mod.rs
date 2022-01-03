// SPDX-License-Identifier: GPL-2.0

//! Synchronisation primitives.
//!
//! This module contains the kernel APIs related to synchronisation that have been ported or
//! wrapped for usage by Rust code in the kernel and is shared by all of them.
//!
//! # Example
//!
//! ```no_run
//! # use kernel::prelude::*;
//! # use kernel::mutex_init;
//! # use kernel::sync::Mutex;
//! # use alloc::boxed::Box;
//! # use core::pin::Pin;
//! // SAFETY: `init` is called below.
//! let mut data = Pin::from(Box::new(unsafe { Mutex::new(0) }));
//! mutex_init!(data.as_mut(), "test::data");
//! *data.lock() = 10;
//! pr_info!("{}\n", *data.lock());
//! ```

use crate::{bindings, str::CStr};
use core::pin::Pin;

mod arc;
mod condvar;
mod guard;
mod locked_by;
mod mutex;
mod revocable_mutex;
mod seqlock;
mod spinlock;

pub use arc::{Ref, RefBorrow, UniqueRef};
pub use condvar::CondVar;
pub use guard::{CreatableLock, Guard, GuardMut, Lock};
pub use locked_by::LockedBy;
pub use mutex::Mutex;
pub use revocable_mutex::{RevocableMutex, RevocableMutexGuard};
pub use seqlock::{SeqLock, SeqLockReadGuard};
pub use spinlock::SpinLock;

/// Safely initialises an object that has an `init` function that takes a name and a lock class as
/// arguments, examples of these are [`Mutex`] and [`SpinLock`]. Each of them also provides a more
/// specialised name that uses this macro.
#[doc(hidden)]
#[macro_export]
macro_rules! init_with_lockdep {
    ($obj:expr, $name:literal) => {{
        static mut CLASS1: core::mem::MaybeUninit<$crate::bindings::lock_class_key> =
            core::mem::MaybeUninit::uninit();
        static mut CLASS2: core::mem::MaybeUninit<$crate::bindings::lock_class_key> =
            core::mem::MaybeUninit::uninit();
        let obj = $obj;
        let name = $crate::c_str!($name);
        // SAFETY: `CLASS1` and `CLASS2` are never used by Rust code directly; the C portion of the
        // kernel may change it though.
        #[allow(unused_unsafe)]
        unsafe {
            $crate::sync::NeedsLockClass::init(obj, name, CLASS1.as_mut_ptr(), CLASS2.as_mut_ptr())
        };
    }};
}

/// A trait for types that need a lock class during initialisation.
///
/// Implementers of this trait benefit from the [`init_with_lockdep`] macro that generates a new
/// class for each initialisation call site.
pub trait NeedsLockClass {
    /// Initialises the type instance so that it can be safely used.
    ///
    /// Callers are encouraged to use the [`init_with_lockdep`] macro as it automatically creates a
    /// new lock class on each usage.
    ///
    /// # Safety
    ///
    /// `key1` and `key2` must point to valid memory locations and remain valid until `self` is
    /// dropped.
    unsafe fn init(
        self: Pin<&mut Self>,
        name: &'static CStr,
        key1: *mut bindings::lock_class_key,
        key2: *mut bindings::lock_class_key,
    );
}

/// Reschedules the caller's task if needed.
pub fn cond_resched() -> bool {
    // SAFETY: No arguments, reschedules `current` if needed.
    unsafe { bindings::cond_resched() != 0 }
}
