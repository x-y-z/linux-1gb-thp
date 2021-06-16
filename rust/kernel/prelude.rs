// SPDX-License-Identifier: GPL-2.0

//! The `kernel` prelude.
//!
//! These are most common items used by Rust code in the kernel, intended to
//! be imported by all Rust code, for convenience.
//!
//! # Examples
//!
//! ```rust,no_run
//! use kernel::prelude::*;
//! ```

pub use alloc::{borrow::ToOwned, string::String};

pub use module::{module, module_misc_device};

pub use super::{pr_alert, pr_cont, pr_crit, pr_emerg, pr_err, pr_info, pr_notice, pr_warn};

pub use super::static_assert;

pub use super::{KernelModule, KernelResult};
