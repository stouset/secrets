use sodium::*;

use std::{cell, uint};
use libc::{c_void, size_t};

pub struct SecretPointer {
    /// A C pointer to a memory location suitable for the storage of
    /// cryptographic secrets.
    ptr: *mut c_void,

    /// The number of live references to the contents of the
    /// `SecretPointer`. When the ref count drops to zero, the memory is
    /// reprotected.
    refs: cell::Cell<uint>,

    /// The current level of access granted to the pointer.
    prot: cell::Cell<Protection>,
}

impl SecretPointer {
    /// Allocates memory for a pointer of the given length. When this
    /// function returns, this memory is `mprotect`ed such that it
    /// cannot be read from or written to. It is also `mlock`ed to
    /// prevent being swapped to disk.
    pub fn alloc(len: size_t) -> SecretPointer {
        init();

        SecretPointer {
            ptr:  unsafe { alloc(len) },
            refs: cell::Cell::new(0u),
            prot: cell::Cell::new(Protection::NoAccess),
        }
    }

    /// The current page-protection of the underlying pointer.
    #[cfg(test)]
    pub fn prot(&self) -> Protection {
        self.prot.get()
    }

    #[cfg(test)]
    /// The number of outstanding references to the underlying pointer.
    pub fn refs(&self) -> uint {
        self.refs.get()
    }

    /// Requests a copy of the internal pointer with a specific access
    /// level and increases the ref count.
    ///
    /// Each `retain` *must* be paired with a corresponding `release`;
    /// when the ref count hits zero, the memory is re-`mprotect`ed to
    /// be inaccessible. Panics if going directly from any
    /// non-NoAccess protection level to another non-NoAccess
    /// protection level, because we don't want to change the
    /// `mprotect` level of a pointer someone else might still have
    /// access to.
    pub fn retain(&self, prot: Protection) -> *mut c_void {
        let refs = self.refs.get() + 1;

        self.protect(prot);
        self.refs.set(refs);

        self.ptr
    }

    /// Manually releases access to the SecretPointer and decreases
    /// the ref count. If the ref count goes below zero, panics.
    pub fn release(&self) {
        let refs = self.refs.get() - 1;

        // technically this can also happen if we just call retain
        // 2^64 times, though something tells me this won't ever
        // happen in practice
        if refs == uint::MAX {
            panic!("released a SecretPointer that was not retained");
        }

        if refs == 0 {
            self.protect(Protection::NoAccess);
        }

        self.refs.set(refs);
    }

    /// Changes the protection level on the underlying pointer. Panics
    /// if we try to change directly between two non-NoAccess levels.
    fn protect(&self, prot: Protection) {
        let current = self.prot.get();

        // short-circuit if we're already at the same protection level
        if current == prot {
            return;
        }

        // disallow everything except NoAccess => access, or access =>
        // NoAccess (either the requested protection or the current
        // protection should be NoAccess)
        if prot != Protection::NoAccess && current != Protection::NoAccess {
            panic!("secret is already unlocked for {}", current);
        }

        unsafe { protect(self.ptr, prot) };

        self.prot.set(prot);
    }
}

impl Drop for SecretPointer {
    /// Sanitizes and frees the memory located at the pointer. Panics
    /// if the ref count isn't zero.
    fn drop(&mut self) {
        if self.refs.get() != 0 {
            panic!("secrets bug: retained SecretPointer was dropped")
        }

        unsafe { free(self.ptr) };
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use sodium::Protection;
    use std::finally::Finally;

    #[test]
    #[should_fail(expected = "secret is already unlocked for ReadOnly")]
    fn test_no_switching_read_to_write() {
        let ptr = SecretPointer::alloc(12);

        (|&mut:| {
            ptr.retain(Protection::ReadOnly);
            ptr.retain(Protection::ReadWrite);
        }).finally(|| {
            ptr.release();
        });
    }

    #[test]
    #[should_fail(expected = "secret is already unlocked for ReadWrite")]
    fn test_no_switching_write_to_read() {
        let ptr = SecretPointer::alloc(90);

        (|&mut:| {
            ptr.retain(Protection::ReadWrite);
            ptr.retain(Protection::ReadOnly);
        }).finally(|| {
            ptr.release();
        });
    }

    #[test]
    #[should_fail(expected = "secrets bug: retained SecretPointer was dropped")]
    fn test_unmatched_retain() {
        let ptr = SecretPointer::alloc(42);

        ptr.retain(Protection::ReadOnly);
    }

    #[test]
    #[should_fail(expected = "released a SecretPointer that was not retained")]
    fn test_unmatched_release() {
        let ptr = SecretPointer::alloc(42);

        ptr.release();
    }
}
