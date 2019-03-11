#![allow(unsafe_code)]

use crate::ffi::sodium;
use crate::traits::*;

use std::cell::Cell;
use std::fmt::{self, Debug};
use std::thread;
use std::ptr::NonNull;
use std::slice;

// TODO: delete this when clippy fixes the bug warning on derived
// implementations of `Clone` and `Eq`
#[cfg_attr(feature = "cargo-clippy", allow(clippy::missing_const_for_fn))]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Prot {
    NoAccess,
    ReadOnly,
    ReadWrite,
}

///
/// NOTE: This implementation is not meant to be exposed directly to
/// end-users, and user-facing wrappers must be written with care to
/// ensure they statically enforce the required invariants. These
/// invariants are asserted with `debug_assert` in order to catch bugs
/// at development-time, but these assertions will be compiled out in
/// release-mode due to the expectation that they are enforced
/// statically.
///
/// TODO: document invariants
///
#[derive(Eq)]
pub(crate) struct Box<T: ByteValue> {
    ptr:  NonNull<T>,
    len:  usize,
    prot: Cell<Prot>,
    refs: Cell<u8>,
}

impl<T: ByteValue> Box<T> {
    unsafe fn _new<F>(len: usize, init: F) -> Self
        where F: FnOnce(&mut [T])
    {
        if !sodium::init() {
            panic!("secrets: failed to initialize libsodium");
        }

        let ptr = NonNull::new(sodium::allocarray::<T>(len))
            .expect("secrets: failed to allocate memory");

        let mut boxed = Self {
            ptr,
            len,

            // `sodium::allocarray` allocates memory read/write, so we'll
            // need to manually lock it after initialization
            prot: Cell::new(Prot::ReadWrite),
            refs: Cell::new(1),
        };

        init(boxed.as_mut());

        boxed.lock();
        boxed
    }

    pub(crate) fn len(&self) -> usize {
        self.len
    }

    pub(crate) fn is_empty(&self) -> bool {
        self.len == 0
    }

    pub(crate) fn size(&self) -> usize {
        self.len * T::size()
    }

    pub(crate) fn unlock(&self) -> &Self {
        self.retain(Prot::ReadOnly);
        self
    }

    pub(crate) fn unlock_mut(&mut self) -> &mut Self {
        self.retain(Prot::ReadWrite);
        self
    }

    pub(crate) fn lock(&self) {
        self.release()
    }

    fn retain(&self, prot: Prot) {
        let refs = self.refs.get();

        if refs == 0 {
            // when retaining, we must retain to a protection level with
            // some access
            debug_assert!(prot != Prot::NoAccess,
                "secrets: must retain readably or writably");

            // allow access to the pointer and record what level of
            // access is being permitted
            //
            // ordering probably doesn't matter here, but we set our
            // internal protection flag first so we never run the risk
            // of believing that memory is protected when it isn't
            self.prot.set(prot);
            mprotect(self.ptr.as_ptr(), prot);
        } else {
            // if we have a nonzero retain count, there is nothing to
            // change, but we can assert some invariants:
            //
            //   * our current protection level *must* be `ReadOnly`
            //     since `ReadWrite` would imply multiple writers and
            //     `NoAccess` would imply no readers/writers
            //   * our target protection level *must* be `ReadOnly`
            //     since otherwise would involve changing the protection
            //     level of a currently-borrowed resource
            debug_assert_eq!(self.prot.get(), Prot::ReadOnly,
                "secrets: cannot unlock mutably more than once");
            debug_assert_eq!(prot,            Prot::ReadOnly,
                "secrets: cannot unlock mutably while unlocked immutably");
        }

        // "255 retains ought to be enough for anybody"
        //
        // We use `checked_add` to ensure we don't overflow our ref
        // counter. This is ensured even in production builds because
        // it's infeasible for consumers of this API to actually enforce
        // this. That said, it's unlikely that anyone would need to
        // have more than 255 outstanding retains at one time.
        self.refs.set(
            refs.checked_add(1)
                .expect("secrets: retained too many times")
        );
    }

    fn release(&self) {
        // when releasing, we must have at least one retain and our
        // protection level must allow some kind of access
        debug_assert!(self.refs.get() != 0,
            "secrets: releases exceeded retains");
        debug_assert!(self.prot.get() != Prot::NoAccess,
            "secrets: locked memory region released");

        // `checked_sub` isn't necessary here since users should be
        // statically ensuring that retains and releases are balanced
        let refs = self.refs.get() - 1;

        self.refs.set(refs);

        if refs == 0 {
            mprotect(self.ptr.as_ptr(), Prot::NoAccess);
            self.prot.set(Prot::NoAccess);
        }
    }
}

impl<T: ByteValue + Uninitializable> Box<T> {
    pub(crate) fn new<F>(len: usize, init: F) -> Self
        where F: FnOnce(&mut [T])
    {
        unsafe { Self::_new(len, init) }
    }

    pub(crate) fn uninitialized(len: usize) -> Self {
        unsafe { Self::_new(len, |_| {}) }
    }
}

impl<T: ByteValue + Randomizable> Box<T> {
    pub(crate) fn random(len: usize) -> Self {
        unsafe { Self::_new(len, Randomizable::randomize) }
    }
}

impl<T: ByteValue + Zeroable> Box<T> {
     pub(crate) fn zero(len: usize) -> Self {
         unsafe { Self::_new(len, Zeroable::zero) }
     }
}

impl<T: ByteValue> Drop for Box<T> {
    fn drop(&mut self) {
        // if we're panicking and the stack is unwinding, we can't be
        // certain that the objects holding a reference to us have been
        // cleaned up correctly and changed our ref count
        if !thread::panicking() {
            // if this value is being dropped, we want to ensure that
            // every retain has been balanced with a release
            debug_assert_eq!(0,              self.refs.get(),
                "secrets: retains exceeded releases");
            debug_assert_eq!(Prot::NoAccess, self.prot.get(),
                "secrets: dropped secret was still accessible");
        }

        unsafe { sodium::free(self.ptr.as_mut()) }
    }
}

impl<T: ByteValue> Debug for Box<T> {
    fn fmt(&self, fmt: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(fmt, "{{ {} bytes redacted }}", self.size())
    }
}

impl<T: ByteValue> AsRef<[T]> for Box<T> {
    fn as_ref(&self) -> &[T] {
        unsafe { slice::from_raw_parts(self.ptr.as_ptr(), self.len) }
    }
}

impl<T: ByteValue> AsMut<[T]> for Box<T> {
    fn as_mut(&mut self) -> &mut [T] {
        unsafe { slice::from_raw_parts_mut(self.ptr.as_mut(), self.len) }
    }
}

impl<T: ByteValue> Clone for Box<T> {
    fn clone(&self) -> Self {
        unsafe {
            Self::_new(self.len, |s| {
                s.copy_from_slice(self.unlock().as_ref());
                self.lock();
            }
        }
    }
}

impl<T: ByteValue + ConstantEq> PartialEq for Box<T> {
    fn eq(&self, other: &Self) -> bool {
        if self.len != other.len {
            return false;
        }

        let lhs = self.unlock().as_ref();
        let rhs = other.unlock().as_ref();

        let ret = lhs.constant_eq(rhs);

        self.lock();
        other.lock();

        ret
    }
}

impl<T: ByteValue + Zeroable> From<&mut [T]> for Box<T> {
    fn from(data: &mut [T]) -> Self {
        // this is safe since the secret and data will never overlap
        unsafe { Self::_new(data.len(), |s| data.transfer(s)) }
    }
}

fn mprotect<T>(ptr: *const T, prot: Prot) {
    if !match prot {
        Prot::NoAccess  => unsafe { sodium::mprotect_noaccess(ptr)  },
        Prot::ReadOnly  => unsafe { sodium::mprotect_readonly(ptr)  },
        Prot::ReadWrite => unsafe { sodium::mprotect_readwrite(ptr) },
    } {
        panic!("secrets: error setting memory protection to {:?}", prot);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn it_allows_custom_initialization() {
        let boxed = Box::<u8>::new(1, |secret| {
            secret.clone_from_slice(b"\x04");
        });

        assert_eq!(boxed.unlock().as_ref(), b"\x04", );
        boxed.lock();
    }

    #[test]
    fn it_initializes_with_garbage() {
        let boxed = Box::<u8>::uninitialized(4);

        assert_eq!(boxed.unlock().as_ref(), b"\xdb\xdb\xdb\xdb");
        boxed.lock();
    }

    #[test]
    fn it_initializes_with_zero() {
        let boxed = Box::<u32>::zero(4);

        assert_eq!(boxed.unlock().as_ref(), [0, 0, 0, 0]);
        boxed.lock();
    }

    #[test]
    fn it_initializes_from_values() {
        let mut value = [4_u64];
        let     boxed = Box::from(&mut value[..]);

        assert_eq!(value,                   [0]);
        assert_eq!(boxed.unlock().as_ref(), [4]);

        boxed.lock();
    }

    #[test]
    fn it_compares_equality() {
        let boxed_1 = Box::<u8>::random(1);
        let boxed_2 = boxed_1.clone();

        assert_eq!(boxed_1, boxed_2);
        assert_eq!(boxed_2, boxed_1);
    }

    #[test]
    fn it_compares_inequality() {
        let boxed_1 = Box::<u128>::random(32);
        let boxed_2 = Box::<u128>::random(32);

        assert_ne!(boxed_1, boxed_2);
        assert_ne!(boxed_2, boxed_1);
    }

    #[test]
    fn it_compares_inequality_using_size() {
        let boxed_1 = Box::<u8>::from(&mut [0, 0, 0, 0][..]);
        let boxed_2 = Box::<u8>::from(&mut [0, 0, 0, 0, 0][..]);

        assert_ne!(boxed_1, boxed_2);
        assert_ne!(boxed_2, boxed_1);
    }

    #[test]
    fn it_initializes_with_zero_refs() {
        let boxed = Box::<u8>::zero(10);

        assert_eq!(0, boxed.refs.get());
    }

    #[test]
    fn it_tracks_ref_counts_accurately() {
        let mut boxed = Box::<u8>::random(10);

        let _ = boxed.unlock();
        let _ = boxed.unlock();
        let _ = boxed.unlock();
        assert_eq!(3, boxed.refs.get());

        boxed.lock(); boxed.lock(); boxed.lock();
        assert_eq!(0, boxed.refs.get());

        let _ = boxed.unlock_mut();
        assert_eq!(1, boxed.refs.get());

        boxed.lock();
        assert_eq!(0, boxed.refs.get());
    }

    #[test]
    fn it_doesnt_overflow_early() {
        let boxed = Box::<u64>::zero(4);

        for _ in 0..u8::max_value() {
            let _ = boxed.unlock();
        }

        for _ in 0..u8::max_value() {
            boxed.lock();
        }
    }

    #[test]
    fn it_allows_arbitrary_readers() {
        let     boxed = Box::<u8>::zero(1);
        let mut count = 0_u8;

        sodium::memrandom(count.as_mut_bytes());

        for _ in 0..count {
            let _ = boxed.unlock();
        }

        for _ in 0..count {
            boxed.lock()
        }
    }

    #[test]
    #[should_panic(expected = "secrets: retained too many times")]
    fn it_doesnt_allow_overflowing_readers() {
        let boxed = Box::<[u64; 8]>::zero(4);

        for _ in 0..=u8::max_value() {
            let _ = boxed.unlock();
        }

        // this ensures that we *don't* inadvertently panic if we
        // somehow made it through the above statement
        for _ in 0..boxed.refs.get() {
            boxed.lock()
        }
    }
}

#[cfg(test)]
mod tests_sigsegv {
    use super::*;
    use std::process;

    fn assert_sigsegv<F>(f: F) where F: FnOnce() {
        unsafe {
            let pid      : libc::pid_t = libc::fork();
            let mut stat : libc::c_int = 0;

            match pid {
                -1 => assert!(false, "`fork(2)` failed"),
                0  => { f(); process::exit(0) },
                _  => {
                    if libc::waitpid(pid, &mut stat, 0) == -1 {
                        assert!(false, "`waitpid(2) failed");
                    };

                    // assert that the process terminated due to a signal
                    assert!(libc::WIFSIGNALED(stat));

                    // assert that we received a SIGBUS or SIGSEGV,
                    // either of which can be sent by an attempt to
                    // access protected memory regions
                    assert!(
                        libc::WTERMSIG(stat) == 10 ||
                        libc::WTERMSIG(stat) == 11
                    );
                }
            }
        }
    }

    #[test]
    fn it_kills_attempts_to_read_while_locked() {
        assert_sigsegv(|| {
            let boxed = Box::<u64>::zero(4);
            let val : &[u64] = boxed.as_ref();

            let _ = sodium::memcmp(
                val.as_bytes(),
                val.as_bytes()
            );
        });
    }

    #[test]
    fn it_kills_attempts_to_write_while_locked() {
        assert_sigsegv(|| {
            let mut boxed = Box::<u64>::zero(4);
            let val : &mut [u64] = boxed.as_mut();

            val.swap(0, 1);
        });
    }

    #[test]
    fn it_kills_attempts_to_read_after_explicitly_locked() {
        assert_sigsegv(|| {
            let boxed = Box::<u32>::random(4);
            let val   = boxed.unlock().as_ref();
            let _     = boxed.unlock();

            boxed.lock();
            boxed.lock();

            let _ = sodium::memcmp(
                val.as_bytes(),
                val.as_bytes()
            );
        })
    }
}

#[cfg(all(test, debug_assertions))]
mod tests_debug_assertions {
    use super::*;

    #[test]
    #[should_panic(expected = "secrets: cannot unlock mutably more than once")]
    fn it_doesnt_allow_multiple_writers() {
        let mut boxed = Box::<u64>::zero(1);

        let _ = boxed.unlock_mut();
        let _ = boxed.unlock_mut();
    }

    #[test]
    #[should_panic(expected = "secrets: releases exceeded retains")]
    fn it_doesnt_allow_negative_users() {
        Box::<u64>::zero(10).lock();
    }

    #[test]
    #[should_panic(expected = "secrets: releases exceeded retains")]
    fn it_doesnt_allow_unbalanced_locking() {
        let boxed = Box::<u64>::zero(4);
        let _     = boxed.unlock();
        boxed.lock();
        boxed.lock();
    }

    #[test]
    #[should_panic(expected = "secrets: cannot unlock mutably while unlocked immutably")]
    fn it_doesnt_allow_different_access_types() {
        let mut boxed = Box::<[u128; 128]>::zero(5);

        let _ = boxed.unlock();
        let _ = boxed.unlock_mut();
    }

    #[test]
    #[should_panic(expected = "secrets: retains exceeded releases")]
    fn it_doesnt_allow_outstanding_readers() {
        let _ = Box::<u8>::zero(1).unlock();
    }

    #[test]
    #[should_panic(expected = "secrets: retains exceeded releases")]
    fn it_doesnt_allow_outstanding_writers() {
        let _ = Box::<u8>::zero(1).unlock_mut();
    }
}
