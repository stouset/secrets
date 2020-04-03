#![allow(unsafe_code)]

use crate::ffi::sodium;
use crate::traits::*;

use std::cell::Cell;
use std::fmt::{self, Debug};
use std::ptr::NonNull;
use std::slice;
use std::thread;

/// The page protection applied to the memory underlying a [`Box`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Prot {
    /// Any attempt to read, write, or execute this memory will result
    /// in a segfault.
    NoAccess,

    /// Any attempt to write to or execute the contents of this memory
    /// will result in a segfault. Reads are permitted.
    ReadOnly,

    /// Any attempt to execute the contents of this memory will result
    /// in a segfault. Reads and writes are permitted.
    ReadWrite,
}

/// The type used for storing ref counts. Overflowing this type by
/// borrowing too many times will cause a runtime panic. It seems
/// implausible that there would be many legitimate use-cases where
/// someone needs more than 255 simultaneous borrows of secret data.
///
/// TODO: Perhaps this could be moved to an associated type on a trait,
/// such that a user who did need a larger value could provide a
/// larger replacement.
type RefCount = u8;

/// NOTE: This implementation is not meant to be exposed directly to
/// end-users, and user-facing wrappers must be written with care to
/// ensure they statically enforce the required invariants. These
/// invariants are asserted with `debug_assert` in order to catch bugs
/// at development-time, but these assertions will be compiled out in
/// release-mode due to the expectation that they are enforced
/// statically.
///
/// TODO: document invariants
#[derive(Eq)]
pub(crate) struct Box<T: Bytes> {
    /// the non-null pointer to the underlying protected memory
    ptr: NonNull<T>,

    /// the number of elements of `T` that can be stored in `ptr`
    len: usize,

    /// the pointer's current protection level
    prot: Cell<Prot>,

    /// the number of outstanding borrows; mutable borrows are tracked
    /// here even though there is a max of one, so that asserts can
    /// ensure invariants are obeyed
    refs: Cell<RefCount>,
}

impl<T: Bytes> Box<T> {
    /// Instantiates a new [`Box`] that can hold `len` elements of type
    /// `T`. The callback `F` will be used for initialization and will
    /// be called with a mutable reference to the unlocked [`Box`]. The
    /// [`Box`] will be locked before it is returned from this function.
    pub(crate) fn new<F>(len: usize, init: F) -> Self
    where
        F: FnOnce(&mut Self),
    {
        let mut boxed = Self::new_unlocked(len);

        proven!(boxed.ptr != std::ptr::NonNull::dangling());
        proven!(boxed.len == len);

        init(&mut boxed);

        boxed.lock();
        boxed
    }

    /// Instantiates a new [`Box`] that can hold `len` elements of type
    /// `T`. The callback `F` will be used for initialization and will
    /// be called with a mutable reference to the unlocked [`Box`]. This
    /// callback must return a [`Result`] indicating whether or not the
    /// initialization succeeded (the [`Ok`] value is ignored). The
    /// [`Box`] will be locked before it is returned from this function.
    pub(crate) fn try_new<U, E, F>(len: usize, init: F) -> Result<Self, E>
    where
        F: FnOnce(&mut Self) -> Result<U, E>
    {
        let mut boxed = Self::new_unlocked(len);

        proven!(boxed.ptr != std::ptr::NonNull::dangling());
        proven!(boxed.len == len);

        let result = init(&mut boxed);

        boxed.lock();

        result.map(|_| boxed)
    }

    /// Returns the number of elements in the [`Box`].
    pub(crate) fn len(&self) -> usize {
        self.len
    }

    /// Returns true if the [`Box`] is empty.
    pub(crate) fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// Returns the size in bytes of the data contained in the [`Box`].
    /// This does not include incidental metadata used in the
    /// implementation of [`Box`] itself, only the size of the data
    /// allocated on behalf of the user.
    ///
    /// It is the maximum number of bytes that can be read from the
    /// internal pointer.
    pub(crate) fn size(&self) -> usize {
        self.len * T::size()
    }

    /// Allows the contents of the [`Box`] to be read from. Any call to
    /// this function *must* be balanced with a call to
    /// [`lock`](Box::lock). Mirroring Rust's borrowing rules, there may
    /// be any number of outstanding immutable unlocks (technically,
    /// limited by the max value of [`RefCount`]) *or* one mutable
    /// unlock.
    pub(crate) fn unlock(&self) -> &Self {
        self.retain(Prot::ReadOnly);
        self
    }

    /// Allows the contents of the [`Box`] to be read from and written
    /// to. Any call to this function *must* be balanced with a call to
    /// [`lock`](Box::lock). Mirroring Rust's borrowing rules, there may
    /// be any number of outstanding immutable unlocks (technically,
    /// limited by the max value of [`RefCount`]) *or* one mutable
    /// unlock.
    pub(crate) fn unlock_mut(&mut self) -> &mut Self {
        self.retain(Prot::ReadWrite);
        self
    }

    /// Disables all access to the underlying memory. Must only be
    /// called to precisely balance prior calls to [`unlock`](Box::unlock)
    /// and [`unlock_mut`](Box::unlock_mut).
    ///
    /// Calling this method in excess of the number of outstanding
    /// unlocks will result in a runtime panic. Omitting a call to this
    /// method and leaving an outstanding unlock will result in a
    /// runtime panic when this object is dropped.
    pub(crate) fn lock(&self) {
        self.release()
    }

    /// Converts the [`Box`]'s contents into a reference. This must only
    /// happen while it is unlocked, and the reference must go out of
    /// scope before it is locked.
    ///
    /// Panics if `len == 0`, in which case it would be unsafe to
    /// dereference the internal pointer.
    pub(crate) fn as_ref(&self) -> &T {
        // we use never! here to ensure that panics happen in both debug
        // and release builds since it would be a violation of memory-
        // safety if a zero-length dereference happens
        never!(self.is_empty(),
            "secrets: attempted to dereference a zero-length pointer");

        proven!(self.prot.get() != Prot::NoAccess,
            "secrets: may not call Box::as_ref while locked");

        unsafe { self.ptr.as_ref() }
    }

    /// Converts the [`Box`]'s contents into a mutable reference. This
    /// must only happen while it is mutably unlocked, and the slice
    /// must go out of scope before it is locked.
    ///
    /// Panics if `len == 0`, in which case it would be unsafe to
    /// dereference the internal pointer.
    pub(crate) fn as_mut(&mut self) -> &mut T {
        // we use never! here to ensure that panics happen in both debug
        // and release builds since it would be a violation of memory-
        // safety if a zero-length dereference happens
        never!(self.is_empty(),
            "secrets: attempted to dereference a zero-length pointer");

        proven!(self.prot.get() == Prot::ReadWrite,
            "secrets: may not call Box::as_mut unless mutably unlocked");

        unsafe { self.ptr.as_mut() }
    }

    /// Converts the [`Box`]'s contents into a slice. This must only
    /// happen while it is unlocked, and the slice must go out of scope
    /// before it is locked.
    pub(crate) fn as_slice(&self) -> &[T] {
        // NOTE: after some consideration, I've decided that this method
        // and its as_mut_slice() sister *are* safe.
        //
        // Using the retuned ref might cause a SIGSEGV, but this is not
        // UB (in fact, it's explicitly defined behavior!), cannot cause
        // a data race, cannot produce an invalid primitive, nor can it
        // break any other guarantee of "safe Rust". Just a SIGSEGV.
        //
        // However, as currently used by wrappers in this crate, these
        // methods are *never* called on unlocked data. Doing so would
        // be indicative of a bug, so we want to detect this during
        // development. If it happens in release mode, it's not
        // explicitly unsafe so we don't need to enable this check.
        proven!(self.prot.get() != Prot::NoAccess,
            "secrets: may not call Box::as_slice while locked");

        unsafe {
            slice::from_raw_parts(
                self.ptr.as_ptr(),
                self.len,
            )
        }
    }

    /// Converts the [`Box`]'s contents into a mutable slice. This must
    /// only happen while it is mutably unlocked, and the slice must go
    /// out of scope before it is locked.
    pub(crate) fn as_mut_slice(&mut self) -> &mut [T] {
        proven!(self.prot.get() == Prot::ReadWrite,
            "secrets: may not call Box::as_mut_slice unless mutably unlocked");

        unsafe {
            slice::from_raw_parts_mut(
                self.ptr.as_ptr(),
                self.len,
            )
        }
    }

    /// Instantiates a new [`Box`] that can hold `len` elements of type
    /// `T`. This [`Box`] will be unlocked and *must* be locked before
    /// it is dropped.
    ///
    /// TODO: make `len` a `NonZero` when it's stabilized and remove the
    /// related panic.
    fn new_unlocked(len: usize) -> Self {
        tested!(len == 0);
        tested!(std::mem::size_of::<T>() == 0);

        if !sodium::init() {
            panic!("secrets: failed to initialize libsodium");
        }

        // `sodium::allocarray` returns a memory location that already
        // allows r/w access
        let ptr = NonNull::new(unsafe { sodium::allocarray::<T>(len) })
            .expect("secrets: failed to allocate memory");

        // NOTE: We technically could save a little extra work here by
        // initializing the struct with [`Prot::NoAccess`] and a zero
        // refcount, and manually calling `mprotect` when finished with
        // initialization. However, the `as_mut()` call performs sanity
        // checks that ensure it's [`Prot::ReadWrite`] so it's easier to
        // just send everything through the "normal" code paths.
        Self {
            ptr,
            len,
            prot: Cell::new(Prot::ReadWrite),
            refs: Cell::new(1),
        }
    }

    /// Performs the underlying retain half of the retain/release logic
    /// for monitoring outstanding calls to unlock.
    fn retain(&self, prot: Prot) {
        let refs = self.refs.get();

        tested!(refs == RefCount::min_value());
        tested!(refs == RefCount::max_value());
        tested!(prot == Prot::NoAccess);

        if refs == 0 {
            // when retaining, we must retain to a protection level with
            // some access
            proven!(prot != Prot::NoAccess,
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
            //   * our current protection level *must not* be
            //     [`Prot::NoAccess`] or we have underflowed the ref
            //     counter
            //   * our current protection level *must not* be
            //     [`Prot::ReadWrite`] because that would imply non-
            //     exclusive mutable access
            //   * our target protection level *must* be `ReadOnly`
            //     since otherwise would involve changing the protection
            //     level of a currently-borrowed resource
            proven!(Prot::NoAccess != self.prot.get(),
                "secrets: out-of-order retain/release detected");
            proven!(Prot::ReadWrite != self.prot.get(),
                "secrets: cannot unlock mutably more than once");
            proven!(Prot::ReadOnly == prot,
                "secrets: cannot unlock mutably while unlocked immutably");
        }

        // "255 retains ought to be enough for anybody"
        //
        // We use `checked_add` to ensure we don't overflow our ref
        // counter. This is ensured even in production builds because
        // it's infeasible for consumers of this API to actually enforce
        // this. That said, it's unlikely that anyone would need to
        // have more than 255 outstanding retains at one time.
        //
        // This also protects us in the event of balanced, out-of-order
        // retain/release code. If an out-of-order `release` causes the
        // ref counter to wrap around below zero, the subsequent
        // `retain` will panic here.
        match refs.checked_add(1) {
            Some(v)                  => self.refs.set(v),
            None if self.is_locked() => panic!("secrets: out-of-order retain/release detected"),
            None                     => panic!("secrets: retained too many times"),
        };
    }

    /// Removes one outsdanding retain, and changes the memory
    /// protection level back to [`Prot::NoAccess`] when the number of
    /// outstanding retains reaches zero.
    fn release(&self) {
        // When releasing, we should always have at least one retain
        // outstanding. This is enforced by all users through
        // refcounting on allocation and drop.
        proven!(self.refs.get() != 0,
            "secrets: releases exceeded retains");

        // When releasing, our protection level must allow some kind of
        // access. If this condition isn't true, it was already
        // [`Prot::NoAccess`] so at least the memory was protected.
        proven!(self.prot.get() != Prot::NoAccess,
            "secrets: releasing memory that's already locked");

        // Deciding whether or not to use `checked_sub` or
        // `wrapping_sub` here has pros and cons. The `proven!`s above
        // help us catch this kind of accident in development, but if
        // a released library has a bug that has imbalanced
        // retains/releases, `wrapping_sub` will cause the refcount to
        // underflow and wrap.
        //
        // `checked_sub` ensures that wrapping won't happen, but will
        // cause consistency issues in the event of balanced but
        // *out-of-order* calls to retain/release. In such a scenario,
        // this will cause the retain count to be nonzero at drop time,
        // leaving the memory unlocked for an indeterminate period of
        // time.
        //
        // We choose `wrapped_sub` here because, by undeflowing, it will
        // ensure that a subsequent `retain` will not unlock the memory
        // and will trigger a `checked_add` runtime panic which we find
        // preferable for safety purposes.
        let refs = self.refs.get().wrapping_sub(1);

        self.refs.set(refs);

        if refs == 0 {
            mprotect(self.ptr.as_ptr(), Prot::NoAccess);
            self.prot.set(Prot::NoAccess);
        }
    }

    /// Returns true if the protection level is [`NoAccess`]. Ignores
    /// ref count.
    fn is_locked(&self) -> bool {
        self.prot.get() == Prot::NoAccess
    }
}

impl<T: Bytes + Randomizable> Box<T> {
    /// Instantiates a new [`Box`] with crypotgraphically-randomized
    /// contents.
    pub(crate) fn random(len: usize) -> Self {
        Self::new(len, |b| b.as_mut_slice().randomize())
    }
}

impl<T: Bytes + Zeroable> Box<T> {
    /// Instantiates a new [`Box`] whose backing memory is zeroed.
    pub(crate) fn zero(len: usize) -> Self {
        Self::new(len, |b| b.as_mut_slice().zero())
    }
}

impl<T: Bytes> Drop for Box<T> {
    fn drop(&mut self) {
        // [`Drop::drop`] is called during stack unwinding, so we may be
        // in a panic already.
        if !thread::panicking() {
            // If this value is being dropped, we want to ensure that
            // every retain has been balanced with a release. If this
            // is not true in release, the memory will be freed
            // momentarily so we don't need to worry about it.
            proven!(self.refs.get() == 0,
                "secrets: retains exceeded releases");

            // Similarly, any dropped value should have previously been
            // set to deny any access.
            proven!(self.prot.get() == Prot::NoAccess,
                "secrets: dropped secret was still accessible");
        }

        unsafe { sodium::free(self.ptr.as_mut()) }
    }
}

impl<T: Bytes> Debug for Box<T> {
    fn fmt(&self, fmt: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(fmt, "{{ {} bytes redacted }}", self.size())
    }
}

impl<T: Bytes> Clone for Box<T> {
    fn clone(&self) -> Self {
        Self::new(self.len, |b| {
            b.as_mut_slice().copy_from_slice(self.unlock().as_slice());
            self.lock();
        })
    }
}

impl<T: Bytes + ConstantEq> PartialEq for Box<T> {
    fn eq(&self, other: &Self) -> bool {
        if self.len != other.len {
            return false;
        }

        let lhs = self.unlock().as_slice();
        let rhs = other.unlock().as_slice();

        let ret = lhs.constant_eq(rhs);

        self.lock();
        other.lock();

        ret
    }
}

impl<T: Bytes + Zeroable> From<&mut T> for Box<T> {
    fn from(data: &mut T) -> Self {
        // this is safe since the secret and data can never overlap
        Self::new(1, |b| unsafe { data.transfer(b.as_mut()) })
    }
}

impl<T: Bytes + Zeroable> From<&mut [T]> for Box<T> {
    fn from(data: &mut [T]) -> Self {
        // this is safe since the secret and data can never overlap
        Self::new(data.len(), |b| unsafe { data.transfer(b.as_mut_slice()) })
    }
}

unsafe impl<T: Bytes + Send> Send for Box<T> {}

/// Immediately changes the page protection level on `ptr` to `prot`.
fn mprotect<T>(ptr: *const T, prot: Prot) {
    if !match prot {
        Prot::NoAccess  => unsafe { sodium::mprotect_noaccess(ptr)  },
        Prot::ReadOnly  => unsafe { sodium::mprotect_readonly(ptr)  },
        Prot::ReadWrite => unsafe { sodium::mprotect_readwrite(ptr) },
    } {
        panic!("secrets: error setting memory protection to {:?}", prot);
    }
}

// LCOV_EXCL_START

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn it_allows_custom_initialization() {
        let boxed = Box::<u8>::new(1, |secret| {
            secret.as_mut_slice().clone_from_slice(b"\x04");
        });

        assert_eq!(boxed.unlock().as_slice(), [0x04]);
        boxed.lock();
    }

    #[test]
    fn it_initializes_with_garbage() {
        let boxed   = Box::<u8>::new(4, |_| {});
        let unboxed = boxed.unlock().as_slice();

        // sodium changed the value of the garbage byte they used, so we
        // allocate a byte and see what's inside to probe for the
        // specific value
        let garbage = unsafe {
            let garbage_ptr  = sodium::allocarray::<u8>(1);
            let garbage_byte = *garbage_ptr;

            sodium::free(garbage_ptr);

            vec![garbage_byte; unboxed.len()]
        };

        // sanity-check the garbage byte in case we have a bug in how we
        // probe for it
        assert_ne!(garbage, vec![0; garbage.len()]);
        assert_eq!(unboxed, &garbage[..]);

        boxed.lock();
    }

    #[test]
    fn it_initializes_with_zero() {
        let boxed = Box::<u32>::zero(4);

        assert_eq!(boxed.unlock().as_slice(), [0, 0, 0, 0]);
        boxed.lock();
    }

    #[test]
    fn it_initializes_from_values() {
        let mut value = [4_u64];
        let     boxed = Box::from(&mut value[..]);

        assert_eq!(value,                     [0]);
        assert_eq!(boxed.unlock().as_slice(), [4]);

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
    fn it_can_be_sent_between_threads() {
        use std::sync::mpsc;
        use std::thread;

        let (tx, rx) = mpsc::channel();

        let child = thread::spawn(move || {
            let boxed = Box::<u64>::random(1);
            let value = boxed.unlock().as_slice().to_vec();

            // here we send an *unlocked* Box to the rx side; this lets
            // us make sure that the sent Box isn't dropped when this
            // thread exits, and that the other thread gets an unlocked
            // Box that it's responsible for locking
            tx.send((boxed, value)).expect("failed to send to channel");
        });

        let (boxed, value) = rx.recv().expect("failed to read from channel");

        assert_eq!(Prot::ReadOnly, boxed.prot.get());
        assert_eq!(value,          boxed.as_slice());

        child.join().expect("child terminated");
        boxed.lock();
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

    #[test]
    #[should_panic(expected = "secrets: out-of-order retain/release detected")]
    fn it_detects_out_of_order_retains_and_releases_that_underflow() {
        let boxed = Box::<u8>::zero(5);

        // manually set up this condition, since doing it using the
        // wrappers will cause other panics to happen
        boxed.refs.set(boxed.refs.get().wrapping_sub(1));
        boxed.prot.set(Prot::NoAccess);

        boxed.retain(Prot::ReadOnly);
    }

    #[test]
    #[should_panic(expected = "secrets: failed to initialize libsodium")]
    fn it_detects_sodium_init_failure() {
        sodium::fail();
        let _ = Box::<u8>::zero(0);
    }


    #[test]
    #[should_panic(expected = "secrets: error setting memory protection to NoAccess")]
    fn it_detects_sodium_mprotect_failure() {
        sodium::fail();
        mprotect(std::ptr::null::<u8>(), Prot::NoAccess);
    }
}

#[cfg(test)]
mod tests_sigsegv {
    use super::*;
    use std::process;

    fn assert_sigsegv<F>(f: F)
    where
        F: FnOnce(),
    {
        unsafe {
            let pid      : libc::pid_t = libc::fork();
            let mut stat : libc::c_int = 0;

            match pid {
                -1 => panic!("`fork(2)` failed"),
                0  => { f(); process::exit(0) },
                _  => {
                    if libc::waitpid(pid, &mut stat, 0) == -1 {
                        panic!("`waitpid(2)` failed");
                    };

                    // assert that the process terminated due to a signal
                    assert!(libc::WIFSIGNALED(stat));

                    // assert that we received a SIGBUS or SIGSEGV,
                    // either of which can be sent by an attempt to
                    // access protected memory regions
                    assert!(
                        libc::WTERMSIG(stat) == libc::SIGBUS ||
                        libc::WTERMSIG(stat) == libc::SIGSEGV
                    );
                }
            }
        }
    }

    #[test]
    fn it_kills_attempts_to_read_while_locked() {
        assert_sigsegv(|| {
            let val = unsafe { Box::<u32>::zero(1).ptr.as_ptr().read() };

            // TODO: replace with [`test::black_box`] when stable
            let _ = sodium::memcmp(val.as_bytes(), val.as_bytes());
        });
    }

    #[test]
    fn it_kills_attempts_to_write_while_locked() {
        assert_sigsegv(|| {
            unsafe { Box::<u64>::zero(1).ptr.as_ptr().write(1) };
        });
    }

    #[test]
    fn it_kills_attempts_to_read_after_explicitly_locked() {
        assert_sigsegv(|| {
            let boxed = Box::<u32>::random(4);
            let val   = boxed.unlock().as_slice();
            let _     = boxed.unlock();

            boxed.lock();
            boxed.lock();

            let _ = sodium::memcmp(
                val.as_bytes(),
                val.as_bytes(),
            );
        })
    }
}

#[cfg(all(test, profile = "debug"))]
mod tests_proven_statements {
    use super::*;

    #[test]
    #[should_panic(expected = "secrets: attempted to dereference a zero-length pointer")]
    fn it_doesnt_allow_referencing_zero_length() {
        let boxed = Box::<u8>::new_unlocked(0);
        let _     = boxed.as_ref();
    }

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

    #[test]
    #[should_panic(expected = "secrets: may not call Box::as_ref while locked")]
    fn it_doesnt_allow_as_ref_while_locked() {
        let _ = Box::<u8>::zero(1).as_ref();
    }

    #[test]
    #[should_panic(expected = "secrets: may not call Box::as_mut unless mutably unlocked")]
    fn it_doesnt_allow_as_mut_while_locked() {
        let _ = Box::<u8>::zero(1).as_mut();
    }

    #[test]
    #[should_panic(expected = "secrets: may not call Box::as_mut unless mutably unlocked")]
    fn it_doesnt_allow_as_mut_while_readonly() {
        let mut boxed = Box::<u8>::zero(1);
        let _ = boxed.unlock();
        let _ = boxed.as_mut();
    }

    #[test]
    #[should_panic(expected = "secrets: may not call Box::as_slice while locked")]
    fn it_doesnt_allow_as_slice_while_locked() {
        let _ = Box::<u8>::zero(1).as_slice();
    }

    #[test]
    #[should_panic(expected = "secrets: may not call Box::as_mut_slice unless mutably unlocked")]
    fn it_doesnt_allow_as_mut_slice_while_locked() {
        let _ = Box::<u8>::zero(1).as_mut_slice();
    }

    #[test]
    #[should_panic(expected = "secrets: may not call Box::as_mut_slice unless mutably unlocked")]
    fn it_doesnt_allow_as_mut_slice_while_readonly() {
        let mut boxed = Box::<u8>::zero(1);
        let _ = boxed.unlock();
        let _ = boxed.as_mut_slice();
    }
}

// LCOV_EXCL_STOP
