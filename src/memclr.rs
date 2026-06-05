//! Best-effort memory zeroing for sensitive buffers.

use core::sync::atomic::{Ordering, compiler_fence};

/// Overwrites the given buffer with zeros. A compiler fence is inserted to
/// discourage the optimizer from eliding the writes. This mirrors gobottle's
/// `MemClr` helper and is best-effort, not a guarantee against all compiler or
/// hardware behavior.
pub fn mem_clr(buf: &mut [u8]) {
    for b in buf.iter_mut() {
        // Volatile-ish write through a black box to resist dead-store removal.
        unsafe_write_zero(b);
    }
    compiler_fence(Ordering::SeqCst);
}

#[inline(never)]
fn unsafe_write_zero(b: &mut u8) {
    *b = 0;
    compiler_fence(Ordering::SeqCst);
}

/// A guard that zeroes a heap buffer when dropped.
pub struct Zeroizing(pub Vec<u8>);

impl Drop for Zeroizing {
    fn drop(&mut self) {
        mem_clr(&mut self.0);
    }
}

impl core::ops::Deref for Zeroizing {
    type Target = [u8];
    fn deref(&self) -> &[u8] {
        &self.0
    }
}

impl Zeroizing {
    /// Wraps the given vector so it will be zeroed on drop.
    pub fn new(v: Vec<u8>) -> Self {
        Zeroizing(v)
    }
}
