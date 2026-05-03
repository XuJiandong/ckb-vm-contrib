//! Optimized BLAKE2b implementation for CKB-VM with Rust bindings.
//!
//! This crate provides a Rust interface to an optimized BLAKE2b implementation
//! designed for CKB-VM (RISC-V). It uses CKB's default personalization
//! `"ckb-default-hash"` via `ckb_blake2b_init`.
//!
//! # Example
//!
//! ```
//! use ckb_opt_blake2b::{Blake2b, blake2b};
//!
//! // One-shot hashing (64-byte output)
//! let hash = blake2b(b"hello world");
//! assert_eq!(hash.len(), 64);
//!
//! // Incremental hashing
//! let mut hasher = Blake2b::new();
//! hasher.update(b"hello ");
//! hasher.update(b"world");
//! let hash = hasher.finalize();
//! ```
//!
//! # Custom output length
//!
//! ```
//! use ckb_opt_blake2b::Blake2b;
//!
//! let mut hasher = Blake2b::with_output_len(32);
//! hasher.update(b"hello world");
//! let hash = hasher.finalize();
//! assert_eq!(hash.len(), 32);
//! ```

#![no_std]

pub const BLAKE2B_BLOCK_SIZE: usize = 128;
pub const BLAKE2B_OUT_SIZE: usize = 64;
pub const BLAKE2B_PERSONAL_SIZE: usize = 16;

mod ffi {
    use core::ffi::{c_int, c_uchar, c_ulonglong};

    #[repr(C)]
    pub struct Blake2bCtx {
        pub h: [c_ulonglong; 8],
        pub t: [c_ulonglong; 2],
        pub f: [c_ulonglong; 2],
        pub buf: [c_uchar; 128],
        pub buflen: c_ulonglong,
        pub outlen: c_ulonglong,
        pub last_node: c_uchar,
    }

    extern "C" {
        pub fn ckb_blake2b_init(ctx: *mut Blake2bCtx, outlen: c_ulonglong) -> c_int;
        pub fn ckb_blake2b_init_personal(ctx: *mut Blake2bCtx, outlen: c_ulonglong, personal: *const c_uchar) -> c_int;
        pub fn blake2b_update(ctx: *mut Blake2bCtx, data: *const c_uchar, len: c_ulonglong) -> c_int;
        pub fn blake2b_final(ctx: *mut Blake2bCtx, out: *mut c_uchar, outlen: c_ulonglong) -> c_int;
    }
}

/// BLAKE2b hasher.
pub struct Blake2b {
    ctx: ffi::Blake2bCtx,
    out_len: usize,
}

impl Blake2b {
    /// Creates a new BLAKE2b hasher with the default 64-byte output length.
    #[inline]
    pub fn new() -> Self {
        Self::with_output_len(BLAKE2B_OUT_SIZE)
    }

    /// Creates a new BLAKE2b hasher with a custom personalization string and
    /// the default 64-byte output length. The personalization is truncated or
    /// zero-padded to 16 bytes.
    #[inline]
    pub fn new_with_personal(personal: &[u8]) -> Self {
        Self::with_output_len_and_personal(BLAKE2B_OUT_SIZE, personal)
    }

    /// Creates a new BLAKE2b hasher with the specified output length (1–64 bytes).
    #[inline]
    pub fn with_output_len(out_len: usize) -> Self {
        Self::with_output_len_and_personal(out_len, &[])
    }

    /// Creates a new BLAKE2b hasher with the specified output length (1–64 bytes)
    /// and a custom personalization string. If `personal` is empty, the CKB
    /// default `"ckb-default-hash"` is used. Otherwise, the personalization is
    /// truncated or zero-padded to 16 bytes.
    #[inline]
    pub fn with_output_len_and_personal(out_len: usize, personal: &[u8]) -> Self {
        assert!(out_len > 0 && out_len <= BLAKE2B_OUT_SIZE, "output length must be between 1 and 64");
        assert!(personal.len() <= BLAKE2B_PERSONAL_SIZE, "personalization must be at most 16 bytes");
        let ctx = ffi::Blake2bCtx {
            h: [0u64; 8],
            t: [0u64; 2],
            f: [0u64; 2],
            buf: [0u8; 128],
            buflen: 0,
            outlen: out_len as u64,
            last_node: 0,
        };
        let mut s = Self { ctx, out_len };
        unsafe {
            if personal.is_empty() {
                ffi::ckb_blake2b_init(&mut s.ctx, out_len as u64);
            } else {
                let mut personal_buf = [0u8; BLAKE2B_PERSONAL_SIZE];
                let copy_len = personal.len().min(BLAKE2B_PERSONAL_SIZE);
                personal_buf[..copy_len].copy_from_slice(&personal[..copy_len]);
                ffi::ckb_blake2b_init_personal(&mut s.ctx, out_len as u64, personal_buf.as_ptr());
            }
        }
        s
    }

    /// Updates the hasher with input data.
    #[inline]
    pub fn update(&mut self, data: &[u8]) {
        unsafe {
            ffi::blake2b_update(&mut self.ctx, data.as_ptr(), data.len() as u64);
        }
    }

    /// Finalizes the hash computation and returns the digest.
    #[inline]
    pub fn finalize(mut self) -> Blake2bDigest {
        let mut hash = [0u8; BLAKE2B_OUT_SIZE];
        unsafe {
            ffi::blake2b_final(&mut self.ctx, hash.as_mut_ptr(), self.out_len as u64);
        }
        Blake2bDigest { data: hash, len: self.out_len }
    }
}

impl Default for Blake2b {
    fn default() -> Self {
        Self::new()
    }
}

/// BLAKE2b digest with configurable output length.
pub struct Blake2bDigest {
    data: [u8; BLAKE2B_OUT_SIZE],
    len: usize,
}

impl Blake2bDigest {
    /// Returns the digest as a byte slice with the configured output length.
    #[inline]
    pub fn as_bytes(&self) -> &[u8] {
        &self.data[..self.len]
    }

    /// Returns the configured output length.
    #[inline]
    pub fn len(&self) -> usize {
        self.len
    }

    /// Returns true if the digest is empty (should never happen).
    #[inline]
    pub fn is_empty(&self) -> bool {
        self.len == 0
    }
}

impl core::fmt::LowerHex for Blake2bDigest {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        for byte in self.as_bytes() {
            write!(f, "{:02x}", byte)?;
        }
        Ok(())
    }
}

/// Computes the BLAKE2b-512 hash of the input data (64-byte output).
#[inline]
pub fn blake2b(data: &[u8]) -> Blake2bDigest {
    let mut hasher = Blake2b::new();
    hasher.update(data);
    hasher.finalize()
}

/// Computes the BLAKE2b hash of the input data with the specified output length.
#[inline]
pub fn blake2b_with_len(data: &[u8], out_len: usize) -> Blake2bDigest {
    let mut hasher = Blake2b::with_output_len(out_len);
    hasher.update(data);
    hasher.finalize()
}
