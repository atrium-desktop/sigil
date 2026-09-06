use crate::domain::{Result, SecretBytes, SigilError};
use rand::rngs::OsRng;
use rand::RngCore;
use std::fmt;
use zeroize::{Zeroize, ZeroizeOnDrop};

pub const MASTER_KEY_LEN: usize = 32;

/// A 256-bit cryptographic master key protected by zeroization on drop.
#[derive(Clone, PartialEq, Eq, Zeroize, ZeroizeOnDrop)]
pub struct MasterKey([u8; MASTER_KEY_LEN]);

impl MasterKey {
    pub fn new(bytes: [u8; MASTER_KEY_LEN]) -> Self {
        Self(bytes)
    }

    pub fn generate() -> Self {
        let mut bytes = [0u8; MASTER_KEY_LEN];
        OsRng.fill_bytes(&mut bytes);
        Self(bytes)
    }

    pub fn from_slice(slice: &[u8]) -> Result<Self> {
        if slice.len() != MASTER_KEY_LEN {
            return Err(SigilError::CryptoFailure(format!(
                "Invalid master key length: expected {}, got {}",
                MASTER_KEY_LEN,
                slice.len()
            )));
        }
        let mut bytes = [0u8; MASTER_KEY_LEN];
        bytes.copy_from_slice(slice);
        Ok(Self(bytes))
    }

    pub fn from_hex(hex_str: &str) -> Result<Self> {
        let trimmed = hex_str.trim();
        if trimmed.len() != MASTER_KEY_LEN * 2 {
            return Err(SigilError::CryptoFailure(format!(
                "Invalid hex key length: expected {}, got {}",
                MASTER_KEY_LEN * 2,
                trimmed.len()
            )));
        }
        let mut bytes = [0u8; MASTER_KEY_LEN];
        for i in 0..MASTER_KEY_LEN {
            bytes[i] = u8::from_str_radix(&trimmed[i * 2..i * 2 + 2], 16)
                .map_err(|e| SigilError::CryptoFailure(format!("Invalid hex string: {e}")))?;
        }
        Ok(Self(bytes))
    }

    pub fn to_hex(&self) -> String {
        let mut s = String::with_capacity(MASTER_KEY_LEN * 2);
        for byte in &self.0 {
            use std::fmt::Write;
            let _ = write!(&mut s, "{:02x}", byte);
        }
        s
    }

    pub fn as_bytes(&self) -> &[u8; MASTER_KEY_LEN] {
        &self.0
    }

    pub fn to_secret_bytes(&self) -> SecretBytes {
        SecretBytes::from_slice(&self.0)
    }
}

impl fmt::Debug for MasterKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "MasterKey([redacted])")
    }
}

/// A secure, memory-locked container holding the MasterKey.
/// Uses `mlock(2)` to prevent swapping to disk and `MADV_DONTDUMP` to keep material out of coredumps.
pub struct LockedKeyBox {
    ptr: *mut u8,
    page_size: usize,
}

unsafe impl Send for LockedKeyBox {}
unsafe impl Sync for LockedKeyBox {}

impl LockedKeyBox {
    pub fn new(key: &MasterKey) -> Self {
        let page_size = unsafe { libc::sysconf(libc::_SC_PAGESIZE) as usize };
        let page_size = if page_size == 0 { 4096 } else { page_size };

        let ptr = unsafe {
            libc::mmap(
                std::ptr::null_mut(),
                page_size,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
                -1,
                0,
            ) as *mut u8
        };

        if ptr == libc::MAP_FAILED as *mut u8 || ptr.is_null() {
            panic!("Failed to allocate mmap page for LockedKeyBox");
        }

        unsafe {
            let _ = libc::mlock(ptr as *const libc::c_void, page_size);
            let _ = libc::madvise(ptr as *mut libc::c_void, page_size, libc::MADV_DONTDUMP);
            std::ptr::copy_nonoverlapping(key.as_bytes().as_ptr(), ptr, MASTER_KEY_LEN);
        }

        Self { ptr, page_size }
    }

    pub fn expose_key<R>(&self, f: impl FnOnce(&[u8; MASTER_KEY_LEN]) -> R) -> R {
        let slice = unsafe { &*(self.ptr as *const [u8; MASTER_KEY_LEN]) };
        f(slice)
    }

    pub fn to_master_key(&self) -> MasterKey {
        self.expose_key(|k| MasterKey::new(*k))
    }
}

impl Drop for LockedKeyBox {
    fn drop(&mut self) {
        if !self.ptr.is_null() && self.ptr != libc::MAP_FAILED as *mut u8 {
            unsafe {
                std::ptr::write_bytes(self.ptr, 0, self.page_size);
                let _ = libc::munlock(self.ptr as *const libc::c_void, self.page_size);
                let _ = libc::munmap(self.ptr as *mut libc::c_void, self.page_size);
            }
        }
    }
}

