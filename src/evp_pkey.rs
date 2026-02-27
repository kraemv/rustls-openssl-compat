use core::ffi::{c_char, c_int, c_long, CStr};
use core::{slice, ptr};
use crate::{error, provider};
use std::sync::Arc;

use openssl_sys::{
    d2i_AutoPrivateKey, EVP_PKEY_free, EVP_PKEY_up_ref, EVP_PKEY, i2d_PrivateKey,
    OPENSSL_free
};
use rustls::pki_types::PrivateKeyDer;
use rustls::sign;

/// Safe, owning wrapper around an OpenSSL EVP_PKEY.
#[derive(Debug)]
pub struct EvpPkey {
    pkey: *const EVP_PKEY,
    signing_key: Option<Arc<dyn sign::SigningKey>>
}

impl EvpPkey {
    /// Use a pre-existing private key, incrementing ownership.
    ///
    /// `pkey` continues to belong to the caller.
    pub fn new_incref(pkey: *mut EVP_PKEY) -> Self {
        debug_assert!(!pkey.is_null());
        unsafe { EVP_PKEY_up_ref(pkey) };
        Self { pkey, signing_key: None }
    }

    /// Parse a key from DER bytes.
    pub fn new_from_der_bytes(data: PrivateKeyDer<'static>) -> Option<Self> {
        let mut old_ptr = ptr::null_mut();
        let mut data_ptr = data.secret_der().as_ptr();
        let data_len = data.secret_der().len();
        let pkey = unsafe { d2i_AutoPrivateKey(&mut old_ptr, &mut data_ptr, data_len as c_long) };

        let signing_key = provider::provider().key_provider.load_private_key(data).map_err(|_| error::Error::bad_data("Failed: PKEY key decoding"));

        if pkey.is_null() || signing_key.is_err() {
            None
        } else {
            Some(Self { pkey, signing_key: Some(signing_key.unwrap())})
        }
    }

    pub fn get_signing_key(&self) -> Option<Arc<dyn sign::SigningKey>> {
        match &self.signing_key {
            Some(key) => Some(key.clone()),
            None => None,
        }
    }

    pub fn add_signing_key(&self) -> Result<Arc<dyn sign::SigningKey>, error::Error>{
        let mut buf: *mut u8 = ptr::null_mut();
        let len = unsafe{ i2d_PrivateKey(self.borrow_ref(), &mut buf)};
        if len < 0 {
            Err(error::Error::bad_data("Failed: PKEY key encoding"))?
        }
        let len = len as usize;

        let mut v = Vec::with_capacity(len);
        v.extend_from_slice(unsafe { slice::from_raw_parts(buf, len) });
        let key_der = PrivateKeyDer::try_from(v)
            .map_err(|_| error::Error::bad_data("Failed: PKEY key encoding"))?;

        unsafe { OPENSSL_free(buf as *mut _) };

        provider::provider().key_provider.load_private_key(key_der).map_err(|_| error::Error::bad_data("Failed: PKEY key decoding"))
    }

    pub fn algorithm(&self) -> rustls::SignatureAlgorithm {
        if self.is_rsa_type() {
            rustls::SignatureAlgorithm::RSA
        } else if self.is_ecdsa_type() {
            rustls::SignatureAlgorithm::ECDSA
        } else if self.is_ed25519_type() {
            rustls::SignatureAlgorithm::ED25519
        } else if self.is_ed448_type() {
            rustls::SignatureAlgorithm::ED448
        } else {
            rustls::SignatureAlgorithm::Unknown(0)
        }
    }

    /// Caller borrows our reference.
    pub fn borrow_ref(&self) -> *mut EVP_PKEY {
        self.pkey as *mut EVP_PKEY
    }

    fn is_rsa_type(&self) -> bool {
        self.is_a(c"RSA") || self.is_a(c"RSA-PSS")
    }

    fn is_ecdsa_type(&self) -> bool {
        self.is_a(c"EC")
    }

    fn is_ed25519_type(&self) -> bool {
        self.is_a(c"ED25519")
    }

    fn is_ed448_type(&self) -> bool {
        self.is_a(c"ED448")
    }

    fn is_a(&self, which: &CStr) -> bool {
        unsafe { EVP_PKEY_is_a(self.pkey, which.as_ptr()) == 1 }
    }
}

impl Clone for EvpPkey {
    fn clone(&self) -> Self {
        unsafe { EVP_PKEY_up_ref(self.pkey as *mut EVP_PKEY) };
        Self { pkey: self.pkey, signing_key: self.signing_key.clone()}
    }
}

impl Drop for EvpPkey {
    fn drop(&mut self) {
        // safety: cast to *mut is safe, because refcounting is assumed atomic
        unsafe { EVP_PKEY_free(self.pkey as *mut EVP_PKEY) };
    }
}

extern "C" {
    pub fn EVP_PKEY_is_a(pkey: *const EVP_PKEY, name: *const c_char) -> c_int;
}
