use core::ffi::c_int;
use core::{fmt, ptr};
use std::sync::Arc;

use crate::constants::{name_to_sig_alg, sig_scheme_to_type_nid};

use openssl_sys::{
    EVP_DigestSign, EVP_DigestSignInit, EVP_MD_CTX_free, EVP_MD_CTX_new,
    EVP_PKEY_CTX_set_rsa_padding, EVP_PKEY_CTX_set_rsa_pss_saltlen, EVP_PKEY_CTX_set_signature_md,
    EVP_sha256, EVP_sha384, EVP_sha512, NID_undef, EVP_MD, EVP_MD_CTX, EVP_PKEY, EVP_PKEY_CTX,
    RSA_PKCS1_PADDING, RSA_PKCS1_PSS_PADDING,
};

use rustls::pki_types::PrivateKeyDer;
use rustls::sign::SigningKey;
use rustls::SignatureScheme;

#[derive(Debug)]
pub(crate) struct EvpKeyInfo {
    base_id: i32,
    bits: i32,
    description: i32,
    id: i32,
    security_bits: i32,
    security_category: i32,
    size: i32,
    ty: i32,
}
/// Safe, owning wrapper around an OpenSSL EVP_PKEY.
#[derive(Clone, Debug)]
enum KeyType {
    Unknown,
    SigningKey(Arc<dyn SigningKey>)
}
/// Safe, owning wrapper around an OpenSSL EVP_PKEY.
#[derive(Debug)]
pub struct EvpPkey {
    inner_key: KeyType,
    scheme: Option<SignatureScheme>,
}

impl EvpPkey {
    pub fn new() -> Self {
        Self {
            inner_key: KeyType::Unknown,
            scheme: None,
        }
    }

    pub fn as_ptr(&self) -> *mut EVP_PKEY {
        self as *const Self as *mut EVP_PKEY
    }

    pub fn get_type(&self) -> c_int {
        self.scheme
            .and_then(sig_scheme_to_type_nid)
            .unwrap_or(NID_undef)
    }

    /// Parse a key from DER bytes.
    pub fn new_from_der_bytes(data: PrivateKeyDer<'static>) -> Option<Self> {
        let provider = crate::provider::provider().key_provider;
        provider.load_private_key(data).ok().map(|keydata| Self {
            inner_key: KeyType::SigningKey(keydata),
            scheme: None, // TODO: Determine here
        })
    }

    /// Sign a message, returning the signature.
    pub fn sign(&self, scheme: &dyn EvpScheme, message: &[u8]) -> Result<Vec<u8>, ()> {
        let mut ctx = SignCtx::new(scheme.digest(), self.as_ptr()).ok_or(())?;
        scheme.configure_ctx(&mut ctx).ok_or(())?;
        ctx.sign(message)
    }

    pub fn algorithm(&self) -> rustls::SignatureAlgorithm {
        match &self.inner_key {
            KeyType::SigningKey(key) => key.algorithm(),
            KeyType::Unknown => rustls::SignatureAlgorithm::Unknown(0),
        }
    }

    /// Return the Subject Public Key Info bytes for this key.
    pub fn subject_public_key_info(&self) -> Vec<u8> {
        match &self.inner_key{
            KeyType::SigningKey(key) => key.public_key().map(|spki| spki.to_vec()).unwrap_or_default(),
            KeyType::Unknown => Vec::new()
        }
    }

    pub fn is_a(&self, which: &str) -> bool {
        name_to_sig_alg(which)
            .map(|alg| self.algorithm() == alg)
            .unwrap_or(false)
    }
}

// We assume read-only (const *EVP_PKEY) functions on EVP_PKEYs are thread safe,
// and refcounting is atomic. The actual facts are not documented.
unsafe impl Sync for EvpPkey {}
unsafe impl Send for EvpPkey {}

pub trait EvpScheme: fmt::Debug {
    fn digest(&self) -> *mut EVP_MD;
    fn configure_ctx(&self, ctx: &mut SignCtx) -> Option<()>;
}

pub fn rsa_pkcs1_sha256() -> Box<dyn EvpScheme + Send + Sync> {
    Box::new(RsaPkcs1(unsafe { EVP_sha256() }))
}

pub fn rsa_pkcs1_sha384() -> Box<dyn EvpScheme + Send + Sync> {
    Box::new(RsaPkcs1(unsafe { EVP_sha384() }))
}

pub fn rsa_pkcs1_sha512() -> Box<dyn EvpScheme + Send + Sync> {
    Box::new(RsaPkcs1(unsafe { EVP_sha512() }))
}

#[derive(Debug)]
struct RsaPkcs1(*const EVP_MD);

impl EvpScheme for RsaPkcs1 {
    fn digest(&self) -> *mut EVP_MD {
        self.0 as *mut EVP_MD
    }

    fn configure_ctx(&self, ctx: &mut SignCtx) -> Option<()> {
        ctx.set_signature_md(self.0)
            .and_then(|_| ctx.set_rsa_padding(RSA_PKCS1_PADDING))
    }
}

unsafe impl Sync for RsaPkcs1 {}
unsafe impl Send for RsaPkcs1 {}

pub fn rsa_pss_sha256() -> Box<dyn EvpScheme + Send + Sync> {
    Box::new(RsaPss(unsafe { EVP_sha256() }))
}

pub fn rsa_pss_sha384() -> Box<dyn EvpScheme + Send + Sync> {
    Box::new(RsaPss(unsafe { EVP_sha384() }))
}

pub fn rsa_pss_sha512() -> Box<dyn EvpScheme + Send + Sync> {
    Box::new(RsaPss(unsafe { EVP_sha512() }))
}

#[derive(Debug)]
struct RsaPss(*const EVP_MD);

impl EvpScheme for RsaPss {
    fn digest(&self) -> *mut EVP_MD {
        self.0 as *mut EVP_MD
    }

    fn configure_ctx(&self, ctx: &mut SignCtx) -> Option<()> {
        const RSA_PSS_SALTLEN_DIGEST: c_int = -1;
        ctx.set_signature_md(self.0)
            .and_then(|_| ctx.set_rsa_padding(RSA_PKCS1_PSS_PADDING))
            .and_then(|_| ctx.set_pss_saltlen(RSA_PSS_SALTLEN_DIGEST))
    }
}

unsafe impl Sync for RsaPss {}
unsafe impl Send for RsaPss {}

pub fn ed25519() -> Box<dyn EvpScheme + Send + Sync> {
    Box::new(Ed25519)
}

#[derive(Debug)]
struct Ed25519;

impl EvpScheme for Ed25519 {
    fn digest(&self) -> *mut EVP_MD {
        // "When calling EVP_DigestSignInit() or EVP_DigestVerifyInit(), the
        // digest type parameter MUST be set to NULL."
        // <https://www.openssl.org/docs/man3.0/man7/EVP_SIGNATURE-ED25519.html>
        ptr::null_mut()
    }

    fn configure_ctx(&self, _: &mut SignCtx) -> Option<()> {
        // "No additional parameters can be set during one-shot signing or verification."
        Some(())
    }
}

pub fn ecdsa_sha256() -> Box<dyn EvpScheme + Send + Sync> {
    Box::new(Ecdsa(unsafe { EVP_sha256() }))
}

pub fn ecdsa_sha384() -> Box<dyn EvpScheme + Send + Sync> {
    Box::new(Ecdsa(unsafe { EVP_sha384() }))
}

pub fn ecdsa_sha512() -> Box<dyn EvpScheme + Send + Sync> {
    Box::new(Ecdsa(unsafe { EVP_sha512() }))
}

#[derive(Debug)]
struct Ecdsa(*const EVP_MD);

impl EvpScheme for Ecdsa {
    fn digest(&self) -> *mut EVP_MD {
        self.0 as *mut EVP_MD
    }

    fn configure_ctx(&self, _: &mut SignCtx) -> Option<()> {
        Some(())
    }
}

unsafe impl Sync for Ecdsa {}
unsafe impl Send for Ecdsa {}

/// Owning wrapper for a signing `EVP_MD_CTX`
pub(crate) struct SignCtx {
    md_ctx: *mut EVP_MD_CTX,
    // owned by `md_ctx`
    pkey_ctx: *mut EVP_PKEY_CTX,
}

impl SignCtx {
    fn new(md: *mut EVP_MD, pkey: *mut EVP_PKEY) -> Option<Self> {
        let md_ctx = unsafe { EVP_MD_CTX_new() };
        let mut pkey_ctx = ptr::null_mut();

        match unsafe { EVP_DigestSignInit(md_ctx, &mut pkey_ctx, md, ptr::null_mut(), pkey) } {
            1 => {}
            _ => {
                unsafe { EVP_MD_CTX_free(md_ctx) };
                return None;
            }
        };

        Some(Self { md_ctx, pkey_ctx })
    }

    fn set_signature_md(&mut self, md: *const EVP_MD) -> Option<()> {
        unsafe { EVP_PKEY_CTX_set_signature_md(self.pkey_ctx, md) == 1 }.then_some(())
    }

    fn set_rsa_padding(&mut self, pad: c_int) -> Option<()> {
        unsafe { EVP_PKEY_CTX_set_rsa_padding(self.pkey_ctx, pad) == 1 }.then_some(())
    }

    fn set_pss_saltlen(&mut self, saltlen: c_int) -> Option<()> {
        unsafe { EVP_PKEY_CTX_set_rsa_pss_saltlen(self.pkey_ctx, saltlen) == 1 }.then_some(())
    }

    fn sign(self, data: &[u8]) -> Result<Vec<u8>, ()> {
        // determine length
        let mut max_len = 0;
        match unsafe {
            EVP_DigestSign(
                self.md_ctx,
                ptr::null_mut(),
                &mut max_len,
                data.as_ptr(),
                data.len(),
            )
        } {
            1 => {}
            _ => return Err(()),
        };

        // do the signature
        let mut out = vec![0u8; max_len];
        let mut actual_len = max_len;

        match unsafe {
            EVP_DigestSign(
                self.md_ctx,
                out.as_mut_ptr(),
                &mut actual_len,
                data.as_ptr(),
                data.len(),
            )
        } {
            1 => {}
            _ => return Err(()),
        }

        out.truncate(actual_len);
        Ok(out)
    }
}

impl Drop for SignCtx {
    fn drop(&mut self) {
        unsafe { EVP_MD_CTX_free(self.md_ctx) };
    }
}

#[cfg(all(test, not(miri)))]
mod tests {
    use super::*;
    use std::io::Cursor;

    use rustls::pki_types::pem::PemObject;
    use rustls::pki_types::{CertificateDer, PrivateKeyDer};

    #[test]
    fn supports_rsaencryption_keys() {
        let der =
            PrivateKeyDer::from_pem_reader(&mut &include_bytes!("../test-ca/rsa/server.key")[..])
                .unwrap();
        let key = EvpPkey::new_from_der_bytes(der).unwrap();
        println!("{key:?}");
        assert_eq!(key.algorithm(), rustls::SignatureAlgorithm::RSA);
        assert_eq!(
            key.sign(rsa_pkcs1_sha256().as_ref(), b"hello")
                .unwrap()
                .len(),
            256
        );
        assert_eq!(
            key.sign(rsa_pkcs1_sha384().as_ref(), b"hello")
                .unwrap()
                .len(),
            256
        );
        assert_eq!(
            key.sign(rsa_pkcs1_sha512().as_ref(), b"hello")
                .unwrap()
                .len(),
            256
        );
        assert_eq!(
            key.sign(rsa_pss_sha256().as_ref(), b"hello").unwrap().len(),
            256
        );
        assert_eq!(
            key.sign(rsa_pss_sha384().as_ref(), b"hello").unwrap().len(),
            256
        );
        assert_eq!(
            key.sign(rsa_pss_sha512().as_ref(), b"hello").unwrap().len(),
            256
        );
    }

    #[test]
    fn pkey_spki() {
        for (key_path, cert_path) in &[
            ("test-ca/rsa/server.key", "test-ca/rsa/server.cert"),
            (
                "test-ca/ecdsa-p256/server.key",
                "test-ca/ecdsa-p256/server.cert",
            ),
            (
                "test-ca/ecdsa-p384/server.key",
                "test-ca/ecdsa-p384/server.cert",
            ),
            (
                "test-ca/ecdsa-p521/server.key",
                "test-ca/ecdsa-p521/server.cert",
            ),
            ("test-ca/ed25519/server.key", "test-ca/ed25519/server.cert"),
        ] {
            let key_der = std::fs::read(key_path).unwrap();
            let cert_der = std::fs::read(cert_path).unwrap();

            let key_der = PrivateKeyDer::from_pem_reader(&mut Cursor::new(&key_der)).unwrap();
            let key = EvpPkey::new_from_der_bytes(key_der).unwrap();

            let cert_der = CertificateDer::from_pem_reader(&mut Cursor::new(cert_der)).unwrap();
            let parsed_cert = rustls::server::ParsedCertificate::try_from(&cert_der).unwrap();

            let cert_spki = parsed_cert.subject_public_key_info();
            let key_spki = key.subject_public_key_info();
            assert_eq!(&key_spki, cert_spki.as_ref());
        }
    }
}
