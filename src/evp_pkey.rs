use core::ffi::{c_char, c_int};
use std::ptr;
use std::sync::Arc;

use crate::constants::{alg_id_to_sig_alg, name_to_sig_alg, scheme_to_info};
use crate::error::Error;
use crate::not_thread_safe::NotThreadSafe;
use crate::provider;

use openssl_sys::EVP_PKEY;

use pkcs8::PrivateKeyInfo;
use pkcs8::der::asn1::OctetString;
use rustls::crypto::{ActiveKeyExchange, SupportedKxGroup};
use rustls::pki_types::{PrivateKeyDer, SignatureVerificationAlgorithm, SubjectPublicKeyInfoDer};
use rustls::sign::SigningKey;
use rustls::SignatureScheme;

use x509_cert::attr::{Attribute, Attributes};
use x509_cert::der::{Any, Decode};
use x509_cert::der::asn1::{BitString, SetOfRef, SetOfVec};
use x509_cert::spki::{AlgorithmIdentifier, SubjectPublicKeyInfo};

/// Safe, owning wrapper around an OpenSSL EVP_PKEY.
#[derive(Default)]
enum KeyType {
    #[default]
    Unknown,
    ExchangePrivateKey(Box<dyn ActiveKeyExchange>),
    ExchangePublicKey(Arc<dyn SupportedKxGroup>, Vec<u8>),
    PrivateKeyShare(Arc<dyn SupportedKxGroup>),
    PublicKeyShare(Arc<dyn ActiveKeyExchange>),
    SigningKey(Arc<dyn SigningKey>),
    VerificationKey(&'static dyn SignatureVerificationAlgorithm, SubjectPublicKeyInfoDer<'static>),

}

#[derive(Clone, Debug, Default, PartialEq)]
pub(crate) enum Scheme {
    #[default]
    Unknown,
    SignatureScheme(SignatureScheme),
}

/// Safe, owning wrapper around an OpenSSL EVP_PKEY.
#[derive(Default)]
pub struct EvpPkey {
    inner_key: KeyType,
    attributes: Attributes,
    scheme: Scheme,
}

impl EvpPkey {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn as_ptr(&self) -> *mut EVP_PKEY {
        self as *const Self as *mut EVP_PKEY
    }

    pub fn is_signing_key(&self) -> bool {
        matches!(&self.inner_key, KeyType::SigningKey(_))
    }

    pub fn get_attributes(&self) -> &[Attribute] {
        self.attributes.as_slice()
    }

    pub fn get_base_id(&self) -> c_int {
        scheme_to_info(&self.scheme).map(|info| info.get_id()).unwrap_or(0)
    }

    pub fn get_bits(&self) -> c_int {
        scheme_to_info(&self.scheme).map(|info| info.get_bits()).unwrap_or(0)
    }

    pub fn get_description(&self) -> *const c_char {
        scheme_to_info(&self.scheme).map(|info| info.get_description().as_ptr()).unwrap_or(ptr::null())
    }

    pub fn get_id(&self) -> c_int {
        scheme_to_info(&self.scheme).map(|info| info.get_id()).unwrap_or(0)
    }

    pub(crate) fn get_scheme(&self) -> Scheme {
        self.scheme.clone()
    }

    pub fn get_security_bits(&self) -> c_int {
        scheme_to_info(&self.scheme).map(|info| info.get_security_bits()).unwrap_or(0)
    }

    pub fn get_size(&self) -> c_int {
        scheme_to_info(&self.scheme).map(|info| info.get_size()).unwrap_or(0)
    }

    fn reset_key(&mut self) {
        *self = Self::default()
    }

    /// Parse a key from DER bytes.
    pub fn new_from_private_der_bytes(data: PrivateKeyDer<'static>) -> Result<Self, Error> {
        type PkInfoType<'a> = PrivateKeyInfo<Any, OctetString, BitString, SetOfRef<'a, Attribute>>;
        let pk_alg: AlgorithmIdentifier<Any> = PkInfoType::from_der(data.secret_der()).map_err(|_| Error::bad_data("[DER] cannot decode"))?.algorithm;
        let scheme = alg_id_to_sig_alg(pk_alg).ok_or(Error::not_supported("[DER] Unknown scheme"))?;
        let provider = provider::provider().key_provider;
        provider.load_private_key(data).map(|keydata| Self {
            inner_key: KeyType::SigningKey(keydata),
            attributes: Attributes::new(),
            scheme: Scheme::SignatureScheme(scheme),
        })
        .map_err(Error::from_rustls)
    }

    pub fn new_from_spki_bytes(data: SubjectPublicKeyInfoDer<'static>) -> Option<Self> {
        let spki_alg: AlgorithmIdentifier<Any>= SubjectPublicKeyInfo::<Any, BitString>::from_der(data.as_ref())
            .ok()?
            .algorithm;
        let spki_scheme = alg_id_to_sig_alg(spki_alg)?;
        let algs = provider::provider().signature_verification_algorithms;
        let scheme_index = algs.supported_schemes()
            .iter()
            .position(|scheme| *scheme == spki_scheme)?;
        let scheme = *algs.mapping[scheme_index].1.first()?;
        Some(Self { inner_key: KeyType::VerificationKey(scheme, data), attributes: SetOfVec::new(), scheme: Scheme::SignatureScheme(spki_scheme) })

    }

    pub fn get_encaps_key(&self) -> Result<(Arc<dyn SupportedKxGroup>, &[u8]), Error> {
        match &self.inner_key {
            KeyType::ExchangePublicKey(group, key) => Ok((group.clone(), key.as_ref())),
            _ => Err(Error::not_supported("Not an encaps key")),
        }
    }

    pub fn get_private_share(&self) -> Result<Arc<dyn SupportedKxGroup>, Error> {
        match &self.inner_key {
            KeyType::PrivateKeyShare(key) => Ok(key.clone()),
            _ => Err(Error::not_supported("Not a private key share")),
        }
    }

    pub fn get_public_share(&self) -> Result<Arc<dyn ActiveKeyExchange>, Error> {
        match &self.inner_key {
            KeyType::PublicKeyShare(key) => Ok(key.clone()),
            _ => Err(Error::not_supported("Not a public key share")),
        }
    }

    pub fn get_signing_key(&self) -> Result<Arc<dyn SigningKey>, Error> {
        match &self.inner_key {
            KeyType::SigningKey(key) => Ok(key.clone()),
            _ => Err(Error::not_supported("Not a signing key")),
        }
    }

    pub fn get_verify_key(&self) -> Result<(&'static dyn SignatureVerificationAlgorithm, &[u8]), Error> {
        match &self.inner_key {
            KeyType::VerificationKey(alg, key) => Ok((*alg, key.as_ref())),
            _ => Err(Error::not_supported("Not a verification key")),
        }
    }

    pub fn take_decaps_key(&mut self) -> Result<Box <dyn ActiveKeyExchange>, Error> {
        let old_key = std::mem::take(&mut self.inner_key);

        match old_key {
            KeyType::ExchangePrivateKey(key) => {
                self.reset_key();
                Ok(key)
            }
            old_key => {
                self.inner_key = old_key;
                Err(Error::not_supported("Not a decaps key"))
            }
        }
    }

    pub fn is_a(&self, which: &str) -> bool {
        let Ok(key) = self.get_signing_key()
        else { return false; };
        name_to_sig_alg(which)
            .map(|alg| key.algorithm() == alg)
            .unwrap_or(false)
    }
}

impl From<Arc<dyn SigningKey>> for EvpPkey{
    fn from(value: Arc<dyn SigningKey>) -> Self {
        Self { inner_key: KeyType::SigningKey(value), attributes: Attributes::new(), scheme: Scheme::Unknown }
    }
    
}

#[derive(Default)]
pub struct EvpPkeyCtx {
    pkey: Option<Arc<NotThreadSafe<EvpPkey>>>,
    peer_key: Option<Arc<NotThreadSafe<EvpPkey>>>,
}

impl EvpPkeyCtx {
    pub fn new() -> Self{
        Self::default()
    }

    pub fn get_pkey(&self) -> Option<Arc<NotThreadSafe<EvpPkey>>> {
        self.pkey.as_ref().map(|key| key.clone())
    }

    pub fn get_peer_key(&self) -> Option<Arc<NotThreadSafe<EvpPkey>>> {
        self.peer_key.as_ref().map(|key| key.clone())
    }

    pub fn set_pkey(&mut self, pkey: Arc<NotThreadSafe<EvpPkey>>) {
        self.pkey = Some(pkey);
    }

    pub fn set_peer_pkey(&mut self, peer: Arc<NotThreadSafe<EvpPkey>>) -> Result<(), Error> {
        let peer_key = peer.get();

        let has_public_share = peer_key.get_public_share().is_ok();
        let has_encaps_key = peer_key.get_encaps_key().is_ok();

        if has_public_share && has_encaps_key {
            Ok(())
        } else {
            Err(Error::not_supported("Not a public key"))
        }
    }
}

impl From<Arc<NotThreadSafe<EvpPkey>>> for EvpPkeyCtx{
    fn from(pkey: Arc<NotThreadSafe<EvpPkey>>) -> Self {
        Self { pkey: Some(pkey), peer_key: None}
    }
    
}