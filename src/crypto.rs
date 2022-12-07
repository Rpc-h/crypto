use blake2::Blake2s256;
use chacha20poly1305::{ChaCha20Poly1305, KeyInit, Nonce};
use chacha20poly1305::aead::Aead;
use elliptic_curve::ecdh::diffie_hellman;
use k256::{PublicKey, SecretKey, ecdh::EphemeralSecret, EncodedPoint};
use elliptic_curve::rand_core::OsRng;
use k256::ecdh::SharedSecret;

use thiserror::Error;

pub const RPCH_CRYPTO_VERSION: u8 = 0x11;

const PUBLIC_KEYSIZE_ENCODED: usize = 33;
const COUNTER_SIZE: usize = 8;
const CIPHER_KEYSIZE: usize = 32;
const CIPHER_IVSIZE: usize = 12;

const COUNTER_GRACE_AMOUNT: u64 = 0;

#[derive(Error, Debug)]
pub enum RpchCryptoError {
    #[error("session is invalid")]
    InvalidSession,
    #[error("message verification failed")]
    VerificationFailed,
    #[error("private key is missing in the used identity")]
    MissingIdentityKey,
    #[error("error while parsing the request or response message")]
    MessageParseError,
    #[error("unsupported protocol version")]
    UnsupportedProtocolVersion,
    #[error("invalid counter value")]
    InvalidCounter,
    #[error("low level cryptographic error: {0}")]
    CryptographicError(String),
    #[error("not implemented")]
    NotImplemented
}

type Result<T> = core::result::Result<T, RpchCryptoError>;

pub struct Session {
    req_data: Option<Box<[u8]>>,
    resp_data: Option<Box<[u8]>>,
    counter: u64,
    shared_presecret: Option<SharedSecret>
}

impl Session {

    pub fn get_request_data(&self) -> Option<Box<[u8]>> {
        self.req_data.clone()
    }

    pub fn get_response_data(&self) -> Option<Box<[u8]>> {
        self.resp_data.clone()
    }

    pub fn counter(&self) -> u64 {
        self.counter
    }
}

pub struct Identity {
    pubkey: PublicKey,
    counter: Option<u64>,
    secret_key: Option<SecretKey>
}

impl Identity {

    pub fn new(public_key: &[u8], counter: Option<u64>, private_key: Option<Box<[u8]>>) -> Result<Identity> {
        let pk = PublicKey::from_sec1_bytes(public_key)
            .map_err(|e| RpchCryptoError::CryptographicError(e.to_string()))?;

        let sk = match private_key {
            None => None,
            Some(k) => Some(SecretKey::from_be_bytes(k.as_ref())
                .map_err(|e| RpchCryptoError::CryptographicError(e.to_string()))?)
        };

        Ok(Identity {
            pubkey: pk,
            counter,
            secret_key: sk
        })
    }

    fn counter(&self) -> Option<u64> {
        self.counter
    }
}

pub struct Envelope {
    message: Box<[u8]>,
    entry_peer_id: String,
    exit_peer_id: String
}

impl Envelope {

    pub fn new(message: &[u8], entry_peer_id: &str, exit_peer_id: &str) -> Envelope {
        Envelope {
            message: message.into(),
            entry_peer_id: entry_peer_id.into(),
            exit_peer_id: exit_peer_id.into()
        }
    }

    pub fn entry_peer_id(&self) -> &str {
        self.entry_peer_id.as_str()
    }

    pub fn exit_peer_id(&self) -> &str {
        self.exit_peer_id.as_str()
    }

    pub fn message(&self) -> &[u8] {
        self.message.as_ref()
    }

}

const REQUEST_TAG: &str = "req";

fn initialize_cipher(shared_presecret: &SharedSecret, counter: u64, salt: &[u8], start_index: usize) -> Result<(ChaCha20Poly1305, Vec<u8>)> {
    let kdf = shared_presecret.extract::<Blake2s256>(Some(salt));

    let mut key = [0u8; CIPHER_KEYSIZE];
    let mut ivm = [0u8; CIPHER_IVSIZE - COUNTER_SIZE];
    for _ in 0..start_index+1 {
        // Generate the encryption key using the KDF
        kdf.expand(&[0u8; 1], &mut key)
            .map_err(|e| RpchCryptoError::CryptographicError(e.to_string()))?;

        // Generate the first part of the IV from shared pre-secret
        kdf.expand(&[0u8; 1], &mut ivm)
            .map_err(|e| RpchCryptoError::CryptographicError(e.to_string()))?;
    }

    // Construct the final IV using the generated prefix and the new counter
    let mut iv = Vec::from(ivm);
    iv.extend_from_slice(&counter.to_be_bytes());

    // Initialize the cipher with the key and the IV
    Ok((ChaCha20Poly1305::new_from_slice(&key)
        .map_err(|e| RpchCryptoError::CryptographicError(e.to_string()))?, iv))
}


/// Called by the RPCh client
pub fn box_request(request: Envelope, exit_node: &Identity) -> Result<Session> {
    // Generate random ephemeral key
    let ephemeral_key = EphemeralSecret::random(&mut OsRng);

    // Perform the Diffie-Hellman step using the Exit node's public key & initialize the KDF using the shared pre-secret
    let shared_presecret = ephemeral_key.diffie_hellman(&exit_node.pubkey);

    // Obtain the exit node counter value and increase it by 1
    let new_counter = exit_node.counter().ok_or(RpchCryptoError::InvalidCounter)? + 1;

    // Create the salt for the request and initialize the cipher
    let mut salt = vec![RPCH_CRYPTO_VERSION];
    salt.extend_from_slice(request.exit_peer_id.as_bytes());
    salt.extend_from_slice(REQUEST_TAG.as_bytes());
    let (cipher, iv) = initialize_cipher(&shared_presecret, new_counter, salt.as_slice(), 0)?;

    // Encrypt and authenticate the request
    let cipher_text = cipher.encrypt(Nonce::from_slice(iv.as_slice()), request.message.as_ref())
        .map_err(|e| RpchCryptoError::CryptographicError(e.to_string()))?;

    // Construct the result
    let mut result = vec![RPCH_CRYPTO_VERSION]; // Version
    result.extend_from_slice(EncodedPoint::from(ephemeral_key.public_key()).as_bytes()); // W
    result.extend_from_slice(&new_counter.to_be_bytes()); // C
    result.extend(cipher_text.iter()); // R,T

    Ok(Session {
        req_data: Some(result.into_boxed_slice()),
        resp_data: None,
        counter: new_counter,
        shared_presecret: Some(shared_presecret)
    })
}

/// Called by the Exit node
pub fn unbox_request(request: Envelope, my_id: &Identity, client_counter: u64) -> Result<Session> {
    let message = request.message();

    if message[0]&0x10 != RPCH_CRYPTO_VERSION&0x10 {
        return Err(RpchCryptoError::UnsupportedProtocolVersion)
    }

    let ephemeral_pk = PublicKey::from_sec1_bytes(&message[1..PUBLIC_KEYSIZE_ENCODED+1])
        .map_err(|_| RpchCryptoError::MessageParseError)?;

    let private_key = my_id.secret_key.as_ref()
        .ok_or(RpchCryptoError::MissingIdentityKey)?;

    let shared_presecret = diffie_hellman(private_key.to_nonzero_scalar(), ephemeral_pk.as_affine());

    let mut counter_bytes = [0u8; COUNTER_SIZE];
    counter_bytes.copy_from_slice(&message[1+PUBLIC_KEYSIZE_ENCODED..1+PUBLIC_KEYSIZE_ENCODED+COUNTER_SIZE]);
    let counter = u64::from_be_bytes(counter_bytes);

    // Create the salt for the request and initialize the cipher
    let mut salt = vec![RPCH_CRYPTO_VERSION];
    salt.extend_from_slice(request.exit_peer_id.as_bytes());
    salt.extend_from_slice(REQUEST_TAG.as_bytes());
    let (cipher, iv ) = initialize_cipher(&shared_presecret, counter, salt.as_slice(), 0)?;

    // Decrypt the response
    let plain_text = cipher.decrypt(Nonce::from_slice(iv.as_slice()), &message[1+PUBLIC_KEYSIZE_ENCODED+COUNTER_SIZE..])
        .map_err(|e| RpchCryptoError::CryptographicError(e.to_string()))?;

    if counter+COUNTER_GRACE_AMOUNT <= client_counter {
        return Err(RpchCryptoError::VerificationFailed)
    }

    Ok(Session {
        req_data: Some(plain_text.into_boxed_slice()),
        resp_data: None,
        counter,
        shared_presecret: Some(shared_presecret)
    })

}

const RESPONSE_TAG: &str = "resp";

/// Called by the Exit node
pub fn box_response(session: &mut Session, response: Envelope) ->  Result<()> {
    let shared_presecret = session.shared_presecret.as_ref().ok_or(RpchCryptoError::InvalidSession)?;

    // Obtain the exit node counter value and increase it by 1
    let new_counter = session.counter() + 1;

    // Create the salt for the request and initialize the cipher
    let mut salt = vec![RPCH_CRYPTO_VERSION];
    salt.extend_from_slice(response.entry_peer_id.as_bytes());
    salt.extend_from_slice(RESPONSE_TAG.as_bytes());
    let (cipher, iv) = initialize_cipher(&shared_presecret, new_counter, salt.as_slice(), 1)?;

    // Encrypt and authenticate the request
    let cipher_text = cipher.encrypt(Nonce::from_slice(iv.as_slice()), response.message.as_ref())
        .map_err(|e| RpchCryptoError::CryptographicError(e.to_string()))?;

    // Construct the result
    let mut result: Vec<u8> = Vec::new();
    result.extend_from_slice(&new_counter.to_be_bytes()); // C
    result.extend(cipher_text.iter()); // R,T

    session.resp_data = Some(result.into_boxed_slice());
    session.counter = new_counter;
    session.shared_presecret = None; // Invalidate the session

    Ok(())
}

/// Called by the RPCh Client
pub fn unbox_response(session: &mut Session, response: Envelope) -> Result<()> {
    let shared_presecret = session.shared_presecret.as_ref().ok_or(RpchCryptoError::InvalidSession)?;

    let message = response.message();

    let mut counter_bytes = [0u8; COUNTER_SIZE];
    counter_bytes.copy_from_slice(&message[0..COUNTER_SIZE]);
    let counter = u64::from_be_bytes(counter_bytes);

    // Create the salt for the request and initialize the cipher
    let mut salt = vec![RPCH_CRYPTO_VERSION];
    salt.extend_from_slice(response.entry_peer_id.as_bytes());
    salt.extend_from_slice(RESPONSE_TAG.as_bytes());
    let (cipher, iv ) = initialize_cipher(shared_presecret, counter, salt.as_slice(), 1)?;

    // Decrypt the response
    let plain_text = cipher.decrypt(Nonce::from_slice(iv.as_slice()), &message[COUNTER_SIZE..])
        .map_err(|e| RpchCryptoError::CryptographicError(e.to_string()))?;

    if counter+COUNTER_GRACE_AMOUNT <= session.counter() {
        return Err(RpchCryptoError::VerificationFailed)
    }

    session.resp_data = Some(plain_text.into_boxed_slice());
    session.counter = counter;
    session.shared_presecret = None; // Invalidate session

    Ok(())
}

/// Unit tests of pure Rust code
#[cfg(test)]
mod tests {
    use std::str::FromStr;
    use super::*;

    use k256::{NonZeroScalar, PublicKey};

    const EXIT_NODE_SK: &str = "06EF2A621EB9DF81F7D6A8F7A2499B9E670613F757648DC3258640767EBD7E0A";

    const EXIT_NODE: &str = "16Uiu2HAmUsJwbECMroQUC29LQZZWsYpYZx1oaM1H9DBoZHLkYn12";
    const ENTRY_NODE: &str = "16Uiu2HAm35DuQk2Cvp9aLpRTD43ZubLqtbAwf242w2YmAe8FskLs";

    #[test]
    fn test_request() {

        let exit_sk = NonZeroScalar::from_str(EXIT_NODE_SK).unwrap();
        let exit_sk_bytes = exit_sk.to_bytes();
        let exit_pk = PublicKey::from_secret_scalar(&exit_sk);

        let exit_id = Identity::new(EncodedPoint::from(exit_pk).as_bytes(), Some(0), None)
            .expect("failed to create exit node identity");

        let request_data = "Hello world!";

        let request_session = box_request(Envelope::new(request_data.as_bytes(), ENTRY_NODE, EXIT_NODE), &exit_id)
            .expect("failed to box request");

        let data_on_wire = request_session.get_request_data().expect("no request data");
        assert_eq!(1, request_session.counter());

        let exit_own_id = Identity::new(EncodedPoint::from(exit_pk).as_bytes(), None,Some(exit_sk_bytes.as_slice().into()))
            .expect("failed to own exit node identity");

        let response_session = unbox_request(Envelope::new(data_on_wire.as_ref(), ENTRY_NODE, EXIT_NODE), &exit_own_id, 0)
            .expect("failed to unbox request");

        let retrieved_data = response_session.get_request_data().expect("no response data");

        let request_str = String::from_utf8(retrieved_data.into_vec()).expect("failed to decode response string");
        assert_eq!(request_data, request_str);
        assert_eq!(1, response_session.counter());
    }

    #[test]
    fn test_response() {
        let exit_sk = NonZeroScalar::from_str(EXIT_NODE_SK).unwrap();
        let exit_pk = PublicKey::from_secret_scalar(&exit_sk);

        let ss = EphemeralSecret::random(&mut OsRng);

        let response_data = "Hello from Infura!";

        let mut mock_exit_session = Session {
            req_data: None,
            resp_data: None,
            counter: 1,
            shared_presecret: Some(ss.diffie_hellman(&exit_pk))
        };

        box_response(&mut mock_exit_session, Envelope::new(response_data.as_bytes(), ENTRY_NODE, EXIT_NODE))
            .expect("failed to box response");

        let data_on_wire = mock_exit_session.get_response_data().expect("failed to get response data");
        assert_eq!(2, mock_exit_session.counter());

        let mut mock_client_session = Session {
            req_data: None,
            resp_data: None,
            counter: 1,
            shared_presecret: Some(ss.diffie_hellman(&exit_pk))
        };

        unbox_response(&mut mock_client_session, Envelope::new(data_on_wire.as_ref(), ENTRY_NODE, EXIT_NODE))
            .expect("failed to unbox response");

        let unboxed_response = mock_client_session.get_response_data().expect("failed to obtain response data");

        assert_eq!(response_data.as_bytes(), unboxed_response.as_ref());
        assert_eq!(2, mock_client_session.counter())
    }

}

/// Module for WASM wrappers of Rust code
pub mod wasm {
    use std::fmt::Display;
    use wasm_bindgen::prelude::*;

    pub fn as_jsvalue<T>(v: T) -> JsValue where T: Display {
        JsValue::from(v.to_string())
    }

    #[wasm_bindgen]
    pub struct Session {
        w: super::Session
    }

    #[wasm_bindgen]
    impl Session {

        pub fn get_request_data(&self) -> Result<Box<[u8]>, JsValue> {
            self.w.get_request_data()
                .ok_or("no request data".into())
        }

        pub fn get_response_data(&self) -> Result<Box<[u8]>, JsValue> {
            self.w.get_response_data()
                .ok_or("no response data".into())
        }

        pub fn counter(&self) -> u64 {
            self.w.counter()
        }
    }

    #[wasm_bindgen]
    pub struct Identity {
        w: super::Identity
    }

    #[wasm_bindgen]
    impl Identity {
        pub fn load_identity(public_key: &[u8], private_key: Option<Box<[u8]>>, counter: Option<u64>) -> Result<Identity, JsValue> {
            Ok(Identity {
                w: super::Identity::new(public_key, counter, private_key).map_err(as_jsvalue)?
            })
        }
    }

    #[wasm_bindgen]
    pub struct Envelope {
        w: super::Envelope
    }

    #[wasm_bindgen]
    impl Envelope {

        #[wasm_bindgen(constructor)]
        pub fn new(message: &[u8], entry_peer_id: &str, exit_peer_id: &str) -> Envelope {
            Envelope {
                w: super::Envelope::new(message, entry_peer_id, exit_peer_id)
            }
        }
    }

    #[wasm_bindgen]
    pub fn box_request(request: Envelope, exit_node: &Identity) -> Result<Session, JsValue> {
        super::box_request(request.w, &exit_node.w)
            .map(|s| Session { w: s })
            .map_err(as_jsvalue)
    }

    #[wasm_bindgen]
    pub fn unbox_request(message: Envelope, my_id: &Identity, client_counter: u64) -> Result<Session, JsValue> {
        super::unbox_request(message.w, &my_id.w, client_counter)
            .map(|s| Session { w: s })
            .map_err(as_jsvalue)
    }

    #[wasm_bindgen]
    pub fn box_response(session: &mut Session, response: Envelope) ->  Result<(), JsValue> {
        super::box_response(&mut session.w, response.w)
            .map_err(as_jsvalue)
    }

    #[wasm_bindgen]
    pub fn unbox_response(session: &mut Session, message: Envelope) -> Result<(), JsValue> {
        super::unbox_response(&mut session.w, message.w)
            .map_err(as_jsvalue)
    }
}
