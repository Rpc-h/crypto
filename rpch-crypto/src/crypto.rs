use blake2::Blake2s256;
use chacha20poly1305::{ChaCha20Poly1305, KeyInit, Nonce};
use chacha20poly1305::aead::Aead;
use k256::{PublicKey, SecretKey, ecdh::EphemeralSecret, EncodedPoint};
use elliptic_curve::rand_core::OsRng;

use thiserror::Error;

pub const RPCH_CRYPTO_VERSION: u8 = 0x11;

const CIPHER_KEYSIZE: usize = 32;
const CIPHER_IVSIZE: usize = 12;

#[derive(Error, Debug)]
pub enum RpchCryptoError {

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
    client_pub: Option<PublicKey>,
    exit_pub: Option<PublicKey>,
    client_counter: u64,
    exit_counter: u64,
    valid: bool
}

impl Session {

    pub fn valid(&self) -> bool {
        self.valid
    }

    pub fn get_request_data(&self) -> Option<Box<[u8]>> {
        assert!(self.valid, "session not valid");
        self.req_data.clone()
    }

    pub fn get_response_data(&self) -> Option<Box<[u8]>> {
        assert!(self.valid, "session not valid");
        self.resp_data.clone()
    }

    pub fn get_client_public_key(&self) -> Option<PublicKey> {
        assert!(self.valid, "session not valid");
        self.client_pub.clone()
    }

    pub fn get_exit_node_public_key(&self) -> Option<PublicKey> {
        assert!(self.valid, "session not valid");
        self.exit_pub.clone()
    }

    pub fn get_client_node_counter(&self) -> u64 {
        assert!(self.valid, "session not valid");
        self.client_counter
    }

    pub fn get_exit_node_counter(&self) -> u64 {
        assert!(self.valid, "session not valid");
        self.exit_counter
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

/// Called by the RPCh client
pub fn box_request(request: Envelope, exit_node: &Identity) -> Result<Session> {
    // Generate random ephemeral key
    let ephemeral_key = EphemeralSecret::random(&mut OsRng);

    // Prepare the salt for the KDF
    let mut salt = vec![RPCH_CRYPTO_VERSION];
    salt.extend_from_slice(request.exit_peer_id.as_bytes());
    salt.extend_from_slice(REQUEST_TAG.as_bytes());

    // Perform the Diffie-Hellman step using the Exit node's public key & initialize the KDF using the shared pre-secret
    let shared_presecret = ephemeral_key.diffie_hellman(&exit_node.pubkey);
    let kdf = shared_presecret.extract::<Blake2s256>(Some(salt.as_slice()));

    // Generate the encryption key using the KDF
    let mut key = [0u8; CIPHER_KEYSIZE];
    kdf.expand(&[0u8; 1], &mut key)
        .map_err(|e| RpchCryptoError::CryptographicError(e.to_string()))?;

    // Generate the first part of the IV from shared pre-secret
    let mut ivm = [0u8; CIPHER_IVSIZE - 8];
    kdf.expand(&[0u8; 1], &mut ivm)
        .map_err(|e| RpchCryptoError::CryptographicError(e.to_string()))?;

    // Obtain the last seen value of the exit node's counter and increment it by 1
    let new_counter = exit_node.counter().ok_or(RpchCryptoError::InvalidCounter)? + 1;

    // Construct the final IV using the generated prefix and the new counter
    let mut iv = Vec::from(ivm);
    iv.extend_from_slice(&new_counter.to_be_bytes());

    // Initialize the cipher with the key and the IV
    let cipher = ChaCha20Poly1305::new_from_slice(&key)
        .map_err(|e| RpchCryptoError::CryptographicError(e.to_string()))?;

    // Encrypt and authenticate the request
    let cipher_text = cipher.encrypt(Nonce::from_slice(&iv), request.message.as_ref())
        .map_err(|e| RpchCryptoError::CryptographicError(e.to_string()))?;

    // Construct the result
    let mut result = vec![RPCH_CRYPTO_VERSION]; // Version
    result.extend_from_slice(EncodedPoint::from(ephemeral_key.public_key()).as_bytes()); // W
    result.extend_from_slice(&new_counter.to_be_bytes()); // C
    result.extend(cipher_text.iter()); // R,T

    Ok(Session {
        req_data: Some(result.into_boxed_slice()),
        resp_data: None,
        exit_pub: Some(exit_node.pubkey),
        client_counter: new_counter,
        client_pub: None,
        valid: true,
        exit_counter: 0,
    })
}

/// Called by the Exit node
pub fn unbox_request(request: Envelope, my_id: &Identity) -> Result<Session> {
    Err(RpchCryptoError::NotImplemented)
}

/// Called by the Exit node
pub fn box_response(session: &mut Session, response: Envelope, client: &Identity) ->  Result<()> {
    Err(RpchCryptoError::NotImplemented)
}

/// Called by the RPCh Client
pub fn unbox_response(session: &mut Session, response: Envelope, my_id: &Identity) -> Result<()> {
    Err(RpchCryptoError::NotImplemented)
}

/// Unit tests of pure Rust code
#[cfg(test)]
mod tests {
    use std::str::FromStr;
    use super::*;

    use k256::{NonZeroScalar, PublicKey};

    const EXIT_NODE_SK: &str = "06EF2A621EB9DF81F7D6A8F7A2499B9E670613F757648DC3258640767EBD7E0A";
    const CLIENT_NODE_SK: &str = "C68A46C26A26E3D96CE2B02D2E0B90D3AC53374A6783D19D5114B9D1C0DF97DD";

    const EXIT_NODE: &str = "16Uiu2HAmUsJwbECMroQUC29LQZZWsYpYZx1oaM1H9DBoZHLkYn12";
    const ENTRY_NODE: &str = "16Uiu2HAm35DuQk2Cvp9aLpRTD43ZubLqtbAwf242w2YmAe8FskLs";

    //#[test]
    fn test_request() {

        let exit_sk = NonZeroScalar::from_str(EXIT_NODE_SK).unwrap();
        let exit_sk_bytes = exit_sk.to_bytes();
        let exit_pk = PublicKey::from_secret_scalar(&exit_sk);


        let exit_id = Identity::new(EncodedPoint::from(exit_pk).as_bytes(), Some(0), None)
            .expect("failed to create exit node identity");

        let request_data = "Hello world!";

        let request_session = box_request(Envelope::new(request_data.as_bytes(), ENTRY_NODE, EXIT_NODE), &exit_id)
            .expect("failed to box request");

        assert!(request_session.valid(), "request session not valid");

        let data_on_wire = request_session.get_request_data().expect("no request data");

        let exit_own_id = Identity::new(EncodedPoint::from(exit_pk).as_bytes(), None,Some(exit_sk_bytes.as_slice().into()))
            .expect("failed to own exit node identity");

        let response_session = unbox_request(Envelope::new(data_on_wire.as_ref(), ENTRY_NODE, EXIT_NODE), &exit_own_id)
            .expect("failed to unbox request");

        assert!(response_session.valid());

        let retrieved_data = response_session.get_response_data().expect("no response data");

        assert_eq!(request_data.as_bytes(), retrieved_data.as_ref());
    }

    //#[test]
    fn test_response() {
        let client_sk = NonZeroScalar::from_str(CLIENT_NODE_SK).unwrap();
        let client_sk_bytes = client_sk.to_bytes();
        let client_pk = PublicKey::from_secret_scalar(&client_sk);


        let client_id = Identity::new(EncodedPoint::from(client_pk).as_bytes(), Some(0), None)
            .expect("failed to create client node identity");

        let response_data = "Hello from Infura!";

        let mut mock_exit_session = Session {
            req_data: None,
            resp_data: None,
            client_pub: None,
            exit_pub: None,
            client_counter: 1,
            exit_counter: 0,
            valid: true
        };

        box_response(&mut mock_exit_session, Envelope::new(response_data.as_bytes(), ENTRY_NODE, EXIT_NODE), &client_id)
            .expect("failed to box response");

        assert!(mock_exit_session.valid());

        let data_on_wire = mock_exit_session.get_response_data().expect("failed to get response data");

        let client_own_id = Identity::new(EncodedPoint::from(client_pk).as_bytes(), None, Some(client_sk_bytes.as_slice().into()))
            .expect("failed to create client own id");

        let mut mock_client_session = Session {
            req_data: None,
            resp_data: None,
            client_pub: None,
            exit_pub: None,
            client_counter: 1,
            exit_counter: 0,
            valid: true
        };

        unbox_response(&mut mock_client_session, Envelope::new(data_on_wire.as_ref(), ENTRY_NODE, EXIT_NODE), &client_own_id)
            .expect("failed to unbox response");

        assert!(mock_client_session.valid());

        let unboxed_response = mock_client_session.get_response_data().expect("failed to obtain response data");

        assert_eq!(response_data.as_bytes(), unboxed_response.as_ref());
    }

}

/// Module for WASM wrappers of Rust code
pub mod wasm {
    use std::fmt::Display;
    use k256::{EncodedPoint, PublicKey, SecretKey};
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

        pub fn valid(&self) -> bool {
            self.w.valid()
        }

        pub fn get_request_data(&self) -> Result<Box<[u8]>, JsValue> {
            self.w.get_request_data()
                .ok_or("no request data".into())
        }

        pub fn get_response_data(&self) -> Result<Box<[u8]>, JsValue> {
            self.w.get_response_data()
                .ok_or("no response data".into())
        }

        pub fn get_client_public_key(&self) -> Result<Box<[u8]>, JsValue> {
            self.w.get_client_public_key()
                .map(|k| Box::from(EncodedPoint::from(k).as_bytes()))
                .ok_or("no client public key".into())
        }

        pub fn get_exit_node_public_key(&self) -> Result<Box<[u8]>, JsValue> {
            self.w.get_exit_node_public_key()
                .map(|k| Box::from(EncodedPoint::from(k).as_bytes()))
                .ok_or("no exit node public key".into())

        }

        pub fn get_client_node_counter(&self) -> u64 {
            self.w.get_client_node_counter()
        }

        pub fn get_exit_node_counter(&self) -> u64 {
            self.w.get_exit_node_counter()
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
    pub fn unbox_request(message: Envelope, my_id: &Identity) -> Result<Session, JsValue> {
        super::unbox_request(message.w, &my_id.w)
            .map(|s| Session { w: s })
            .map_err(as_jsvalue)
    }

    #[wasm_bindgen]
    pub fn box_response(session: &mut Session, response: Envelope, client: &Identity) ->  Result<(), JsValue> {
        super::box_response(&mut session.w, response.w, &client.w)
            .map_err(as_jsvalue)
    }

    #[wasm_bindgen]
    pub fn unbox_response(session: &mut Session, message: Envelope, my_id: &Identity) -> Result<(), JsValue> {
        super::unbox_response(&mut session.w, message.w, &my_id.w)
            .map_err(as_jsvalue)
    }
}

