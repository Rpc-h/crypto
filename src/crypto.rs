use blake2::Blake2s256;
use chacha20poly1305::{ChaCha20Poly1305, KeyInit, Nonce};
use chacha20poly1305::aead::Aead;
use elliptic_curve::ecdh::diffie_hellman;
use k256::{PublicKey, SecretKey, ecdh::EphemeralSecret, EncodedPoint};
use elliptic_curve::rand_core::{CryptoRng, OsRng, RngCore};
use k256::ecdh::SharedSecret;

use thiserror::Error;

/// Current version of the protocol.
pub const RPCH_CRYPTO_VERSION: u8 = 0x12;

// Private constants
type CounterType = u64;
const PUBLIC_KEYSIZE_ENCODED: usize = 33;
const CIPHER_KEYSIZE: usize = 32;
const CIPHER_IVSIZE: usize = 12;
const COUNTER_SIZE: usize = std::mem::size_of::<CounterType>();

/// Contains all error messages that could be returned by
/// the protocol functions.
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
    #[error("low level cryptographic error: {0}")]
    CryptographicError(String),
    #[error("not implemented")]
    NotImplemented
}

type Result<T> = core::result::Result<T, RpchCryptoError>;

/// Represent an inclusive counter bound for verification
/// against replay attacks.
pub struct CounterBound {
    lower: CounterType,
    upper: Option<CounterType>,
    tolerance: Option<CounterType>
}

impl CounterBound {
    pub fn validate(&self, value: CounterType) -> bool {
        let tol = self.tolerance.unwrap_or(0) as i128;
        let lower_diff = value as i128 - self.lower as i128;
        let upper_diff = self.upper.unwrap_or(value) as i128 - value as i128;

        lower_diff >= -tol && upper_diff >= -tol
    }
}

/// Represents a request-response session.
pub struct Session {
    req_data: Option<Box<[u8]>>,
    resp_data: Option<Box<[u8]>>,
    counter: CounterType,
    shared_presecret: Option<SharedSecret>,
}

impl Session {

    pub fn get_request_data(&self) -> Option<Box<[u8]>> {
        self.req_data.clone()
    }

    pub fn get_response_data(&self) -> Option<Box<[u8]>> {
        self.resp_data.clone()
    }

    pub fn updated_counter(&self) -> CounterType {
        self.counter
    }
}

/// Identifies a party in the protocol.
/// If the party is remote, only the public key is populated.
/// If the party is local, also the secret key is populated.
pub struct Identity {
    pubkey: PublicKey,
    secret_key: Option<SecretKey>
}

impl Identity {
    pub fn new(public_key: &[u8], private_key: Option<Box<[u8]>>) -> Result<Identity> {
        let pk = PublicKey::from_sec1_bytes(public_key)
            .map_err(|e| RpchCryptoError::CryptographicError(e.to_string()))?;

        let sk = match private_key {
            None => None,
            Some(k) => Some(SecretKey::from_be_bytes(k.as_ref())
                .map_err(|e| RpchCryptoError::CryptographicError(e.to_string()))?)
        };

        Ok(Identity {
            pubkey: pk,
            secret_key: sk
        })
    }
}

/// Wrapper for the request/response data
/// along with the peer ID of the HOPR entry node and exit node
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

fn initialize_cipher(shared_presecret: &SharedSecret, counter: u64, salt: &[u8], start_index: u8) -> Result<(ChaCha20Poly1305, Vec<u8>)> {
    let kdf = shared_presecret.extract::<Blake2s256>(Some(salt));

    let mut key = [0u8; CIPHER_KEYSIZE];
    let mut ivm = [0u8; CIPHER_IVSIZE - COUNTER_SIZE];

    // Generate the encryption key using the KDF
    kdf.expand(&[start_index; 1], &mut key)
        .map_err(|e| RpchCryptoError::CryptographicError(e.to_string()))?;

    // Generate the first part of the IV from shared pre-secret
    kdf.expand(&[start_index + 1; 1], &mut ivm)
        .map_err(|e| RpchCryptoError::CryptographicError(e.to_string()))?;

    // Construct the final IV using the generated prefix and the new counter
    let mut iv = Vec::from(ivm);
    iv.extend_from_slice(&counter.to_be_bytes());

    // Initialize the cipher with the key and the IV
    Ok((ChaCha20Poly1305::new_from_slice(&key)
        .map_err(|e| RpchCryptoError::CryptographicError(e.to_string()))?, iv))
}

/// Called by the RPCh client
/// Takes enveloped request data, the identity of the RPCh Exit Node and Request counter for such
/// RPCh Exit node and then encrypts and authenticates the data.
/// The encrypted data and new counter value to be persisted is returned in the resulting session.
/// The counter can be also represented by a UTC timestamp.
pub fn box_request(request: Envelope, exit_node: &Identity, exit_request_counter: CounterType) -> Result<Session> {
    box_request_int(request, exit_node, exit_request_counter, &mut OsRng)
}

pub(crate) fn box_request_int(request: Envelope, exit_node: &Identity, exit_request_counter: CounterType, rng: impl CryptoRng + RngCore) -> Result<Session> {
    // Generate random ephemeral key
    let ephemeral_key = EphemeralSecret::random(rng);

    // Perform the Diffie-Hellman step using the Exit node's public key & initialize the KDF using the shared pre-secret
    let shared_presecret = ephemeral_key.diffie_hellman(&exit_node.pubkey);

    // Obtain the exit node counter value and increase it by 1
    let new_counter = exit_request_counter + 1;

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

/// Called by the RPCh Exit Node
/// Takes enveloped encrypted data, the local identity of the RPCh Exit Node and Request counter for
/// RPCh Client node associated with the request and then decrypts and verifies the data.
/// The decrypted data and new counter value to be persisted is returned in the resulting session.
/// The counter can be also represented by a UTC timestamp.
pub fn unbox_request(request: Envelope, my_id: &Identity, client_request_counter: CounterBound) -> Result<Session> {
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

    if !client_request_counter.validate(counter) {
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

/// Called by the RPCh Exit Node
/// Takes enveloped response data, the request session obtained by unbox_request and Response counter for the associated
/// RPCh Client node and then encrypts and authenticates the data.
/// The encrypted data and new counter value to be persisted is returned in the resulting session.
/// The counter can be also represented by a UTC timestamp.
pub fn box_response(session: &mut Session, response: Envelope, client_response_counter: CounterType) ->  Result<()> {
    let shared_presecret = session.shared_presecret.as_ref().ok_or(RpchCryptoError::InvalidSession)?;

    // Obtain the exit node counter value and increase it by 1
    let new_counter = client_response_counter + 1;

    // Create the salt for the request and initialize the cipher
    let mut salt = vec![RPCH_CRYPTO_VERSION];
    salt.extend_from_slice(response.entry_peer_id.as_bytes());
    salt.extend_from_slice(RESPONSE_TAG.as_bytes());
    let (cipher, iv) = initialize_cipher(&shared_presecret, new_counter, salt.as_slice(), 2)?;

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

/// Called by the RPCh Client Node
/// Takes enveloped encrypted data, the associated session returned by box_request and Request counter for
/// RPCh Exit node associated with the response and then decrypts and verifies the data.
/// The decrypted data and new counter value to be persisted is returned in the resulting session.
/// The counter can be also represented by a UTC timestamp.
pub fn unbox_response(session: &mut Session, response: Envelope, exit_response_counter: CounterBound) -> Result<()> {
    let shared_presecret = session.shared_presecret.as_ref().ok_or(RpchCryptoError::InvalidSession)?;

    let message = response.message();

    let mut counter_bytes = [0u8; COUNTER_SIZE];
    counter_bytes.copy_from_slice(&message[0..COUNTER_SIZE]);
    let counter = u64::from_be_bytes(counter_bytes);

    // Create the salt for the request and initialize the cipher
    let mut salt = vec![RPCH_CRYPTO_VERSION];
    salt.extend_from_slice(response.entry_peer_id.as_bytes());
    salt.extend_from_slice(RESPONSE_TAG.as_bytes());
    let (cipher, iv ) = initialize_cipher(shared_presecret, counter, salt.as_slice(), 2)?;

    // Decrypt the response
    let plain_text = cipher.decrypt(Nonce::from_slice(iv.as_slice()), &message[COUNTER_SIZE..])
        .map_err(|e| RpchCryptoError::CryptographicError(e.to_string()))?;

    if !exit_response_counter.validate(counter) {
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

    #[test]
    fn test_counter_bound_lower() {
        let t = CounterBound {
            lower: 10,
            upper: None,
            tolerance: None,
        };

        assert!(t.validate(11));
        assert!(t.validate(10));
        assert!(!t.validate(9));
    }

    #[test]
    fn test_counter_bound_upper() {
        let t = CounterBound {
            lower: 10,
            upper: Some(15),
            tolerance: None,
        };

        assert!(t.validate(11));
        assert!(t.validate(10));
        assert!(!t.validate(9));

        assert!(t.validate(14));
        assert!(t.validate(15));
        assert!(!t.validate(16));
    }

    #[test]
    fn test_counter_bound_lower_tolerance() {
        let t = CounterBound {
            lower: 10,
            upper: Some(15),
            tolerance: Some(1),
        };

        assert!(t.validate(11));
        assert!(t.validate(9));
        assert!(t.validate(10));
        assert!(!t.validate(8));

        assert!(t.validate(14));
        assert!(t.validate(15));
        assert!(t.validate(16));
        assert!(!t.validate(17));
    }

    const EXIT_NODE_SK: &str = "06EF2A621EB9DF81F7D6A8F7A2499B9E670613F757648DC3258640767EBD7E0A";
    const EXIT_NODE: &str = "16Uiu2HAmUsJwbECMroQUC29LQZZWsYpYZx1oaM1H9DBoZHLkYn12";
    const ENTRY_NODE: &str = "16Uiu2HAm35DuQk2Cvp9aLpRTD43ZubLqtbAwf242w2YmAe8FskLs";

    const TEST_EPHEMERAL_PRIVATE_KEY: &str = "492057cf93e99b31d2a85bc5e98a9c3aa0021feec52c227cc8170e8f7d047775";
    const TEST_VECTOR_REQUEST_INPUT: &str = "e1afa1e0a0a3e482bce0be80e39ca4e5a0a4e681b3d1a0e19ca8c390d7bbe380b9e69aa0e7a982ceb8cf92e4bebce7b0a5e589abe184b4c7b0e28ca0e38786e69f92e2a7a8c288e287b8c3b9e68587e19ba0e0a580e4baa439e4a8b44363d0a5e6968ac9a0e28580d297e294a8e4ad83e3ada0e2b6b2e399ace2a192e1a58ee380a7e6a58ee0aaaee680bae680aee280b5e69a89e29596e5a0bae495ace6beaee480a6e6a0a2e794a476e7b188e3a4bbe1b6b6e280a4e69a8050e480a1e3bab9e280a020";
    const TEST_VECTOR_REQUEST_OUTPUT: &str = "120239d1bc2291826eaed86567d225cf243ebc637275e0a5aedb0d6b1dc82136a38e000001856a69d98192302d2c0a27a012e61e086fcac4977d61805617aace48a42cc6d37d4cf7276a39c0cc81de4da122d1ead7c0ae047ae727ca788c17137455caf712265e84edeca71e5cf80119d30e09e55a9d4546178cbc254004ffa780166f154516939033e8476bf6aa332706f604289c3e22fb5a9f93dc312b9d0981c44cc48344e4f8db3e6b2a9b3d0365d5b4a96e51eae57709db62f72ce4768e88f054f8634655e6938d05e02179e308b579f352ef039e5e3f56925c03f05058b305f6f792a7e6a31ac3faace94fa667ea5254bc6937d6c7f2cc3cb4f134";

    const TEST_VECTOR_RESPONSE_INPUT: &str = "e1afa1e0a0b3e485ace0b480dcb0e19d88cb92e48496c7b9e48ca3e0b0b2c2b8c7b0c2812dd0a1e198a0e4b490da8ae59693e68da0e197a0e0b6a0e19d9de490a1e780b1e4b5b8e48193e1bca0e18790e4a0a0e5bd89e280a020";
    const TEST_VECTOR_RESPONSE_OUTPUT: &str = "000001856a69d9816d0a1e6ed9cfe3b95125d3ae02400ea86d869fce21b7e6241d22dbe911182c51345c8eb13ebc9c5cf9989e7e0f9cac2cd2a3026cc06d6fca6f2df1b45ee17f94543194b0f7f285cf261348b729fd78d6bb9a2021ca947b49f3ccbc36d43eea6efef2c4e25c205bb1286d";
    const TEST_COUNTER: u64 = 1672527600000;

    struct TestRng;

    impl CryptoRng for TestRng {}

    impl RngCore for TestRng {
        fn next_u32(&mut self) -> u32 {
            unimplemented!()
        }

        fn next_u64(&mut self) -> u64 {
            unimplemented!()
        }

        fn fill_bytes(&mut self, dest: &mut [u8]) {
            self.try_fill_bytes(dest).unwrap()
        }

        fn try_fill_bytes(&mut self, dest: &mut [u8]) -> std::result::Result<(), elliptic_curve::rand_core::Error> {
            dest.copy_from_slice(&hex::decode(TEST_EPHEMERAL_PRIVATE_KEY).unwrap());
            Ok(())
        }
    }

    #[test]
    fn test_request_test_vector() {
        let exit_sk = NonZeroScalar::from_str(EXIT_NODE_SK).unwrap();
        let exit_sk_bytes = exit_sk.to_bytes();
        let exit_pk = PublicKey::from_secret_scalar(&exit_sk);

        let exit_id = Identity::new(EncodedPoint::from(exit_pk).as_bytes(), None)
            .expect("failed to create exit node identity");

        let request_session = box_request_int(Envelope::new(&hex::decode(TEST_VECTOR_REQUEST_INPUT).unwrap(), ENTRY_NODE, EXIT_NODE), &exit_id, TEST_COUNTER, &mut TestRng)
            .expect("failed to box request");

        let data_on_wire = request_session.get_request_data().expect("no request data");
        assert_eq!(TEST_COUNTER + 1, request_session.updated_counter());
        assert_eq!(TEST_VECTOR_REQUEST_OUTPUT, hex::encode(&data_on_wire));

        let exit_own_id = Identity::new(EncodedPoint::from(exit_pk).as_bytes(), Some(exit_sk_bytes.as_slice().into()))
            .expect("failed to own exit node identity");

        let response_session = unbox_request(Envelope::new(data_on_wire.as_ref(), ENTRY_NODE, EXIT_NODE), &exit_own_id,
                                             CounterBound { lower: TEST_COUNTER, upper: None, tolerance: None } )
            .expect("failed to unbox request");

        let retrieved_data = response_session.get_request_data().expect("no response data");

        let request_str = hex::encode(retrieved_data.into_vec());
        assert_eq!(TEST_VECTOR_REQUEST_INPUT, request_str);
        assert_eq!(TEST_COUNTER + 1, response_session.updated_counter());
    }

    #[test]
    fn test_request() {
        let exit_sk = NonZeroScalar::from_str(EXIT_NODE_SK).unwrap();
        let exit_sk_bytes = exit_sk.to_bytes();
        let exit_pk = PublicKey::from_secret_scalar(&exit_sk);

        let exit_id = Identity::new(EncodedPoint::from(exit_pk).as_bytes(), None)
            .expect("failed to create exit node identity");

        let request_data = "Hello world!";
        let request_counter = 0u64;

        let request_session = box_request(Envelope::new(request_data.as_bytes(), ENTRY_NODE, EXIT_NODE), &exit_id, request_counter)
            .expect("failed to box request");

        let data_on_wire = request_session.get_request_data().expect("no request data");
        assert_eq!(request_counter + 1, request_session.updated_counter());

        let exit_own_id = Identity::new(EncodedPoint::from(exit_pk).as_bytes(), Some(exit_sk_bytes.as_slice().into()))
            .expect("failed to own exit node identity");

        let response_session = unbox_request(Envelope::new(data_on_wire.as_ref(), ENTRY_NODE, EXIT_NODE), &exit_own_id,
                                             CounterBound { lower: request_counter, upper: None, tolerance: None } )
            .expect("failed to unbox request");

        let retrieved_data = response_session.get_request_data().expect("no response data");

        let request_str = String::from_utf8(retrieved_data.into_vec()).expect("failed to decode response string");
        assert_eq!(request_data, request_str);
        assert_eq!(request_counter + 1, response_session.updated_counter());
    }

    #[test]
    fn test_response_test_vector() {
        let exit_sk = NonZeroScalar::from_str(EXIT_NODE_SK).unwrap();
        let exit_pk = PublicKey::from_secret_scalar(&exit_sk);

        let ss = EphemeralSecret::random(&mut TestRng);

        let mut mock_exit_session = Session {
            req_data: None,
            resp_data: None,
            counter: 1,
            shared_presecret: Some(ss.diffie_hellman(&exit_pk))
        };

        box_response(&mut mock_exit_session, Envelope::new(&hex::decode(TEST_VECTOR_RESPONSE_INPUT).unwrap(), ENTRY_NODE, EXIT_NODE), TEST_COUNTER)
            .expect("failed to box response");

        let data_on_wire = mock_exit_session.get_response_data().expect("failed to get response data");
        assert_eq!(TEST_COUNTER + 1, mock_exit_session.updated_counter());
        assert_eq!(TEST_VECTOR_RESPONSE_OUTPUT, hex::encode(&data_on_wire));

        let mut mock_client_session = Session {
            req_data: None,
            resp_data: None,
            counter: 1,
            shared_presecret: Some(ss.diffie_hellman(&exit_pk))
        };

        unbox_response(&mut mock_client_session, Envelope::new(data_on_wire.as_ref(), ENTRY_NODE, EXIT_NODE),
                       CounterBound { lower: TEST_COUNTER, upper: None, tolerance: None })
            .expect("failed to unbox response");

        let unboxed_response = mock_client_session.get_response_data().expect("failed to obtain response data");

        assert_eq!(TEST_VECTOR_RESPONSE_INPUT, hex::encode(unboxed_response));
        assert_eq!(TEST_COUNTER + 1, mock_client_session.updated_counter())
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

        let resp_counter = 20u64;

        box_response(&mut mock_exit_session, Envelope::new(response_data.as_bytes(), ENTRY_NODE, EXIT_NODE), resp_counter)
            .expect("failed to box response");

        let data_on_wire = mock_exit_session.get_response_data().expect("failed to get response data");
        assert_eq!(resp_counter + 1, mock_exit_session.updated_counter());

        let mut mock_client_session = Session {
            req_data: None,
            resp_data: None,
            counter: 1,
            shared_presecret: Some(ss.diffie_hellman(&exit_pk))
        };

        unbox_response(&mut mock_client_session, Envelope::new(data_on_wire.as_ref(), ENTRY_NODE, EXIT_NODE),
                       CounterBound { lower: resp_counter, upper: None, tolerance: None })
            .expect("failed to unbox response");

        let unboxed_response = mock_client_session.get_response_data().expect("failed to obtain response data");

        assert_eq!(response_data.as_bytes(), unboxed_response.as_ref());
        assert_eq!(resp_counter + 1, mock_client_session.updated_counter())
    }

}

/// Module for WASM wrappers of Rust code
pub mod wasm {
    use crate::crypto::CounterBound;

    use std::fmt::Display;
    use wasm_bindgen::prelude::*;

    #[cfg(feature = "timestamps")]
    use js_sys::Date;

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

        pub fn updated_counter(&self) -> u64 {
            self.w.updated_counter()
        }
    }

    #[wasm_bindgen]
    pub struct Identity {
        w: super::Identity
    }

    #[wasm_bindgen]
    impl Identity {
        pub fn load_identity(public_key: &[u8], private_key: Option<Box<[u8]>>) -> Result<Identity, JsValue> {
            Ok(Identity {
                w: super::Identity::new(public_key, private_key).map_err(as_jsvalue)?
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

    #[cfg(not(feature = "timestamps"))]
    #[wasm_bindgen]
    pub fn box_request(request: Envelope, exit_node: &Identity, exit_request_counter: u64) -> Result<Session, JsValue> {
        super::box_request(request.w, &exit_node.w, exit_request_counter)
            .map(|s| Session { w: s })
            .map_err(as_jsvalue)
    }

    #[cfg(feature = "timestamps")]
    #[wasm_bindgen]
    pub fn box_request(request: Envelope, exit_node: &Identity) -> Result<Session, JsValue> {
        let current_ts = Date::now() as u64;
        super::box_request(request.w, &exit_node.w, current_ts)
            .map(|s| Session { w: s })
            .map_err(as_jsvalue)
    }

    #[cfg(not(feature = "timestamps"))]
    #[wasm_bindgen]
    pub fn unbox_request(message: Envelope, my_id: &Identity, client_request_counter: u64) -> Result<Session, JsValue> {
        super::unbox_request(message.w, &my_id.w, CounterBound {
            lower: client_request_counter,
            upper: None,
            tolerance_upper: None,
            tolerance_lower: None,
        })
        .map(|s| Session { w: s })
        .map_err(as_jsvalue)
    }

    #[cfg(feature = "timestamps")]
    #[wasm_bindgen]
    pub fn unbox_request(message: Envelope, my_id: &Identity, client_last_request_ts: u64) -> Result<Session, JsValue> {
        let current_ts = Date::now() as u64;
        super::unbox_request(
            message.w,
            &my_id.w,
            CounterBound {
                lower: client_last_request_ts,
                upper: Some(current_ts),
                // set default tolerance to 30sec
                tolerance: Some(30000),
            },
        )
        .map(|s| Session { w: s })
        .map_err(as_jsvalue)
    }

    #[cfg(not(feature = "timestamps"))]
    #[wasm_bindgen]
    pub fn box_response(session: &mut Session, response: Envelope, client_response_counter: u64) ->  Result<(), JsValue> {
        super::box_response(&mut session.w, response.w, client_response_counter)
            .map_err(as_jsvalue)
    }

    #[cfg(feature = "timestamps")]
    #[wasm_bindgen]
    pub fn box_response(session: &mut Session, response: Envelope) ->  Result<(), JsValue> {
        let current_ts = Date::now() as u64;
        super::box_response(&mut session.w, response.w, current_ts)
            .map_err(as_jsvalue)
    }

    #[cfg(not(feature = "timestamps"))]
    #[wasm_bindgen]
    pub fn unbox_response(session: &mut Session, message: Envelope, exit_response_counter: u64) -> Result<(), JsValue> {
        super::unbox_response(&mut session.w, message.w, CounterBound {
            lower: exit_response_counter,
            upper: None,
            tolerance_upper: None,
            tolerance_lower: None,
        })
        .map_err(as_jsvalue)
    }

    #[cfg(feature = "timestamps")]
    #[wasm_bindgen]
    pub fn unbox_response(session: &mut Session, message: Envelope, exit_last_response_ts: u64) -> Result<(), JsValue> {
        let current_ts = Date::now() as u64;
        super::unbox_response(
            &mut session.w,
            message.w,
            CounterBound {
                lower: exit_last_response_ts,
                upper: Some(current_ts),
                // set default tolerance to 30sec
                tolerance: Some(30000),
            },
        )
        .map_err(as_jsvalue)
    }
}
