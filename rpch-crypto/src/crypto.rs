use k256::{PublicKey, SecretKey, ecdh::EphemeralSecret, EncodedPoint};
use elliptic_curve::rand_core::OsRng;

use thiserror::Error;

#[derive(Error, Debug)]
pub enum RpchCryptoError {
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
    req_counter: u64,
    resp_counter: u64,
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
        self.req_counter
    }

    pub fn get_exit_node_counter(&self) -> u64 {
        assert!(self.valid, "session not valid");
        self.resp_counter
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

/// Called by the RPCh client
pub fn box_request(request: Envelope, exit_node: &Identity) -> Result<Session> {
    Err(RpchCryptoError::NotImplemented)
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
    use elliptic_curve::rand_core::OsRng;
    use super::*;

    use k256::{NonZeroScalar, PublicKey, SecretKey};

    const EXIT_NODE: &str = "16Uiu2HAmUsJwbECMroQUC29LQZZWsYpYZx1oaM1H9DBoZHLkYn12";
    const ENTRY_NODE: &str = "16Uiu2HAm35DuQk2Cvp9aLpRTD43ZubLqtbAwf242w2YmAe8FskLs";

    #[test]
    fn test_request() {

        let our_sk = NonZeroScalar::random(&mut OsRng);
        let our_pk = PublicKey::from_secret_scalar(&our_sk);

        let exit_sk = NonZeroScalar::random(&mut OsRng);
        let exit_pk = PublicKey::from_secret_scalar(&exit_sk);


        // TODO: Add more unit tests
    }

}

/// Module for WASM wrappers of Rust code
pub mod wasm {
    use std::fmt::Display;
    use k256::{EncodedPoint, PublicKey, SecretKey};
    use k256::Secp256k1;
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

