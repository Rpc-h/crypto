use k256::{PublicKey, SecretKey, ecdh::EphemeralSecret, EncodedPoint};
use elliptic_curve::rand_core::OsRng;

pub struct Session {

}

impl Session {

    pub fn valid(&self) -> bool {
        false
    }

    pub fn get_data(&self) -> Option<Box<[u8]>> {
        None
    }
}

pub struct Identity {
    counter: u64,
    pubkey: PublicKey,
    secret_key: Option<SecretKey>
}

impl Identity {

    pub fn new(counter: u64, public_key: PublicKey, private_key: Option<SecretKey>) -> Identity {
        Identity {
            counter,
            pubkey: public_key,
            secret_key: private_key
        }
    }

    pub fn counter(&self) -> u64 {
        self.counter
    }

    fn increment(&mut self) {
        self.counter = self.counter+1
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
pub fn box_request(request: &Envelope, exit_node: &Identity) -> Result<Session, String> {
    Err("not implemented".into())
}

/// Called by the Exit node
pub fn unbox_request(request: &Envelope, my_id: &Identity) -> Result<Session, String> {
    Err("not implemented".into())
}

/// Called by the Exit node
pub fn box_response(session: &Session, response: &Envelope, client: &Identity) ->  Result<Session, String> {
    Err("not implemented".into())
}

/// Called by the RPCh Client
pub fn unbox_response(session: &Session, response: &Envelope, my_id: &Identity) -> Result<Session, String> {
    Err("not implemented".into())
}

/// Unit tests of pure Rust code
#[cfg(test)]
mod tests {
    use elliptic_curve::rand_core::OsRng;
    use super::*;

    use k256::{PublicKey, SecretKey};

    const EXIT_NODE: &str = "16Uiu2HAmUsJwbECMroQUC29LQZZWsYpYZx1oaM1H9DBoZHLkYn12";
    const ENTRY_NODE: &str = "16Uiu2HAm35DuQk2Cvp9aLpRTD43ZubLqtbAwf242w2YmAe8FskLs";

    #[test]
    fn test_request() {

        let our_key = EphemeralSecret::random(&mut OsRng);
        let exit_node_key = EphemeralSecret::random(&mut OsRng);

        //let exit_node_id = Identity::new(EXIT_NODE, 0, )

    }

}

/// Module for WASM wrappers of Rust code
pub mod wasm {
    use std::fmt::Display;
    use k256::{PublicKey, SecretKey};
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

        pub fn get_data(&self) -> Option<Box<[u8]>> {
            self.w.get_data()
        }
    }

    #[wasm_bindgen]
    pub struct Identity {
        w: super::Identity
    }

    #[wasm_bindgen]
    impl Identity {
        pub fn load_identity(peer_id: &str, counter: u64, public_key: Box<[u8]>, private_key: Option<Box<[u8]>>) -> Result<Identity, JsValue> {
            let private = match private_key {
                Some(k) => Some(SecretKey::from_be_bytes(k.as_ref()).map_err(as_jsvalue)?),
                None => None
            };

            Ok(Identity {
                w: super::Identity::new(counter,
                                        PublicKey::from_sec1_bytes(public_key.as_ref()).map_err(as_jsvalue)?,
                                        private)
            })
        }

        pub fn counter(&self) -> u64 {
            self.w.counter()
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
    pub fn box_request(request: &Envelope, exit_peer: &Identity) -> Result<Session, JsValue> {
        super::box_request(&request.w, &exit_peer.w)
            .map(|s| Session { w: s })
            .map_err(as_jsvalue)
    }

    #[wasm_bindgen]
    pub fn unbox_request(message: &Envelope, my_id: &Identity) -> Result<Session, JsValue> {
        super::unbox_request(&message.w, &my_id.w)
            .map(|s| Session { w: s })
            .map_err(as_jsvalue)
    }

    #[wasm_bindgen]
    pub fn box_response(session: &Session, response: &Envelope, entry_peer: &Identity) ->  Result<Session, JsValue> {
        super::box_response(&session.w, &response.w, &entry_peer.w)
            .map(|s| Session { w: s })
            .map_err(as_jsvalue)
    }

    #[wasm_bindgen]
    pub fn unbox_response(session: &Session, message: &Envelope, my_id: &Identity) -> Result<Session, JsValue> {
        super::unbox_response(&session.w, &message.w, &my_id.w)
            .map(|s| Session { w: s })
            .map_err(as_jsvalue)
    }
}

