use k256::{PublicKey, SecretKey};

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
    peer_id: String,
    counter: u64,
    pubkey: PublicKey,
    secret_key: Option<SecretKey>
}

impl Identity {

    pub fn new(peer_id: &str, counter: u64, public_key: PublicKey, private_key: Option<SecretKey>) -> Identity {
        Identity {
            peer_id: peer_id.into(),
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

    pub fn peer_id(&self) -> &str {
        self.peer_id.as_str()
    }
}

pub fn box_request(request: &[u8], exit_peer: &Identity) -> Result<Session, String> {
    Err("not implemented".into())
}

pub fn unbox_request(message: &[u8], my_id: &Identity) -> Result<Session, String> {
    Err("not implemented".into())
}

pub fn box_response(session: &Session, response: &[u8], entry_peer: &Identity) ->  Result<Session, String> {
    Err("not implemented".into())
}

pub fn unbox_response(session: &Session, message: &[u8], my_id: &Identity) -> Result<Session, String> {
    Err("not implemented".into())
}

/// Unit tests of pure Rust code
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_request() {

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
                w: super::Identity::new(peer_id, counter,
                                        PublicKey::from_sec1_bytes(public_key.as_ref()).map_err(as_jsvalue)?,
                                        private)
            })
        }

        pub fn counter(&self) -> u64 {
            self.w.counter()
        }

        pub fn peer_id(&self) -> String {
            self.w.peer_id().to_string()
        }
    }

    #[wasm_bindgen]
    pub fn box_request(request: &[u8], exit_peer: &Identity) -> Result<Session, JsValue> {
        super::box_request(request, &exit_peer.w)
            .map(|s| Session { w: s })
            .map_err(as_jsvalue)
    }

    #[wasm_bindgen]
    pub fn unbox_request(message: &[u8], my_id: &Identity) -> Result<Session, JsValue> {
        super::unbox_request(message, &my_id.w)
            .map(|s| Session { w: s })
            .map_err(as_jsvalue)
    }

    #[wasm_bindgen]
    pub fn box_response(session: &Session, response: &[u8], entry_peer: &Identity) ->  Result<Session, JsValue> {
        super::box_response(&session.w, response, &entry_peer.w)
            .map(|s| Session { w: s })
            .map_err(as_jsvalue)
    }

    #[wasm_bindgen]
    pub fn unbox_response(session: &Session, message: &[u8], my_id: &Identity) -> Result<Session, JsValue> {
        super::unbox_response(&session.w, message, &my_id.w)
            .map(|s| Session { w: s })
            .map_err(as_jsvalue)
    }
}

