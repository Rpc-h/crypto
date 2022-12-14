#![cfg(target_arch = "wasm32")]

extern crate wasm_bindgen_test;

use js_sys::Date;
use wasm_bindgen_test::*;

extern crate hex;
extern crate core;

/// All integration tests for WASM wrappers go in this directory.

use rpch_crypto::crypto::wasm::*;

//wasm_bindgen_test_configure!(run_in_browser);

const EXIT_NODE_PRIV_KEY: &str = "9724e2860178e062b9f1e7252de004b22a40cd4069f704604efef4fe0105c7da";
const EXIT_NODE_PUB_KEY: &str = "03dd289a45ca51763044917d9e49051548e75b1405fc9740623e20e11d4784c531";

const EXIT_NODE_PEER_ID: &str = "16Uiu2HAmUsJwbECMroQUC29LQZZWsYpYZx1oaM1H9DBoZHLkYn12";
const ENTRY_NODE_PEER_ID: &str = "16Uiu2HAm35DuQk2Cvp9aLpRTD43ZubLqtbAwf242w2YmAe8FskLs";

#[cfg(not(feature = "timestamps"))]
#[wasm_bindgen_test]
fn test_whole_flow() {
    const REQUEST_DATA: &str = "Hello world!";
    const RESPONSE_DATA: &str = "Hello world from Infura!";

    let mut data_on_wire: Box<[u8]>;
    let mut client_session: Session;
    let exit_node_id;

    // --- on RPCh Client ---
    {
        // RPCh Client loads the identity of the selected Exit node
        let exit_node_pk = hex::decode(EXIT_NODE_PUB_KEY).unwrap();
        exit_node_id = Identity::load_identity(exit_node_pk.as_slice(), None)
            .expect("client identity load failed");

        let exit_req_counter = 0;

        // RPCh Client create an envelope containing the request and starts up a session
        client_session = box_request(Envelope::new(REQUEST_DATA.as_bytes(), ENTRY_NODE_PEER_ID, EXIT_NODE_PEER_ID), &exit_node_id, exit_req_counter)
            .expect("failed to create client session");

        // Now the RPCh Client must update the counter
        assert_eq!(exit_req_counter + 1,  client_session.updated_counter());

        // session.get_request_data() is sent to the Exit node via HOPR network
        data_on_wire = client_session.get_request_data().expect("failed to retrieve request data for sending")
    }

    // --- on Exit node ---

    {
        // Exit node loads its own identity
        let exit_pk = hex::decode(EXIT_NODE_PUB_KEY).unwrap();
        let exit_sk = hex::decode(EXIT_NODE_PRIV_KEY).unwrap();
        let exit_id = Identity::load_identity(exit_pk.as_slice(), Some(exit_sk.into_boxed_slice()))
            .expect("exit node identity load failed");

        // Exit node receives the Request data and constructs an Envelope
        let client_req_counter = 0;
        let mut session = unbox_request(Envelope::new(data_on_wire.as_ref(), ENTRY_NODE_PEER_ID, EXIT_NODE_PEER_ID), &exit_id, client_req_counter)
            .expect("request unboxing failed");

        // The Exit node must update the client's counter value in a DB
        assert_eq!(client_req_counter + 1, session.updated_counter());

        // Now the Exit node performs the request to the Final RPC provider
        let request_data = session.get_request_data().expect("failed to retrieve request data on exit node");
        let request_str = String::from_utf8(request_data.into_vec()).expect("failed to decode response string");
        assert_eq!(REQUEST_DATA, request_str, "message not correct");

        let client_resp_counter = 0;

        // Construct the Response
        box_response(&mut session, Envelope::new(RESPONSE_DATA.as_bytes(), ENTRY_NODE_PEER_ID, EXIT_NODE_PEER_ID), client_resp_counter)
            .expect("failed to create response");

        // The Exit node must update the client's counter value in a DB
        assert_eq!(client_resp_counter + 1, session.updated_counter());

        data_on_wire = session.get_response_data().expect("failed to retrieve response data")
    }

    // --- on RPCh Client ---

    {
        let exit_resp_counter = 0;

        unbox_response(&mut client_session, Envelope::new(data_on_wire.as_ref(), ENTRY_NODE_PEER_ID, EXIT_NODE_PEER_ID), exit_resp_counter)
            .expect("response unboxing failed");

        // Retrieve the response data
        let response_data = client_session.get_response_data().expect("failed to retrieve response data");
        let response_str = String::from_utf8(response_data.into_vec()).expect("failed to decode response string");

        assert_eq!(RESPONSE_DATA, response_str, "message not correct");

        // Now the RPCh Client must update the counter
        assert_eq!(exit_resp_counter + 1,  client_session.updated_counter());
    }
}

#[cfg(feature = "timestamps")]
#[wasm_bindgen_test]
fn test_whole_flow() {
    const REQUEST_DATA: &str = "Hello world!";
    const RESPONSE_DATA: &str = "Hello world from Infura!";

    let mut data_on_wire: Box<[u8]>;
    let mut client_session: Session;
    let exit_node_id;

    let start_time = Date::now() as u64;

    // --- on RPCh Client ---
    {
        // RPCh Client loads the identity of the selected Exit node
        let exit_node_pk = hex::decode(EXIT_NODE_PUB_KEY).unwrap();
        exit_node_id = Identity::load_identity(exit_node_pk.as_slice(), None)
            .expect("client identity load failed");

        // RPCh Client create an envelope containing the request and starts up a session
        client_session = box_request(Envelope::new(REQUEST_DATA.as_bytes(), ENTRY_NODE_PEER_ID, EXIT_NODE_PEER_ID), &exit_node_id)
            .expect("failed to create client session");

        // Now the RPCh Client must update the counter
        assert!(client_session.updated_counter() > start_time);

        // session.get_request_data() is sent to the Exit node via HOPR network
        data_on_wire = client_session.get_request_data().expect("failed to retrieve request data for sending")
    }

    // --- on Exit node ---

    {
        // Exit node loads its own identity
        let exit_pk = hex::decode(EXIT_NODE_PUB_KEY).unwrap();
        let exit_sk = hex::decode(EXIT_NODE_PRIV_KEY).unwrap();
        let exit_id = Identity::load_identity(exit_pk.as_slice(), Some(exit_sk.into_boxed_slice()))
            .expect("exit node identity load failed");

        // Exit node receives the Request data and constructs an Envelope
        let mut session = unbox_request(Envelope::new(data_on_wire.as_ref(), ENTRY_NODE_PEER_ID, EXIT_NODE_PEER_ID), &exit_id, start_time)
            .expect("request unboxing failed");

        // The Exit node must update the client's counter value in a DB
        assert!(session.updated_counter() > start_time);

        // Now the Exit node performs the request to the Final RPC provider
        let request_data = session.get_request_data().expect("failed to retrieve request data on exit node");
        let request_str = String::from_utf8(request_data.into_vec()).expect("failed to decode response string");
        assert_eq!(REQUEST_DATA, request_str, "message not correct");

        let now = Date::now() as u64;

        // Construct the Response
        box_response(&mut session, Envelope::new(RESPONSE_DATA.as_bytes(), ENTRY_NODE_PEER_ID, EXIT_NODE_PEER_ID))
            .expect("failed to create response");

        // The Exit node must update the client's counter value in a DB
        assert!(session.updated_counter() > now);

        data_on_wire = session.get_response_data().expect("failed to retrieve response data")
    }

    // --- on RPCh Client ---

    {
        unbox_response(&mut client_session, Envelope::new(data_on_wire.as_ref(), ENTRY_NODE_PEER_ID, EXIT_NODE_PEER_ID), start_time)
            .expect("response unboxing failed");

        // Retrieve the response data
        let response_data = client_session.get_response_data().expect("failed to retrieve response data");
        let response_str = String::from_utf8(response_data.into_vec()).expect("failed to decode response string");

        assert_eq!(RESPONSE_DATA, response_str, "message not correct");

        // Now the RPCh Client must update the counter
        assert!(client_session.updated_counter() > start_time);
    }
}
