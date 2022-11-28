
const RPCH_CLIENT_PRIV_KEY = "da168e73ebf1de84410cf94dfacf589dfcf90f343c32ce36550e688165a7f3f7";
const RPCH_CLIENT_PUB_KEY  = "02ae28530d283ac87f5585be918badd16ac98f4141c8566c2619b5f40fb366bc63";

const EXIT_NODE_PRIV_KEY   = "9724e2860178e062b9f1e7252de004b22a40cd4069f704604efef4fe0105c7da";
const EXIT_NODE_PUB_KEY    = "03dd289a45ca51763044917d9e49051548e75b1405fc9740623e20e11d4784c531";

const EXIT_NODE_PEER_ID    = "16Uiu2HAmUsJwbECMroQUC29LQZZWsYpYZx1oaM1H9DBoZHLkYn12";
const ENTRY_NODE_PEER_ID:  = "16Uiu2HAm35DuQk2Cvp9aLpRTD43ZubLqtbAwf242w2YmAe8FskLs";



// --- On RPCh Client node: boxing the request before sending


// After selecting the Exit node, we need to load details about it. We also keep a counter per each exit node we've interacted with in the persistent DB.
let exit_node_counter = 10n; // its a bigint
let exit_node_public_key = ...; // As Uint8Array


try { // NOTE that function below can throw!

	// Once loaded from the persistent storage, we store the Exit node details in the Identity class:

	let exit_node_id = Identity::load_identity(exit_node_public_key, undefined, exit_node_counter);


	// We have the request data we need to box in an Uint8Array:
	let request_data = ...; 

	// Also we need to know the Entry node Peer ID and the Exit node peer ID (as strings)
	let entry_node_peer_id = "16Uiu..."; 
	let exit_node_peer_id = "16Uiu2..."; 

	// We need to save the "client_session" Session object for later to process the response as well
	let client_session = box_request(new Envelope(request_data, entry_node_peer_id, exit_node_peer_id), exit_node_id);

	if (client_session.valid()) {
		let boxed_request = client_session.get_request_data() // this is an Uint8Array with encrypted data that will be sent to the Entry node
		// ... send to the Entry node!

		// IMPORTANT: Update the counter in the DB (along with the Exit node identity)
		let save_me = session.get_exit_node_counter()
	}
	else throw Error("invalid session!")
}
catch {
	...
}


// --- On RPCh Exit node: retrieving the boxed request and unboxing it to forward to the actual RPC provider

try { // anything can throw

	// Exit node loads its own Identity details
	let exit_node_public_key = ...; // Uint8Array
	let exit_node_private_key = ...; // Uint8Array

	
	let my_exit_node_id = Identity::load_identity(exit_node_public_key, exit_node_private_key); // NOTE we're not loading any counter here

	// Boxed request data we retrieved via HOPR network
	let boxed_request_data = ... ; // Uint8Array

	// We also know our own peer ID and the Entry node Peer ID (we got that along with the request)
	let entry_node_peer_id = "16Uiu..."; 
	let our_exit_node_peer_id = "16Uiu2...";

	let session = unbox_request(new Envelope(boxed_request_data, entry_node_peer_id, our_exit_node_peer_id), my_exit_node_id);

	if (session.valid()) {
		let unboxed_request = session.get_request_data(); // It's an Uint8Array
		
		// IMPORTANT: Update the counter in the DB (along with the Client identity)
		let save_me = session.get_client_node_counter()

		// Now send that to Infura or whatever RPC provider!
	}
	else throw Error("invalid session!")


	// So we got a response back from Infura or some RPC provider
	let rpc_response = ... ; // As Uint8Array


	// We need to retrieve the public key and counter of the RPCh Client from the DB
	let client_node_public_key = ...; // Uint8Array
	let client_node_counter = 10n; // it's a bigint

	let client_id = Identity::load_identity(client_node_public_key, undefined, client_node_counter);


	box_response(session, new Envelope(rpc_response, entry_node_peer_id, our_exit_node_peer_id), client_id);

	if (session.valid())
	{
		let boxed_response = session.get_response_data(); // It's an Uint8Array
		// Now send that back the the RPCh client via HOPR network!


		// IMPORTANT: Update the counter in the DB (along with the Client identity)
		let save_me = session.get_client_node_counter()
	}
	else throw Error("invalid session!")

}
catch {
	...
}

// --- Back on the RPCh Client node: unboxing the response

try { // again, anything can throw

	
	// This is the response data we got via HOPR network
	let boxed_rpc_response = ...; // Uint8Array


	// Let's load our identity details first, as a RPCh client
	let our_client_public_key = ...; // Uint8Array
	let our_client_private_key = ..; // Uint8Array


	let our_id = Identity::load_identity(our_client_public_key, our_client_private_key) // No counter needed

	// Remember we also got the "client_session" Session object

	unbox_response(client_session, new Envelope(boxed_rpc_response, entry_node_peer_id, exit_node_peer_id), our_id);

	if (client_session.valid()) 
	{
		let unboxed_rpc_response = session.get_response_data()
		// Now present this back to the Wallet!


		// IMPORTANT: Update the counter in the DB (along with the Exit node identity)
		let save_me = session.get_exit_node_counter()
	}
	else throw Error("invalid session!")

}
catch {
	...
}


