
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

	
	let boxed_request = client_session.get_request_data() // this is an Uint8Array with encrypted data that will be sent to the Entry node
	// ... send to the Entry node!

	// IMPORTANT: Update the counter in the DB (along with the Exit node identity)
	let save_me = session.counter()
	
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


	// We also need to retrieve the public key and counter of the RPCh Client from the DB
	let client_node_counter = 10n; // it's a bigint


	// Boxed request data we retrieved via HOPR network
	let boxed_request_data = ... ; // Uint8Array

	// We also know our own peer ID and the Entry node Peer ID (we got that along with the request)
	let entry_node_peer_id = "16Uiu..."; 
	let our_exit_node_peer_id = "16Uiu2...";

	let session = unbox_request(new Envelope(boxed_request_data, entry_node_peer_id, our_exit_node_peer_id), my_exit_node_id, client_node_counter);

	let unboxed_request = session.get_request_data(); // It's an Uint8Array
		
	// IMPORTANT: Update the counter in the DB (along with the Client identity)
	let save_me = session.counter()

	// Now send that to Infura or whatever RPC provider!
	

	// So we got a response back from Infura or some RPC provider
	let rpc_response = ... ; // As Uint8Array


	box_response(session, new Envelope(rpc_response, entry_node_peer_id, our_exit_node_peer_id));

	let boxed_response = session.get_response_data(); // It's an Uint8Array
	// Now send that back the the RPCh client via HOPR network!


	// IMPORTANT: Update the counter in the DB (along with the Client identity)
	let save_me = session.counter()
	

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

	unbox_response(client_session, new Envelope(boxed_rpc_response, entry_node_peer_id, exit_node_peer_id));

	
	let unboxed_rpc_response = session.get_response_data()
	// Now present this back to the Wallet!


	// IMPORTANT: Update the counter in the DB (along with the Exit node identity)
	let save_me = session.counter()

}
catch {
	...
}


