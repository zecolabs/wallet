use bip39::{Language, Mnemonic};
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use hmac::{Hmac, Mac};
use sha2::Sha512;
use tiny_keccak::{Hasher, Keccak};
use wasm_bindgen::prelude::*;
use zeroize::Zeroizing;
type HmacSha512 = Hmac<Sha512>;

const TX_DOMAIN: [u8; 1] = [1]; // = DOMAIN_TX on the node
const MESSAGE_DOMAIN: &[u8] = b"\x00I signing this message";
const TX_VERSION: u8 = 1;
const TX_UNSIGNED_LEN: usize = 179; // signed fields len
const TX_BODY_LEN: usize = 243; // 179 + 64-byte signature
const MSG_PROOF_LEN: usize = 104; // public key (32) + signature (64) + timestamp (8)

#[cfg(feature = "console_error_panic_hook")]
#[wasm_bindgen(start)]
pub fn init_panic_hook() {
	console_error_panic_hook::set_once();
}

#[wasm_bindgen]
pub fn generate_mnemonic(word_count: u32) -> String {
	let wc = match word_count {
		12 | 15 | 18 | 21 | 24 => word_count as usize,
		_ => 12,
	};
	// wc is always a valid BIP39 word count, so this cannot fail.
	Mnemonic::generate_in(Language::English, wc)
		.expect("word count is always a valid BIP39 length")
		.to_string()
}

#[wasm_bindgen]
pub fn validate_mnemonic(phrase: &str) -> bool {
	Mnemonic::parse_in_normalized(Language::English, phrase).is_ok()
}

fn parse_hardened_path(path: &str) -> Result<Vec<u32>, String> {
	let mut segments = path.split('/');
	match segments.next() {
		Some("m") => {}
		_ => return Err("path must start with 'm/'".into()),
	}
	let mut out = Vec::new();
	for seg in segments {
		let seg = seg.trim();
		if !seg.ends_with('\'') {
			return Err(format!(
				"level '{seg}' is not hardened: Ed25519 (SLIP-0010) requires all levels to be hardened"
			));
		}
		let num_str = &seg[..seg.len() - 1];
		let num: u32 = num_str.parse().map_err(|_| format!("invalid index: {seg}"))?;
		if num >= 0x8000_0000 {return Err(format!("index too large: {seg}"));}
		out.push(num + 0x8000_0000);
	}
	Ok(out)
}

fn slip10_master(seed: &[u8]) -> ([u8; 32], [u8; 32]) {
	let mut mac = HmacSha512::new_from_slice(b"ed25519 seed").expect("hmac key ok");
	mac.update(seed);
	let result = mac.finalize().into_bytes();
	let mut il = [0u8; 32];
	let mut ir = [0u8; 32];
	il.copy_from_slice(&result[..32]);
	ir.copy_from_slice(&result[32..]);
	(il, ir)
}

fn slip10_child(private_key: &[u8; 32], chain_code: &[u8; 32], index_hardened: u32) -> ([u8; 32], [u8; 32]) {
	let mut mac = HmacSha512::new_from_slice(chain_code).expect("hmac key ok");
	mac.update(&[0x00u8]);
	mac.update(private_key);
	mac.update(&index_hardened.to_be_bytes());
	let result = mac.finalize().into_bytes();
	let mut il = [0u8; 32];
	let mut ir = [0u8; 32];
	il.copy_from_slice(&result[..32]);
	ir.copy_from_slice(&result[32..]);
	(il, ir)
}

fn derive_priv_seed(phrase: &str, passphrase: &str, path: &str) -> Result<Zeroizing<[u8; 32]>, JsValue> {
	let mnemonic = Mnemonic::parse_in_normalized(Language::English, phrase)
		.map_err(|e| JsValue::from_str(&format!("invalid mnemonic: {e}")))?;
	let seed = mnemonic.to_seed(passphrase);
	let indices = parse_hardened_path(path).map_err(|e| JsValue::from_str(&e))?;
	let (mut key, mut chain) = slip10_master(&seed);
	for idx in indices {
		let (k, c) = slip10_child(&key, &chain, idx);
		key = k;
		chain = c;
	}
	Ok(Zeroizing::new(key))
}

#[wasm_bindgen]
pub fn derive_ed25519_pubkey_hex(phrase: &str, passphrase: &str, path: &str) -> Result<String, JsValue> {
	let seed = derive_priv_seed(phrase, passphrase, path)?;
	let signing_key = SigningKey::from_bytes(&seed);
	Ok(hex::encode(signing_key.verifying_key().to_bytes()))
}

#[wasm_bindgen]
pub fn derive_ed25519_privkey_hex(phrase: &str, passphrase: &str, path: &str) -> Result<String, JsValue> {
	let seed = derive_priv_seed(phrase, passphrase, path)?;
	Ok(format!("rx{}", hex::encode(&*seed)))
}

#[wasm_bindgen]
pub fn derive_address(phrase: &str, passphrase: &str, path: &str, prefix: &str) -> Result<String, JsValue> {
	let seed = derive_priv_seed(phrase, passphrase, path)?;
	let signing_key = SigningKey::from_bytes(&seed);
	let pubkey_bytes = signing_key.verifying_key().to_bytes();

	let hash = keccak256(&pubkey_bytes);
	let addr_bytes = &hash[12..];

	Ok(format!("{prefix}{}", hex::encode(addr_bytes)))
}

#[wasm_bindgen]
pub fn build_hardened_path(coin_type: u32, account_index: u32) -> String {
	format!("m/44'/{coin_type}'/0'/0'/{account_index}'")
}

fn keccak256(data: &[u8]) -> [u8; 32] {
	let mut hasher = Keccak::v256();
	hasher.update(data);
	let mut output = [0u8; 32];
	hasher.finalize(&mut output);
	output
}

fn timestamp_now() -> u64 {
	(js_sys::Date::now() / 1000.0) as u64
}


fn verify_raw_hash(message_hash: &[u8; 32], raw_public_key: &[u8; 32], raw_signature: &[u8; 64]) -> bool {
	let Ok(verifier) = VerifyingKey::from_bytes(raw_public_key) else {
		return false;
	};
	let signature = Signature::from_bytes(raw_signature);
	verifier.verify_strict(message_hash, &signature).is_ok()
}

fn decode_hex_flexible(s: &str) -> Result<Vec<u8>, String> {
	let s = s.strip_prefix("rx").unwrap_or(s);
	if s.is_empty() {return Ok(Vec::new());}
	hex::decode(s).map_err(|e| format!("invalid hex: {e}"))
}

fn decode_hex_fixed<const N: usize>(s: &str, field: &str) -> Result<[u8; N], JsValue> {
	let bytes = decode_hex_flexible(s).map_err(|e| JsValue::from_str(&e))?;
	let len = bytes.len();
	bytes
		.try_into()
		.map_err(|_| JsValue::from_str(&format!("{field} must be {N} bytes, got {len} bytes")))
}

/*
The 179 transaction field bytes (without signature), in EXACTLY the same order as
`SignedBodyV1::unsigned_bytes` on the node:
version(1) chainid(4) action(1) sender(32) to(20) nonce(8) amount(32)
power(8) power_limit(8) price_per_power(32) packet(1) tip(32)

sender = the sender's 32-byte public key, NOT a 20-byte address (Ed25519 has no recovery).
amount/price_per_power/tip = big-endian uint256 (32 bytes). The signer does no arithmetic
on these values; validating them is the caller's job.
*/
fn encode_transaction_unsigned(
	chainid: u32,
	action: u8,
	sender: &[u8; 32],
	to: &[u8; 20],
	nonce: u64,
	amount: &[u8; 32],
	power: u64,
	power_limit: u64,
	price_per_power: &[u8; 32],
	packet: u8,
	tip: &[u8; 32],
) -> [u8; TX_UNSIGNED_LEN] {
	let mut out = [0u8; TX_UNSIGNED_LEN];
	let mut pos = 0usize;
	let mut put = |data: &[u8]| {
		out[pos..pos + data.len()].copy_from_slice(data);
		pos += data.len();
	};
	put(&[TX_VERSION]); // u8
	put(&chainid.to_be_bytes()); // u32 byte
	put(&[action]); // u8
	put(sender); // bytes32 or [u8; 32]
	put(to); // address or [u8; 20]
	put(&nonce.to_be_bytes()); // u64 byte
	put(amount); // u256 byte 
	put(&power.to_be_bytes()); // u64 byte
	put(&power_limit.to_be_bytes()); // u64 byte 
	put(price_per_power); // u256 byte
	put(&[packet]); // dynamic bytes data, transfer action is b"\x00" or u8 0
	put(tip); // u256 byte
	debug_assert_eq!(pos, TX_UNSIGNED_LEN);
	out
}

// Message signed by the sender: TX_DOMAIN || 179 field bytes (signature excluded).
fn tx_signing_message(unsigned: &[u8; TX_UNSIGNED_LEN]) -> Vec<u8> {
	let mut m = Vec::with_capacity(TX_DOMAIN.len() + TX_UNSIGNED_LEN);
	m.extend_from_slice(&TX_DOMAIN);
	m.extend_from_slice(unsigned);
	m
}

// Returns the 243-byte body, ready to send.
#[allow(clippy::too_many_arguments)]
fn build_signed_tx(seed: &[u8; 32], chainid: u32, action: u8, to: &[u8; 20], nonce: u64, amount: &[u8; 32], power: u64, power_limit: u64, price_per_power: &[u8; 32], tip: &[u8; 32]) -> Result<[u8; TX_BODY_LEN], String> {
	if action != 0 {return Err("only action 0 (transfer) is supported".into());}
	if power_limit < power {return Err("power_limit must be >= power".into());}
	let signing_key = SigningKey::from_bytes(seed);
	let sender = signing_key.verifying_key().to_bytes();
	// packet is a fixed placeholder 0 for transfers
	let unsigned = encode_transaction_unsigned(
		chainid, action, &sender, to, nonce, amount, power, power_limit, price_per_power, 0, tip,
	);
	let to_sign = keccak256(&tx_signing_message(&unsigned));
	let signature = signing_key.sign(&to_sign).to_bytes();
	let mut body = [0u8; TX_BODY_LEN];
	body[..TX_UNSIGNED_LEN].copy_from_slice(&unsigned);
	body[TX_UNSIGNED_LEN..].copy_from_slice(&signature);
	Ok(body)
}

// Verifies a 243-byte body the same way the node does (`verify_strict`).
fn verify_tx_body(wire: &[u8]) -> Result<bool, String> {
	if wire.len() != TX_BODY_LEN {return Err(format!("tx body must be {TX_BODY_LEN} bytes, got {} bytes", wire.len()));}
	let unsigned: [u8; TX_UNSIGNED_LEN] = wire[..TX_UNSIGNED_LEN].try_into().unwrap();
	let sig_bytes: [u8; 64] = wire[TX_UNSIGNED_LEN..].try_into().unwrap();
	let sender: [u8; 32] = wire[6..38].try_into().unwrap(); // offset: version(1)+chainid(4)+action(1)
	let Ok(verifier) = VerifyingKey::from_bytes(&sender) else {return Ok(false);};
	let signature = Signature::from_bytes(&sig_bytes);
	let to_sign = keccak256(&tx_signing_message(&unsigned));
	Ok(verifier.verify_strict(&to_sign, &signature).is_ok())
}

// Message hash: keccak256(MESSAGE_DOMAIN || chainid(4) || message || timestamp(8)).
fn message_hash(message: &str, chainid: u32, timestamp_be: &[u8; 8]) -> [u8; 32] {
	let mut kec = Keccak::v256();
	kec.update(MESSAGE_DOMAIN);
	kec.update(&chainid.to_be_bytes());
	kec.update(message.as_bytes());
	kec.update(timestamp_be);
	let mut hash = [0u8; 32];
	kec.finalize(&mut hash);
	hash
}

/*
Signs a transfer transaction. `to_hex` = 20-byte hex (optional "rx" prefix).
`amount_hex`/`price_per_power_hex`/`tip_hex` = big-endian uint256, EXACTLY 32 bytes
(64 hex characters, optional "rx" prefix). `power` = expected power use (must match the
node's rules), `power_limit` >= `power`. The node computes the fee as
power * price_per_power, so there is NO fee parameter. `price_per_power` must exactly
match the protocol price (fetch it from /power_price). Only action 0 (transfer) is
supported; packet is always 0.
Returns the 243-byte body as hex, ready to POST to /send_transaction:
version(1) chainid(4) action(1) sender_pubkey(32) to(20) nonce(8) amount(32) power(8)
power_limit(8) price_per_power(32) packet(1) tip(32) signature(64).
*/
#[wasm_bindgen]
pub fn sign_transaction(
	phrase: &str,
	passphrase: &str,
	path: &str,
	chainid: u32,
	action: u8,
	to_hex: &str,
	nonce: u64,
	amount_hex: &str,
	power: u64,
	power_limit: u64,
	price_per_power_hex: &str,
	tip_hex: &str,
) -> Result<String, JsValue> {
	let seed = derive_priv_seed(phrase, passphrase, path)?;
	let to_bytes: [u8; 20] = decode_hex_fixed(to_hex, "to")?;
	let amount_bytes: [u8; 32] = decode_hex_fixed(amount_hex, "amount")?;
	let price_bytes: [u8; 32] = decode_hex_fixed(price_per_power_hex, "price_per_power")?;
	let tip_bytes: [u8; 32] = decode_hex_fixed(tip_hex, "tip")?;
	let body = build_signed_tx(
		&seed, chainid, action, &to_bytes, nonce, &amount_bytes, power, power_limit, &price_bytes, &tip_bytes,
	)
	.map_err(|e| JsValue::from_str(&e))?;
	Ok(hex::encode(body))
}

// Re-verifies a body produced by `sign_transaction` (UI sanity check before broadcast, or testing).
#[wasm_bindgen]
pub fn verify_transaction(signed_tx_hex: &str) -> Result<bool, JsValue> {
	let wire = decode_hex_flexible(signed_tx_hex).map_err(|e| JsValue::from_str(&e))?;
	verify_tx_body(&wire).map_err(|e| JsValue::from_str(&e))
}

/*
Transaction hash = keccak256(entire 243-byte body, including signature), hex without prefix.
Matches the hash returned by the node, so the wallet can check the node's reply.
*/
#[wasm_bindgen]
pub fn tx_hash_hex(signed_tx_hex: &str) -> Result<String, JsValue> {
	let wire = decode_hex_flexible(signed_tx_hex).map_err(|e| JsValue::from_str(&e))?;
	if wire.len() != TX_BODY_LEN {return Err(JsValue::from_str(&format!("tx body must be {TX_BODY_LEN} bytes, got {} bytes", wire.len())));}
	Ok(hex::encode(keccak256(&wire)))
}

// Proof format: public key (32) + signature (64) + timestamp (8)
#[wasm_bindgen]
pub fn sign_message(phrase: &str, passphrase: &str, path: &str, message: &str, chainid: u32) -> Result<String, JsValue> {
	let seed = derive_priv_seed(phrase, passphrase, path)?;
	let signer = SigningKey::from_bytes(&seed);
	let public_key = signer.verifying_key().to_bytes();
	let timestamp = timestamp_now();
	let hash = message_hash(message, chainid, &timestamp.to_be_bytes());
	let signature = signer.sign(&hash).to_bytes();
	let mut proof = [0u8; MSG_PROOF_LEN];
	proof[0..32].copy_from_slice(&public_key);
	proof[32..96].copy_from_slice(&signature);
	proof[96..104].copy_from_slice(&timestamp.to_be_bytes());
	Ok(hex::encode(proof))
}

// Verifies a proof from `sign_message`. Needs no private key; the public key is in the proof.
#[wasm_bindgen]
pub fn verify_message(message: &str, chainid: u32, proof_hex: &str) -> Result<bool, JsValue> {
	let proof: [u8; MSG_PROOF_LEN] = decode_hex_fixed(proof_hex, "proof")?;
	let pubkey: [u8; 32] = proof[0..32].try_into().unwrap();
	let signature: [u8; 64] = proof[32..96].try_into().unwrap();
	let timestamp: [u8; 8] = proof[96..104].try_into().unwrap();
	let hash = message_hash(message, chainid, &timestamp);
	Ok(verify_raw_hash(&hash, &pubkey, &signature))
}
