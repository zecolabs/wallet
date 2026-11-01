import init, {
  generate_mnemonic,
  validate_mnemonic,
  derive_address,
  derive_ed25519_privkey_hex,
  build_hardened_path,
  sign_transaction,
  tx_hash_hex,
  sign_message,
  verify_message,
} from "./pkg/libcrypto.js";

const COIN_TYPE = 15000;
const ADDRESS_PREFIX = "rx";
const AUTO_LOCK_MS = 5 * 60 * 1000;
const U256_MAX = (1n << 256n) - 1n;

const DEFAULT_RPC_URL = "http://127.0.0.1:3000/";
const RPC_TIMEOUT_MS = 8000;
const ADDRESS_PREFIX_RX = "rx";
const CHAINID = 1;
const TRANSFER_POWER = 1200n;
const POLL_MAX_TRY = 15;
const POLL_DELAY_MS = 2000;
const HISTORY_MAX_ENTRIES = 50;
const MAX_FEE = 10n ** 17n;
const MAX_TIP = 10n ** 17n;
const MAX_SIGN_MSG_BYTES = 1024;

function getStorage() {
  if (typeof chrome === "undefined" || !chrome.storage || !chrome.storage.local) {
    throw new Error(
      'chrome.storage.local is not available. Make sure "storage" is in the ' +
      'manifest.json permissions and the code is running as the extension service worker.'
    );
  }
  return chrome.storage.local;
}
async function storageGet(keys) { return getStorage().get(keys); }
async function storageSet(obj) { return getStorage().set(obj); }

function hexToBytes(hex) {
  const clean = hex.startsWith("rx") ? hex.slice(2) : hex;
  if (clean.length % 2 !== 0) throw new Error("Hex string has odd length");
  const out = new Uint8Array(clean.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(clean.substr(i * 2, 2), 16);
  return out;
}

function sleep(ms) { return new Promise((r) => setTimeout(r, ms)); }

function stripPrefix(v) {
  return String(v).replace(new RegExp("^" + ADDRESS_PREFIX_RX, "i"), "");
}
function rejectLegacyPrefix(v, label) {
  if (/^0x/i.test(String(v))) {
    throw new Error(label + " with the 0x prefix is not supported. Use the rx prefix.");
  }
}
function toRx(v) { return ADDRESS_PREFIX_RX + stripPrefix(v); }

// u256 -> 32-byte hex
function u256ToHex(value, fieldName) {
  let v;
  try {
    v = typeof value === "bigint" ? value : BigInt(value);
  } catch {
    throw new Error(`${fieldName} is not a valid integer: ${value}`);
  }
  if (v < 0n) throw new Error(`${fieldName} cannot be negative: ${v}`);
  if (v > U256_MAX) throw new Error(`${fieldName} exceeds the uint256 limit (2^256-1): ${v}`);
  return v.toString(16).padStart(64, "0");
}

const U64_MAX = (1n << 64n) - 1n;

// Validate u64 (nonce, power, power_limit) -> BigInt
function toU64(value, fieldName) {
  let n;
  try {
    n = typeof value === "bigint" ? value : BigInt(value);
  } catch {
    throw new Error(`${fieldName} is not a valid integer: ${value}`);
  }
  if (n < 0n) throw new Error(`${fieldName} cannot be negative: ${n}`);
  if (n > U64_MAX) throw new Error(`${fieldName} exceeds the uint64 limit: ${n}`);
  return n;
}

/*
The node returns JSON. Success = HTTP 200 + object; failure = HTTP 4xx/5xx + {"error":"..."}.
Number rules from the node: u64 = JSON number, U256 = decimal string,
byte data = "rx" + hex. u64 above 2^53 is kept exact by parseJsonKeepU64() below.
*/
class RpcError extends Error {
  constructor(message, status) { super(message); this.status = status; }
}

async function getRpcUrl() {
  const { rpcUrl } = await storageGet(["rpcUrl"]);
  return rpcUrl || DEFAULT_RPC_URL;
}

const JSON_SOURCE_SUPPORTED = (() => {
  try {
    let ok = false;
    JSON.parse("1", (k, v, ctx) => { ok = !!ctx && ctx.source === "1"; return v; });
    return ok;
  } catch { return false; }
})();

function parseJsonKeepU64(text) {
  return JSON.parse(text, (key, value, ctx) => {
    if (
      typeof value === "number" &&
      !Number.isSafeInteger(value) &&
      ctx && typeof ctx.source === "string" &&
      /^-?\d+$/.test(ctx.source)
    ) {
      return BigInt(ctx.source);
    }
    return value;
  });
}

async function rpcJsonAt(base, path, options) {
  if (!JSON_SOURCE_SUPPORTED) {
    throw new RpcError("Browser too old: JSON.parse source text is required (Chrome 114+).", 0);
  }
  let res;
  try {
    res = await fetch(base + path, { signal: AbortSignal.timeout(RPC_TIMEOUT_MS), ...options });
  } catch (e) {
    if (e && e.name === "TimeoutError") {
      throw new RpcError(`Node did not respond within ${RPC_TIMEOUT_MS / 1000} seconds (${base})`, 0);
    }
    throw new RpcError(`Cannot connect to node (${base}). Check the URL, server, and access permission.`, 0);
  }
  let data = null;
  try { data = parseJsonKeepU64(await res.text()); } catch { /* body is not JSON */ }
  if (!res.ok) throw new RpcError((data && data.error) || `HTTP ${res.status} for ${path}`, res.status);
  if (data === null || typeof data !== "object") throw new RpcError("Node response is not JSON", res.status);
  return data;
}

async function rpcJson(path, options) {
  return rpcJsonAt(await getRpcUrl(), path, options);
}

function requireDec(value, name) {
  if (typeof value !== "string" || !/^\d+$/.test(value)) throw new Error(`Node response: ${name} is not a decimal number`);
  return value;
}
/*
u64 from the node: JSON number (Number if safe, BigInt if large via parseJsonKeepU64) or a
decimal string. Returns a decimal string: same shape as requireDec and safe for
chrome.runtime.sendResponse (BigInt cannot be serialized).
*/
function requireU64(value, name) {
  let n;
  if (typeof value === "bigint") {
    n = value;
  } else if (typeof value === "number") {
    // A Number reaching here is a safe integer; anything else (fraction, 1e20) is rejected.
    if (!Number.isSafeInteger(value)) throw new Error(`Node response: ${name} is not an integer`);
    n = BigInt(value);
  } else if (typeof value === "string" && /^\d+$/.test(value)) {
    n = BigInt(value);
  } else {
    throw new Error(`Node response: ${name} is not a valid u64 number`);
  }
  if (n < 0n || n > U64_MAX) throw new Error(`Node response: ${name} is out of the u64 range`);
  return n.toString();
}

// Transaction status: 0=pending, 1=success, 2=failed
function txStatusText(code) {
  switch (code) {
    case 0: return "pending";
    case 1: return "success";
    case 2: return "failed";
    default: return "unknown";
  }
}
function isFinalStatus(code) { return code === 1 || code === 2; }

// Tip recommendations. Node: {min, medium, fast}; the popup uses the names low/medium/fast.
async function getTraffic() {
  const d = await rpcJson("traffic", { method: "GET" });
  return { low: requireDec(d.min, "min"), medium: requireDec(d.medium, "medium"), fast: requireDec(d.fast, "fast") };
}

async function getAccount(address) {
  try {
    const d = await rpcJson("account/" + toRx(address), { method: "GET" });
    const [nonceName, nonceRaw] = d.pending_nonce != null ? ["pending_nonce", d.pending_nonce] : ["nonce", d.nonce];
    return {
      address: d.address,
      balance: requireDec(d.balance, "balance"), // u256: stays a string
      nonce: requireU64(nonceRaw, nonceName),    // u64: JSON number
    };
  } catch (e) {
    if (e instanceof RpcError && e.status === 404) return { address: toRx(address), balance: "0", nonce: "0" };
    throw e;
  }
}

async function getPowerPrice() {
  const d = await rpcJson("power_price", { method: "GET" });
  return BigInt(requireDec(d.power_price, "power_price"));
}

// fee = power * price (fixed, set by the protocol). Used by the popup's Max button.
async function getFeeInfo() {
  const price = await getPowerPrice();
  return { power: TRANSFER_POWER.toString(), powerPrice: price.toString(), fee: (price * TRANSFER_POWER).toString() };
}

// Transaction detail from the node, mapped to the shape the popup uses.
async function getTransactionDetail(txHash) {
  if (!/^[0-9a-fA-F]{64}$/.test(stripPrefix(txHash))) throw new Error("Invalid tx hash format");
  const d = await rpcJson("transaction/" + toRx(txHash), { method: "GET" });

  return {
    version: d.version,
    hash: d.hash,
    txStatus: d.status,
    txStatusText: txStatusText(d.status),
    blockNumber: requireU64(d.blocknumber, "blocknumber"),
    position: d.position,
    timestamp: Number(requireU64(d.timestamp, "timestamp")),
    chainid: d.chainid,
    action: d.action,
    sender: d.sender, // format {"sender": {"address": xxx, "public_key": xxx}}
    to: d.to,
    nonce: d.pending_nonce != null ? requireU64(d.pending_nonce, "pending_nonce") : requireU64(d.nonce, "nonce"),
    amount: requireDec(d.amount, "amount"),
    power: requireU64(d.power, "power"),
    powerLimit: requireU64(d.power_limit, "power_limit"),
    powerUsed: requireU64(d.power_used, "power_used"),
    pricePerPower: requireDec(d.price_per_power, "price_per_power"),
    fee: requireDec(d.fee, "fee"),
    tip: requireDec(d.tip, "tip"),
    packet: d.packet,
    signature: d.signature,
  };
}

function normalizeRpcUrl(input) {
  let u;
  try {
    u = new URL(String(input).trim());
  } catch {
    throw new Error("Invalid URL. Example: http://127.0.0.1:3000");
  }
  if (u.protocol !== "http:" && u.protocol !== "https:") throw new Error("URL must start with http:// or https://");
  if (u.username || u.password) throw new Error("URL must not contain a username/password");
  if (u.search || u.hash) throw new Error("URL must not contain a query (?...) or fragment (#...)");
  if (!u.pathname.endsWith("/")) u.pathname += "/";
  return u.href;
}

// Probe the node: it must return valid JSON and its chain ID must match this wallet's.
async function probeRpc(base) {
  const t0 = Date.now();
  const c = await rpcJsonAt(base, "chainid", { method: "GET" });
  if (c.chainid !== CHAINID) {
    throw new Error(`Node chain ID (${c.chainid}) does not match the wallet (${CHAINID}). This is not a node for this chain.`);
  }
  const b = await rpcJsonAt(base, "block_number", { method: "GET" });
  return { url: base, chainid: c.chainid, blockNumber: requireU64(b.block_number, "block_number"), latencyMs: Date.now() - t0 };
}

async function getRpcConfig() {
  const url = await getRpcUrl();
  return { url, defaultUrl: DEFAULT_RPC_URL, isDefault: url === DEFAULT_RPC_URL };
}

async function testRpc(url) {
  return probeRpc(url ? normalizeRpcUrl(url) : await getRpcUrl());
}

async function setRpc(url) {
  const base = normalizeRpcUrl(url);
  const info = await probeRpc(base);
  if (base === DEFAULT_RPC_URL) await getStorage().remove("rpcUrl");
  else await storageSet({ rpcUrl: base });
  return info;
}

async function resetRpc() {
  await getStorage().remove("rpcUrl");
  return getRpcConfig();
}

/*
// Signed fields: amount, tip, nonce, power, power_limit, price_per_power.
// The fee is NOT sent: the node computes fee = power * price_per_power. Price and nonce are always
// fetched fresh from the node at send time (not from the popup), so they are never stale.
*/
async function validateTxParams(p) {
  rejectLegacyPrefix(p.to, "Destination address");
  if (!/^[0-9a-fA-F]{40}$/.test(stripPrefix(p.to))) throw new Error("Destination address must be 20 bytes of hex (40 characters).");
  const amount = BigInt(p.amount);
  const tip = BigInt(p.tip);
  if (amount < 0n || tip < 0n) throw new Error("Amount and tip cannot be negative.");

  const { address } = await storageGet(["address"]);
  if (!address) throw new Error("Wallet address not found.");

  const [price, account] = await Promise.all([getPowerPrice(), getAccount(address)]);
  const fee = price * TRANSFER_POWER;
  if (fee > MAX_FEE) {
    throw new Error("Fee from the node is too high (" + fee + "). The node may be untrustworthy; transaction cancelled.");
  }
  if (tip > MAX_TIP) {
    throw new Error("Tip is too high (" + tip + "); transaction cancelled.");
  }
  if (BigInt(account.balance) < amount + tip + fee) {
    throw new Error("Insufficient balance for amount + tip + fee.");
  }
  return { account, price, fee, address };
}

async function sendTransaction(txParams) {
  const { account, price, fee, address } = await validateTxParams(txParams);
  const signedBodyHex = await signTx({
    to: txParams.to,
    nonce: account.nonce,
    amount: txParams.amount,
    tip: txParams.tip,
    pricePerPower: price,
  });
  const bodyBytes = hexToBytes(signedBodyHex);
  // The hash is computed locally from the body we send, then checked against the node's reply.
  const localHash = toRx(tx_hash_hex(signedBodyHex)).toLowerCase();
  const res = await rpcJson("send_transaction", {
    method: "POST",
    headers: { "Content-Type": "application/octet-stream" },
    body: bodyBytes,
  });
  const nodeHash = String(res.hash).toLowerCase();
  if (nodeHash !== localHash) {
    throw new Error(`Hash from the node (${nodeHash}) differs from the local hash (${localHash}). The transaction may already have been sent, check manually.`);
  }
  // The tx has been sent. If polling fails/times out, do not treat it as failed: record it as pending.
  let detail = null;
  try {
    detail = await waitTxResult(localHash);
  } catch (e) {
    console.warn("Tx polling not final yet:", e.message);
  }
  return {
    txHash: localHash,
    status: detail ? detail.txStatusText : "pending",
    fee: detail ? detail.fee : fee.toString(),
    detail,
    from: address,
  };
}

/*
Polling. The node only stores a tx after it is included in a block, so until then it answers 404:
- 404 / transient connection error -> retry
- 400 (bad hash format) -> bug, stop immediately
- FINAL (1/2) -> return
- attempts exhausted -> throw
*/
async function waitTxResult(txHash) {
  let lastErr = null;
  for (let attempt = 0; attempt < POLL_MAX_TRY; attempt++) {
    try {
      const detail = await getTransactionDetail(txHash);
      if (isFinalStatus(detail.txStatus)) return detail;
    } catch (e) {
      if (e instanceof RpcError && e.status === 400) throw e;
      lastErr = e;
    }
    await sleep(POLL_DELAY_MS);
  }
  throw new Error(
    "Transaction was not included in a block after " + (POLL_MAX_TRY * POLL_DELAY_MS / 1000) + " seconds" +
    (lastErr ? " (last error: " + lastErr.message + ")" : "") +
    ". tx_hash: " + txHash
  );
}

let wasmReady = init().catch((e) => {
  console.error("Failed to init wasm:", e);
  throw e;
});

let DEFAULT_PATH = null;
async function ensureWasm() {
  await wasmReady;
  if (DEFAULT_PATH === null) DEFAULT_PATH = build_hardened_path(COIN_TYPE, 0);
}

const SESSION_KEY = "session";
const LOCK_ALARM = "zecowallet-autolock";

function getSessionStorage() {
  if (typeof chrome === "undefined" || !chrome.storage || !chrome.storage.session) {
    throw new Error("chrome.storage.session is not available (requires Chrome 102+ and the \"storage\" permission).");
  }
  return chrome.storage.session;
}

function scheduleLockAlarm() {
  if (chrome.alarms) chrome.alarms.create(LOCK_ALARM, { when: Date.now() + AUTO_LOCK_MS });
}
function clearLockAlarm() {
  if (chrome.alarms) chrome.alarms.clear(LOCK_ALARM);
}

async function saveSession(mnemonics) {
  await getSessionStorage().set({ [SESSION_KEY]: { mnemonics, lockAt: Date.now() + AUTO_LOCK_MS } });
  scheduleLockAlarm();
}

async function readSession() {
  const data = await getSessionStorage().get([SESSION_KEY]);
  const s = data[SESSION_KEY];
  if (!s || !s.mnemonics) return null;
  if (Date.now() >= s.lockAt) { await lockWallet(); return null; }
  return s;
}

// Extend the idle timer on every activity.
async function touchSession(s) {
  s.lockAt = Date.now() + AUTO_LOCK_MS;
  await getSessionStorage().set({ [SESSION_KEY]: s });
  scheduleLockAlarm();
}

async function lockWallet() {
  await getSessionStorage().remove(SESSION_KEY);
  clearLockAlarm();
}

if (chrome.alarms) {
  chrome.alarms.onAlarm.addListener((alarm) => {
    if (alarm.name === LOCK_ALARM) readSession().catch(() => {});
  });
}

// Used by the popup on open: is the wallet still unlocked?
async function getSessionStatus() {
  const s = await readSession();
  if (!s) return { unlocked: false };
  await touchSession(s);
  const { address, wallets, activeId } = await storageGet(["address", "wallets", "activeId"]);
  const active = (wallets || []).find((w) => w.id === activeId);
  return { unlocked: true, address, name: active ? active.name : WALLET_MAIN_NAME };
}

/*
Vault v2+ = { version, salt, iv, ciphertext }; encrypted content = JSON {"wallets":[{id, mnemonic}]}.
Vault v1 (legacy) = { salt, iv, ciphertext } holding a single raw mnemonic; it is read as one
wallet and migrated automatically on the next unlock.
Wallet names & addresses (not secret) are stored separately in the "wallets" storage key for display.
*/
const WALLET_MAIN_NAME = "Main Wallet";
const LEGACY_WALLET_ID = "w1";
const MIN_PASSWORD_LEN = 10;
const PBKDF2_ITERATIONS = 600000;
const LEGACY_PBKDF2_ITERATIONS = 310000;
const VAULT_VERSION = 3;

async function deriveKeyFromPassword(password, saltBytes, iterations) {
  const keyMaterial = await crypto.subtle.importKey(
    "raw",
    new TextEncoder().encode(password),
    "PBKDF2",
    false,
    ["deriveKey"]
  );
  return crypto.subtle.deriveKey(
    { name: "PBKDF2", salt: saltBytes, iterations, hash: "SHA-256" },
    keyMaterial,
    { name: "AES-GCM", length: 256 },
    false,
    ["encrypt", "decrypt"]
  );
}

async function encryptText(text, password) {
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const key = await deriveKeyFromPassword(password, salt, PBKDF2_ITERATIONS);
  const ciphertext = await crypto.subtle.encrypt(
    { name: "AES-GCM", iv },
    key,
    new TextEncoder().encode(text)
  );
  return {
    iterations: PBKDF2_ITERATIONS,
    salt: Array.from(salt),
    iv: Array.from(iv),
    ciphertext: Array.from(new Uint8Array(ciphertext)),
  };
}

async function decryptText({ salt, iv, ciphertext, iterations }, password) {
  const key = await deriveKeyFromPassword(password, new Uint8Array(salt), iterations || LEGACY_PBKDF2_ITERATIONS);
  let plain;
  try {
    plain = await crypto.subtle.decrypt(
      { name: "AES-GCM", iv: new Uint8Array(iv) },
      key,
      new Uint8Array(ciphertext)
    );
  } catch {
    throw new Error("Incorrect password");
  }
  return new TextDecoder().decode(plain);
}

// wallets: [{ id, mnemonic }] -> current vault version
async function encryptVault(wallets, password) {
  const enc = await encryptText(JSON.stringify({ wallets }), password);
  return { version: VAULT_VERSION, ...enc };
}

async function decryptVault(vault, password) {
  if (!vault) throw new Error("No wallet yet");
  const plain = await decryptText(vault, password);
  if (vault.version >= 2) {
    const data = JSON.parse(plain);
    if (!data || !Array.isArray(data.wallets) || data.wallets.length === 0) throw new Error("Vault is corrupted");
    return data.wallets;
  }
  return [{ id: LEGACY_WALLET_ID, mnemonic: plain }]; // v1
}

async function previewNewWallet() {
  await ensureWasm();
  return generate_mnemonic(12);
}

function newWalletId() { return crypto.randomUUID(); }

function mnemonicMap(list) {
  return Object.fromEntries(list.map((w) => [w.id, w.mnemonic]));
}

async function finalizeWallet(mnemonic, password) {
  await ensureWasm();
  if (!validate_mnemonic(mnemonic)) throw new Error("Recovery phrase is invalid");
  if (!password || password.length < MIN_PASSWORD_LEN) throw new Error(`Password must be at least ${MIN_PASSWORD_LEN} characters`);
  if (await hasWallet()) throw new Error("A wallet already exists. Use Add Wallet.");
  const id = newWalletId();
  const address = derive_address(mnemonic, "", DEFAULT_PATH, ADDRESS_PREFIX);
  const vault = await encryptVault([{ id, mnemonic }], password);
  await storageSet({ vault, wallets: [{ id, name: WALLET_MAIN_NAME, address }], activeId: id, address });
  await saveSession({ [id]: mnemonic });
  return { address, name: WALLET_MAIN_NAME };
}

async function importWallet(mnemonic, password) {
  await ensureWasm();
  if (!validate_mnemonic(mnemonic)) throw new Error("Recovery phrase is invalid");
  return finalizeWallet(mnemonic, password);
}

async function hasWallet() {
  const { vault } = await storageGet(["vault"]);
  return !!vault;
}

async function getWallets() {
  const s = await readSession();
  if (!s) throw new Error("Wallet is locked, unlock first");
  await touchSession(s);
  const { wallets, activeId } = await storageGet(["wallets", "activeId"]);
  return { wallets: wallets || [], activeId };
}

async function addWallet(mnemonic, password) {
  await ensureWasm();
  const s = await readSession();
  if (!s) throw new Error("Wallet is locked, unlock first");
  if (!validate_mnemonic(mnemonic)) throw new Error("Recovery phrase is invalid");
  const { vault, wallets } = await storageGet(["vault", "wallets"]);
  const meta = wallets || [];
  const list = await decryptVault(vault, password); // wrong password -> throws
  const address = derive_address(mnemonic, "", DEFAULT_PATH, ADDRESS_PREFIX);
  if (meta.some((w) => w.address === address)) throw new Error("This wallet already exists");

  const id = newWalletId();
  const name = `Wallet ${meta.length + 1}`;
  const newVault = await encryptVault([...list, { id, mnemonic }], password);
  await storageSet({ vault: newVault, wallets: [...meta, { id, name, address }], activeId: id, address });
  await saveSession({ ...s.mnemonics, [id]: mnemonic });
  return { id, name, address };
}

async function switchWallet(id) {
  const s = await readSession();
  if (!s) throw new Error("Wallet is locked, unlock first");
  const { wallets } = await storageGet(["wallets"]);
  const w = (wallets || []).find((x) => x.id === id);
  if (!w) throw new Error("Wallet not found");
  if (!s.mnemonics[id]) throw new Error("Wallet is not unlocked yet, lock and unlock again");
  await storageSet({ activeId: id, address: w.address });
  await touchSession(s);
  return { id, name: w.name, address: w.address };
}

async function revealMnemonic(password) {
  await ensureWasm();
  const { vault, activeId } = await storageGet(["vault", "activeId"]);
  const list = await decryptVault(vault, password);
  const w = list.find((x) => x.id === activeId) || list[0];
  return w.mnemonic;
}

async function exportPrivateKey(password) {
  await ensureWasm();
  const mnemonic = await revealMnemonic(password);
  return derive_ed25519_privkey_hex(mnemonic, "", DEFAULT_PATH);
}

async function unlockWallet(password) {
  await ensureWasm();
  const { vault, wallets, activeId } = await storageGet(["vault", "wallets", "activeId"]);
  const list = await decryptVault(vault, password);
  const names = new Map((wallets || []).map((w) => [w.id, w.name]));
  const meta = list.map((w, i) => ({
    id: w.id,
    name: names.get(w.id) || (i === 0 ? WALLET_MAIN_NAME : `Wallet ${i + 1}`),
    address: derive_address(w.mnemonic, "", DEFAULT_PATH, ADDRESS_PREFIX),
  }));
  const active = meta.find((w) => w.id === activeId) || meta[0];
  const patch = { wallets: meta, activeId: active.id, address: active.address };
  if (vault.version !== VAULT_VERSION) patch.vault = await encryptVault(list, password); // migrate to current version
  await storageSet(patch);

  await saveSession(mnemonicMap(list));
  return { address: active.address, name: active.name };
}

async function requireUnlocked() {
  const s = await readSession();
  if (!s) throw new Error("Wallet is locked, unlock first");
  await touchSession(s);
  const { activeId } = await storageGet(["activeId"]);
  const mnemonic = s.mnemonics[activeId];
  if (!mnemonic) throw new Error("Active wallet not found, lock and unlock again");
  return mnemonic;
}

async function signTx({ to, nonce, amount, tip, pricePerPower }) {
  await ensureWasm();
  const mnemonic = await requireUnlocked();
  return sign_transaction(
    mnemonic, "", DEFAULT_PATH,
    CHAINID, 0, stripPrefix(to), toU64(nonce, "nonce"),
    u256ToHex(amount, "amount"), TRANSFER_POWER, TRANSFER_POWER,
    u256ToHex(pricePerPower, "price_per_power"), u256ToHex(tip, "tip")
  );
}

async function signMsg(message) {
  if (typeof message !== "string" || message.trim().length === 0) throw new Error("Message cannot be empty.");
  if (new TextEncoder().encode(message).length > MAX_SIGN_MSG_BYTES) {
    throw new Error(`Message is too long (max ${MAX_SIGN_MSG_BYTES} bytes).`);
  }
  await ensureWasm();
  const mnemonic = await requireUnlocked();
  return sign_message(mnemonic, "", DEFAULT_PATH, message, CHAINID);
}

async function verifyMsg(message, proofHex) {
  if (typeof message !== "string" || message.trim().length === 0) throw new Error("Message cannot be empty.");
  if (new TextEncoder().encode(message).length > MAX_SIGN_MSG_BYTES) {
    throw new Error(`Message is too long (max ${MAX_SIGN_MSG_BYTES} bytes).`);
  }
  if (typeof proofHex !== "string" || proofHex.length === 0) throw new Error("Proof cannot be empty.");
  await wasmReady; // verify does not need DEFAULT_PATH
  return verify_message(message, CHAINID, proofHex);
}

async function loadHistoryMap() {
  const { txHistoryByAddress, txHistory, address } = await storageGet(["txHistoryByAddress", "txHistory", "address"]);
  const map = txHistoryByAddress && typeof txHistoryByAddress === "object" ? txHistoryByAddress : {};
  if (Array.isArray(txHistory)) {
    if (address && !Array.isArray(map[address])) map[address] = txHistory;
    await storageSet({ txHistoryByAddress: map });
    await getStorage().remove("txHistory");
  }
  return { map, address };
}

async function recordHistoryEntry(entry, address) {
  const { map, address: active } = await loadHistoryMap();
  const key = address || active;
  const list = Array.isArray(map[key]) ? map[key] : [];
  list.unshift(entry); // newest first
  map[key] = list.slice(0, HISTORY_MAX_ENTRIES);
  await storageSet({ txHistoryByAddress: map });
}

async function getHistory() {
  const { map, address } = await loadHistoryMap();
  return Array.isArray(map[address]) ? map[address] : [];
}

chrome.runtime.onMessage.addListener((msg, sender, sendResponse) => {
  if (sender.id !== chrome.runtime.id) {
    sendResponse({ error: "Sender not allowed" });
    return false;
  }
  if (!msg || typeof msg.type !== "string") {
    sendResponse({ error: "Invalid message" });
    return false;
  }
  switch (msg.type) {
    case "GET_TRAFFIC":
      getTraffic()
        .then((traffic) => sendResponse({ traffic }))
        .catch((e) => sendResponse({ error: e.message }));
      return true;

    case "GET_ACCOUNT":
      (async () => {
        let addr = msg.address;
        if (!addr) {
          const { address } = await storageGet(["address"]);
          if (!address) throw new Error("Wallet address not found.");
          addr = address;
        }
        return getAccount(addr);
      })()
        .then((account) => sendResponse({ account }))
        .catch((e) => sendResponse({ error: e.message }));
      return true;

    case "GET_RPC":
      getRpcConfig()
        .then(sendResponse) // { url, defaultUrl, isDefault }
        .catch((e) => sendResponse({ error: e.message }));
      return true;

    case "TEST_RPC":
      testRpc(msg.url)
        .then(sendResponse) // { url, chainid, blockNumber, latencyMs }
        .catch((e) => sendResponse({ error: e.message }));
      return true;

    case "SET_RPC":
      setRpc(msg.url)
        .then(sendResponse)
        .catch((e) => sendResponse({ error: e.message }));
      return true;

    case "RESET_RPC":
      resetRpc()
        .then(sendResponse)
        .catch((e) => sendResponse({ error: e.message }));
      return true;

    case "GET_FEE_INFO":
      getFeeInfo()
        .then((info) => sendResponse({ info }))
        .catch((e) => sendResponse({ error: e.message }));
      return true;

    case "GET_TX_DETAIL":
      getTransactionDetail(msg.txHash)
        .then((detail) => sendResponse({ detail }))
        .catch((e) => sendResponse({ error: e.message }));
      return true;

    case "SEND_TX":
      sendTransaction(msg.tx)
        .then((result) => {
          recordHistoryEntry({
            to: msg.tx.to,
            amount: msg.tx.amount,
            fee: result.fee,
            tip: msg.tx.tip,
            status: result.status,
            txHash: result.txHash,
            timestamp: Math.floor(Date.now() / 1000),
          }, result.from).catch((e) => console.warn("Failed to save local history:", e.message));
          sendResponse(result);
        })
        .catch((e) => sendResponse({ error: e.message }));
      return true;

    case "GET_HISTORY":
      getHistory()
        .then((history) => sendResponse({ history }))
        .catch((e) => sendResponse({ error: e.message }));
      return true;

    case "HAS_WALLET":
      hasWallet()
        .then((exists) => sendResponse({ exists }))
        .catch((e) => sendResponse({ error: e.message }));
      return true;

    case "PREVIEW_NEW_WALLET":
      previewNewWallet()
        .then((mnemonic) => sendResponse({ mnemonic }))
        .catch((e) => sendResponse({ error: e.message }));
      return true;

    case "FINALIZE_WALLET":
      finalizeWallet(msg.mnemonic, msg.password)
        .then(sendResponse)
        .catch((e) => sendResponse({ error: e.message }));
      return true;

    case "IMPORT_WALLET":
      importWallet(msg.mnemonic, msg.password)
        .then(sendResponse)
        .catch((e) => sendResponse({ error: e.message }));
      return true;

    case "UNLOCK":
      unlockWallet(msg.password)
        .then(sendResponse) // { address, name }
        .catch((e) => sendResponse({ error: e.message }));
      return true;

    case "GET_WALLETS":
      getWallets()
        .then(sendResponse) // { wallets: [{id, name, address}], activeId }
        .catch((e) => sendResponse({ error: e.message }));
      return true;

    case "ADD_WALLET":
      addWallet(msg.mnemonic, msg.password)
        .then(sendResponse) // { id, name, address }
        .catch((e) => sendResponse({ error: e.message }));
      return true;

    case "SWITCH_WALLET":
      switchWallet(msg.id)
        .then(sendResponse) // { id, name, address }
        .catch((e) => sendResponse({ error: e.message }));
      return true;

    case "GET_SESSION":
      getSessionStatus()
        .then(sendResponse)
        .catch((e) => sendResponse({ error: e.message }));
      return true;

    case "LOCK":
      lockWallet()
        .then(() => sendResponse({ ok: true }))
        .catch((e) => sendResponse({ error: e.message }));
      return true;

    case "REVEAL_MNEMONIC":
      revealMnemonic(msg.password)
        .then((mnemonic) => sendResponse({ mnemonic }))
        .catch((e) => sendResponse({ error: e.message }));
      return true;

    case "EXPORT_PRIVATE_KEY":
      exportPrivateKey(msg.password)
        .then((privateKey) => sendResponse({ privateKey }))
        .catch((e) => sendResponse({ error: e.message }));
      return true;

    case "SIGN_MESSAGE":
      signMsg(msg.message)
        .then((proof) => sendResponse({ proof }))
        .catch((e) => sendResponse({ error: e.message }));
      return true;

    case "VERIFY_MESSAGE":
      verifyMsg(msg.message, msg.proof)
        .then((valid) => sendResponse({ valid }))
        .catch((e) => sendResponse({ error: e.message }));
      return true;

    default:
      // Unknown message type: reply with an error so the popup does not hang waiting for a response.
      sendResponse({ error: `Unknown message type: ${msg && msg.type}` });
      return false;
  }
});
