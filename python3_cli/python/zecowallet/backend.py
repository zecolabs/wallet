import os, re, sys, requests, json
from mnemonic import Mnemonic
from . import _libcrypto as libcrypto
from ._libcrypto import keccak256, DecryptError, KeystoreError

import hashlib, hmac

def data_dir() -> str:
	"""Per-user folder for wallet.json and config.json (independent of the current directory).
	Override with the ZECOWALLET_HOME environment variable."""
	env = os.environ.get("ZECOWALLET_HOME")
	if env:
		return os.path.abspath(os.path.expanduser(env))
	home = os.path.expanduser("~")
	if sys.platform == "win32":
		base = os.environ.get("APPDATA") or home
	elif sys.platform == "darwin":
		base = os.path.join(home, "Library", "Application Support")
	else:
		base = os.environ.get("XDG_DATA_HOME") or os.path.join(home, ".local", "share")
	return os.path.join(base, "zecowallet")


DATA_DIR = data_dir()
CONFIG_FILE = os.path.join(DATA_DIR, "config.json")
KEYSTORE_FILE = os.path.join(DATA_DIR, "wallet.json")


def ensure_dir(d: str):
	"""create folder d (owner-only permissions) if it does not exist yet."""
	if d:
		os.makedirs(d, mode=0o700, exist_ok=True)


def display_path(p: str) -> str:
	"""shorten the home folder to ~ for display."""
	home = os.path.expanduser("~")
	if home and (p == home or p.startswith(home + os.sep)):
		return "~" + p[len(home):]
	return p

MAX_FEE = 10 ** 17
MAX_TIP = 10 ** 17
CONFIG = {"rpc_url": "http://127.0.0.1:3000/"}
COIN_TYPE = 15_000
DEFAULT_PATH = "m/44'/%d'/0'/0'/0'" % COIN_TYPE
TX_PREFIX = b"\x01"
DECIMALS = 18
UNIT = 10 ** DECIMALS

byte0 = b"\x00"
version = b"\x01"
chainid = (1).to_bytes(4, "big") or b"\x00\x00\x00\x01"
msg_domain = b"\x00I signing this message"
address_prefix = "rx"

def get_power_price() -> int:
	d = requests.get(rpc("power_price"), timeout=10).json()
	if "power_price" not in d:
		raise Exception("could not get power price from node: %s" % d.get("error", d))
	return int(d["power_price"])

def load_config():
	try:
		with open(CONFIG_FILE) as f:
			CONFIG.update(json.load(f))
	except (FileNotFoundError, json.JSONDecodeError):
		pass


def save_config():
	ensure_dir(os.path.dirname(CONFIG_FILE))
	with open(CONFIG_FILE, "w") as f:
		json.dump(CONFIG, f, indent=4)


def rpc(path: str) -> str:
	return CONFIG["rpc_url"] + path

def strip_rx(v: str) -> str:
	"""drop a leading 'rx' (str.removeprefix needs Python 3.9; this package supports 3.8)."""
	return v[2:] if v.startswith("rx") else v


def validate(v: str, expect_length: int) -> bool:
	try:
		if v.startswith("rx"):
			if len(v) == (expect_length + 2):
				bytes.fromhex(strip_rx(v))
				return True
	except Exception:
		return False
	return False


def parse_int(key: list, data: dict):
	for k in key:
		data[k] = int(data[k])


def format_block(block: dict) -> dict:
	"""copy of the block detail with u256 fields (fees/tips collected) in coin units."""
	out = dict(block)
	for k in ("fees_collected", "tips_collected"):
		if isinstance(out.get(k), int):
			out[k] = to_coin(out[k])
	return out


def to_coin(v: int) -> str:
	"""smallest unit -> coin string, using integer math (no float)."""
	whole, frac = divmod(int(v), UNIT)
	frac_s = str(frac).zfill(DECIMALS).rstrip("0")
	return "%d.%s" % (whole, frac_s) if frac_s else str(whole)

def from_coin(v: str) -> int:
	"""coin string (e.g. '1.5') -> smallest unit, using integer math (no float)."""
	m = re.fullmatch(r"(\d+)(?:\.(\d{1,%d}))?" % DECIMALS, v.strip())
	if not m:
		raise ValueError("invalid coin amount: %r" % v)
	whole, frac = m.group(1), m.group(2) or ""
	return int(whole) * UNIT + int(frac.ljust(DECIMALS, "0"))

def parse_amount(v: str) -> int:
	"""coin string (e.g. '1.5') -> smallest unit. Max 18 decimals, must be > 0."""
	v = v.strip()
	m = re.fullmatch(r"(\d+)(?:\.(\d{1,%d}))?" % DECIMALS, v)
	if not m:
		throw()
	n = int(m.group(1)) * UNIT + int((m.group(2) or "").ljust(DECIMALS, "0"))
	if n <= 0:
		throw()
	return n


def format_tx(tx: dict) -> dict:
	"""copy of the tx detail with u256 fields in coin units (for display).
	u64 fields (nonce, power, power_used, power_limit, blocknumber, timestamp) are left unchanged."""
	out = dict(tx)
	for k in ("amount", "fee", "tip", "price_per_power"):
		if isinstance(out.get(k), int):
			out[k] = to_coin(out[k])
	return out

def get_transaction_detail(tx_hash: str) -> dict:
	if not validate(tx_hash, 64):
		raise Exception("tx_hash must be rx + 64 hexstring")
	r = requests.get(rpc("transaction/" + tx_hash), timeout=10)
	raw = r.json()

	k = [
		"blocknumber", "timestamp",
		"power_used", "fee", "nonce", "amount",
		"power", "power_limit", "price_per_power", "tip"
	]
	if raw.get("blocknumber"):
		parse_int(k, raw)
	return raw


def get_block(number: int) -> dict:  # "/block/:number
	r = requests.get(rpc("block/" + str(number)), timeout=10)
	raw = r.json()
	k = [
		"blocknumber", "timestamp",
		"power_used", "power_limit",
		"fees_collected", "tips_collected",
	]
	if "blocknumber" in raw:  # not raw.get(): block 0 (genesis) must not be skipped
		parse_int(k, raw)
	return raw


def get_traffic() -> dict:
	r = requests.get(rpc("traffic"), timeout=10)
	raw = r.json()
	if raw.get("medium"):
		parse_int(["min", "medium", "fast"], raw)
	return raw


def get_account(address: str) -> dict:
	if not validate(address, 40):
		raise Exception("address must be rx + 40 hexstring")
	r = requests.get(rpc("account/" + address), timeout=10)
	raw = r.json()
	if "balance" in raw:
		nonce_key = "pending_nonce" if "pending_nonce" in raw else "nonce"
		parse_int(["balance", nonce_key], raw)
		raw["nonce"] = raw[nonce_key]
	return raw



# ---------------------------------------------------------------- wallet

def pubkey_to_address(public_key: bytes) -> str:
	return address_prefix + keccak256(public_key)[-20:].hex()


def verify(public_key: bytes, msg: bytes, signature: bytes) -> bool:
	"""ed25519 verify_strict. Returns False if the signature/key is invalid.
	Raises ValueError only if the public_key (32) or signature (64) length is wrong."""
	return libcrypto.ed25519_verify(public_key, msg, signature)


class Wallet:
	def __init__(self, private_key: bytes, mnemonic: str = None, index: int = 0):
		self.private_key = private_key
		self.mnemonic = mnemonic  # None if imported from a private key
		self.index = index

	@classmethod
	def from_mnemonic(cls, phrase: str, index: int = 0):
		key = ed25519_private_key(phrase, account_index(index))
		return cls(key, phrase, index)

	@classmethod
	def from_private_key(cls, key: bytes):
		if len(key) != 32:
			raise Exception("private key must be 32 bytes")
		return cls(key)

	@property
	def public_key(self) -> bytes:
		return libcrypto.ed25519_public_key(self.private_key)

	def sign(self, msg: bytes) -> bytes:
		"""64-byte ed25519 signature over msg (deterministic, RFC 8032)."""
		return libcrypto.ed25519_sign(self.private_key, msg)

	@property
	def address(self) -> str:
		return pubkey_to_address(self.public_key)

	def to_payload(self) -> dict:
		return {
			"private_key": self.private_key.hex(),
			"mnemonic": self.mnemonic,
			"index": self.index,
		}

	@classmethod
	def from_payload(cls, p: dict):
		return cls(bytes.fromhex(p["private_key"]), p.get("mnemonic"), p.get("index", 0))

def encrypt_payload(payload: dict, password: str, address: str = "") -> str:
	"""payload -> JSON keystore v2 (Argon2id + XChaCha20-Poly1305).
	address is public but is authenticated together with the KDF parameters."""
	return libcrypto.keystore_encrypt(json.dumps(payload).encode(), password, address)


def decrypt_payload(ks_json: str, password: str) -> dict:
	"""DecryptError if the password is wrong / the file is corrupted,
	KeystoreError if the keystore format or version is invalid."""
	return json.loads(libcrypto.keystore_decrypt(ks_json, password))


def save_keystore(w: Wallet, password: str, path: str):
	ks = encrypt_payload(w.to_payload(), password, w.address)
	ensure_dir(os.path.dirname(os.path.abspath(path)))
	tmp = path + ".tmp"
	fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
	with os.fdopen(fd, "w") as f:
		f.write(ks)
	os.replace(tmp, path)


def load_keystore(path: str, password: str) -> Wallet:
	with open(path) as f:
		ks = f.read()
	w = Wallet.from_payload(decrypt_payload(ks, password))
	if json.loads(ks).get("address") != w.address:
		raise KeystoreError("keystore address does not match the wallet inside")
	return w


def to_be_bytes(v: int, size: int) -> bytes:
	valid = [1, 2, 4, 8, 32]  # uint128 are never used here
	if size not in valid:
		raise Exception("invalid size %d, must be in %s" % (size, str(valid)))
	return v.to_bytes(size, "big")

def throw():
	raise Exception 

def remove_prefix(v: str) -> str:
	if v.startswith("rx") or v.startswith("0x"):
		v = v[2:]
	return v

def is_hex(v: str) -> str:
	v = remove_prefix(v)
	bytes.fromhex(v)
	return v

def is_hex32b(v: str) -> str:
	h = remove_prefix(v)
	if len(h) == 64:
		bytes.fromhex(h)
		return v
	raise Exception

def is_hex_address(v: str) -> str:
	if v.startswith("rx"):
		if len(v) == 42:
			bytes.fromhex(strip_rx(v))
			return v
	raise Exception 

def account_index(x: int) -> str:
	return "m/44'/%d'/0'/0'/%d'" %(COIN_TYPE, x)

def generate_mnemonic():
	mnemo = Mnemonic("english")
	phrase = mnemo.generate(strength=128)
	return phrase

def parse_hardened_path(path: str): # [u32; 5]
	s = path.split("/")
	if s[0] != "m":
		raise Exception("path must start with 'm/'")
	out = []
	for seg in s[1:]:
		if not seg.endswith("\'"):
			raise Exception(f"level '{seg}' is not hardened — Ed25519 (SLIP-0010) requires all levels to be hardened")
		num = int(seg[:-1])
		if num >= 0x8000_0000:
			raise Exception(f"index too large: {seg}")
		out.append(num + 0x8000_0000)
	return out


def slip10_master(seed: bytes):
	mac = hmac.new(b"ed25519 seed", digestmod=hashlib.sha512)
	mac.update(seed)
	r = mac.digest()
	return (r[:32], r[-32:])

def slip10_child(private_key: bytes, chain_code: bytes, index_hardened: int):
	mac = hmac.new(chain_code, digestmod=hashlib.sha512)
	mac.update(b"\x00")
	mac.update(private_key)
	mac.update(index_hardened.to_bytes(4, "big"))
	r = mac.digest()
	return (r[:32], r[-32:])

def derive_priv_seed(phrase: str, path: str):
	mnemo = Mnemonic("english")
	if not mnemo.check(phrase):
		raise Exception("invalid mnemonic")
	seed = mnemo.to_seed(phrase)
	indices = parse_hardened_path(path)
	key, chain = slip10_master(seed)
	for idx in indices:
		key, chain = slip10_child(key, chain, idx)
	return key

def ed25519_public_key(privkey: bytes):
	return libcrypto.ed25519_public_key(privkey)

def ed25519_private_key(phrase: str, path):
	seed = derive_priv_seed(phrase, path)
	return seed
