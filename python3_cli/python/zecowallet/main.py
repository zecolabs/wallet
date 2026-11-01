import os, curses, json, locale, secrets, sys, textwrap, threading, time

import requests
from . import backend
from .backend import (
	Mnemonic, DecryptError, keccak256,
	account_index, 
	generate_mnemonic, is_hex, is_hex32b,
	is_hex_address, remove_prefix, throw
)

LOGO = [
    "        █▄      ",
    "        ███     ",
    "       █████    ",
    "     ▄██████    ",
    "  ▄█ ███████ ▄▀ ",
    " ▄█ ███████ ██▄ ",
    "▄██▄▀██  ██████▄",
    "████ ▀ ▄▄ ██████",
    "████▀ ▄██  ▀████",
    "▀███ ▄██▄▄█ ███▀",
    " ▀██ ██████ ██▀ ",
    "   ▀▀ ▀███▀ ▀   ",
]

ESC = "\x1b"
ENTER = ("\n", "\r", curses.KEY_ENTER)
BACKSPACE = ("\x7f", "\b", curses.KEY_BACKSPACE)
TX_STATUS = {0: "pending", 1: "success", 2: "failed"}
MAX_INDEX = 0x8000_0000
MAX_MESSAGE = 1024  # characters, for sign / verify message
PROOF_LEN = 104  # public_key (32) + signature (64) + timestamp u64 (8)


class Cancelled(Exception):
	"""user pressed Esc while waiting."""


class Invalid(Exception):
	"""validator: custom error message to be displayed."""


class G:
	"""glyphs; filled in by set_glyphs() according to the terminal's UTF-8 support."""


def set_glyphs(utf: bool):
	G.utf = utf
	G.tl, G.tr, G.bl, G.br, G.h, G.v = "╭╮╰╯─│" if utf else "++++-|"
	G.mask = "•" if utf else "*"
	G.sel = "▸" if utf else ">"
	G.spin = "⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏" if utf else "|/-\\"
	G.ud = "↑↓" if utf else "Up/Down"
	G.lr = "←→" if utf else "Left/Right"


class BalanceWatcher(threading.Thread):
	"""polls the balance in a separate thread so the UI does not lag when the node is slow."""

	def __init__(self):
		super().__init__(daemon=True)
		self.addr = None
		self.text = "-"
		self.ok = True
		self.ev = threading.Event()

	def set_address(self, addr):
		self.addr = addr
		self.text = "..." if addr else "-"
		self.ok = True
		self.ev.set()

	def poke(self):
		self.ev.set()

	def run(self):
		while True:
			self.ev.wait(10)
			self.ev.clear()
			addr = self.addr
			if not addr:
				continue
			try:
				acc = backend.get_account(addr)
				if "balance" in acc:
					text, ok = backend.to_coin(acc["balance"]), True
				elif acc.get("error") == "account not found":
					text, ok = "0", True
				else:
					text, ok = "error: %s" % acc.get("error", "unexpected response"), False
			except Exception:
				text, ok = "unavailable (node unreachable?)", False
			if addr == self.addr:
				self.text, self.ok = text, ok


def prepare_transfer(w, to: str, amount: int) -> dict:
	if not backend.validate(to, 40):
		raise Exception("invalid format recipient address")
	acc = backend.get_account(w.address)
	if "balance" not in acc:
		raise Exception("insufficient balance (account not found on chain)")
	nonce, balance = acc["nonce"], acc["balance"]
	if balance < amount:
		raise Exception("insufficient balance (you have %s)" % backend.to_coin(balance))
	power = 1200
	price = backend.get_power_price()
	fee = power * price
	if fee > backend.MAX_FEE:
		raise Exception("fee from node is too high (%s); the node may be untrustworthy" % backend.to_coin(fee))
	traffic = backend.get_traffic()
	if "medium" not in traffic:
		raise Exception("could not get tip from node: %s" % traffic.get("error", traffic))
	tip = traffic["medium"]
	if tip > backend.MAX_TIP:
		raise Exception("tip from node is too high (%s); the node may be untrustworthy" % backend.to_coin(tip))
	total = amount + fee + tip
	if balance < total:
		raise Exception("insufficient balance: amount + fee + tip = %s, you have %s"
		                % (backend.to_coin(total), backend.to_coin(balance)))
	return dict(nonce=nonce, balance=balance, power=power, price=price, fee=fee, tip=tip, total=total)


def send_transfer(w, to: str, amount: int, plan: dict) -> dict:
	public_key = w.public_key
	body = bytearray()
	for k in [
		backend.version,
		backend.chainid,
		backend.byte0,
		public_key,
		bytes.fromhex(backend.strip_rx(to)),
		backend.to_be_bytes(plan["nonce"], 8),
		backend.to_be_bytes(amount, 32),
		backend.to_be_bytes(plan["power"], 8),
		backend.to_be_bytes(plan["power"], 8),
		backend.to_be_bytes(plan["price"], 32),
		backend.byte0,
		backend.to_be_bytes(plan["tip"], 32),
	]:
		body.extend(k)
	msg_hash = keccak256(backend.TX_PREFIX + bytes(body))
	body.extend(w.sign(msg_hash))
	return requests.post(
		backend.rpc("send_transaction"),
		data=bytes(body),
		headers={"Content-Type": "application/octet-stream"},
		timeout=10,
	).json()

def msg_domain() -> bytes:
	return backend.msg_domain


def sign_message(w, message: str) -> str:
	ts = int(time.time()).to_bytes(8, "big")
	h = keccak256(msg_domain() + backend.chainid + message.encode("utf-8") + ts)
	signature = w.sign(h)
	return (w.public_key + signature + ts).hex()


def verify_message(message: str, proof: str) -> dict:
	"""the wallet only ensures the signature is valid; the timestamp is claimed by the signer."""
	h = bytes.fromhex(is_hex(proof))
	if len(h) != PROOF_LEN:
		raise Exception("invalid proof: must be %d bytes (%d hex chars), got %d bytes"
		                % (PROOF_LEN, PROOF_LEN * 2, len(h)))
	pubkey, signature, ts = h[:32], h[32:96], h[96:104]
	msgh = keccak256(msg_domain() + backend.chainid + message.encode("utf-8") + ts)
	if not backend.verify(pubkey, msgh, signature):
		raise Exception("message not match with proof given")
	return dict(address=backend.pubkey_to_address(pubkey), public_key=pubkey.hex(),
	            timestamp=int.from_bytes(ts, "big"))


def fmt_ts(ts: int) -> str:
	try:
		return time.strftime("%Y-%m-%d %H:%M:%S UTC", time.gmtime(ts))
	except (OverflowError, ValueError, OSError):
		return str(ts)


def init_attrs() -> dict:
	B = curses.A_BOLD
	A = dict(norm=0, bold=B, dim=curses.A_DIM, sel=curses.A_REVERSE | B,
	         accent=B, ok=B, err=B, warn=B, logo=[B] * len(LOGO))
	if not curses.has_colors():
		return A
	curses.start_color()
	bg = -1
	try:
		curses.use_default_colors()
	except curses.error:
		bg = curses.COLOR_BLACK
	big = curses.COLORS >= 256

	def cp(n, fg, bgc=bg):
		curses.init_pair(n, fg, bgc)
		return curses.color_pair(n)

	orange = 166 if big else curses.COLOR_YELLOW
	A["sel"] = cp(1, curses.COLOR_BLACK, orange) | B
	A["accent"] = cp(2, orange) | B
	A["ok"] = cp(3, curses.COLOR_GREEN) | B
	A["err"] = cp(4, curses.COLOR_RED) | B
	A["warn"] = cp(5, curses.COLOR_YELLOW) | B
	A["dim"] = cp(6, 244) if big else (cp(6, curses.COLOR_WHITE) | curses.A_DIM)
	grad = [220, 214, 214, 208, 208, 172, 172, 166, 166, 130, 130, 130] if big \
		else [curses.COLOR_YELLOW] * len(LOGO)
	A["logo"] = [cp(7 + i, c) | B for i, c in enumerate(grad)]
	return A

class App:
	def __init__(self, scr):
		self.scr = scr
		self.A = init_attrs()
		self.wallet = None
		self.watcher = BalanceWatcher()
		self.watcher.start()
		scr.keypad(True)
		self.cursor(False)


	def cursor(self, on: bool):
		try:
			curses.curs_set(1 if on else 0)
		except curses.error:
			pass

	def put(self, y, x, s, attr=0):
		h, w = self.scr.getmaxyx()
		if y < 0 or y >= h or x >= w or not s:
			return
		if x < 0:
			s, x = s[-x:], 0
		try:
			self.scr.addstr(y, x, s[:w - x], attr)
		except curses.error:
			pass

	def putseg(self, y, x, segs):
		for text, attr in segs:
			self.put(y, x, text, attr)
			x += len(text)

	def getkey(self, timeout=-1):
		self.scr.timeout(timeout)
		try:
			return self.scr.get_wch()
		except curses.error:
			return None
		except KeyboardInterrupt:
			return ESC


	def header(self) -> int:
		"""logo + status. Returns the first row that is free for content."""
		h, w = self.scr.getmaxyx()
		A = self.A
		if self.wallet is None:
			addr, bal = ("- (no wallet loaded)", A["dim"]), ("-", A["dim"])
		else:
			addr = (self.wallet.address, A["bold"])
			bal = (self.watcher.text, A["ok"] if self.watcher.ok else A["err"])
		node = (backend.CONFIG["rpc_url"], A["dim"])

		def row(y, x, label, val):
			self.putseg(y, x, [(label.ljust(9), A["dim"]), val])

		lw = max(len(s) for s in LOGO)
		nl = len(LOGO)
		wide = w >= 2 + lw + 4 + 9 + 44
		if not G.utf or h < nl + 14 or (not wide and h < nl + 17):
			self.put(0, 7, "wallet", A["dim"])
			row(1, 2, "address", addr)
			self.putseg(2, 2, [("balance".ljust(9), A["dim"]), bal, ("   node  ", A["dim"]), node])
			y = 3
		else:
			for i, line in enumerate(LOGO):
				self.put(1 + i, 2, line, A["logo"][i])
			if wide:
				x = 2 + lw + 4
				self.putseg(4, x, [(" wallet", A["dim"])])
				row(5, x, "address", addr)
				row(6, x, "balance", bal)
				row(7, x, "node", node)
				y = 1 + nl
			else:
				row(1 + nl, 2, "address", addr)
				row(2 + nl, 2, "balance", bal)
				row(3 + nl, 2, "node", node)
				y = 4 + nl
		self.put(y, 2, G.h * max(0, w - 4), A["dim"])
		return y + 1

	def page(self, title="", footer="", tattr=None) -> int:
		self.scr.erase()
		y = self.header()
		h, w = self.scr.getmaxyx()
		if title:
			self.put(y, 2, title, self.A["accent"] if tattr is None else tattr)
			y += 2
		if footer:
			self.put(h - 1, 2, footer, self.A["dim"])
		return y

	def text_lines(self, text, width, attr=0):
		out = []
		for para in text.split("\n"):
			for ln in (textwrap.wrap(para, width) or [""]):
				out.append([(ln, attr)])
		return out

	def kv_lines(self, pairs, width):
		kw = min(18, max((len(p[0]) for p in pairs if p[0]), default=0))
		vw = max(8, width - kw - 2)
		out = []
		for p in pairs:
			key, val = p[0], p[1]
			attr = p[2] if len(p) > 2 else 0
			if not key and not val:
				out.append([])
				continue
			parts = []
			for chunk in str(val).split("\n"):
				parts += textwrap.wrap(chunk, vw, break_long_words=True, break_on_hyphens=False) or [""]
			for i, part in enumerate(parts):
				out.append([((key[:kw] if i == 0 else "").ljust(kw) + "  ", self.A["dim"]), (part, attr)])
		return out

	def body_lines(self, text, pairs, width, attr=0):
		lines = self.text_lines(text, width, attr) if text else []
		if pairs:
			lines += ([[]] if lines else []) + self.kv_lines(pairs, width)
		return lines

	def dict_pairs(self, d: dict, first=None):
		A = self.A
		pairs = list(first or [])
		for k, v in d.items():
			attr = 0
			if k == "status":
				if isinstance(v, int):
					v = TX_STATUS.get(v, str(v))
				attr = A["ok"] if v == "success" else A["err"] if v == "failed" else A["warn"]
			if v is None:
				v = "-"
			elif isinstance(v, (dict, list)):
				v = json.dumps(v)
			pairs.append((k, str(v), attr))
		return pairs


	def menu(self, title, items, sel=0, footer=None):
		"""items: [(label, hint)]. Returns the index, or None on Esc/q."""
		n = len(items)
		keys = "1234567890"
		A = self.A
		while True:
			h, w = self.scr.getmaxyx()
			y = self.page(title, footer or "%s move   Enter select   1-9 jump   Esc back" % G.ud)
			avail = max(1, h - 1 - y)
			top = 0 if n <= avail else min(max(sel - avail // 2, 0), n - avail)
			bar = min(w - 4, max(max(len(it[0]) for it in items) + 10, 34))
			for i in range(top, min(n, top + avail)):
				label, hint = items[i]
				row = y + i - top
				num = keys[i] if i < 10 else " "
				if i == sel:
					self.put(row, 2, (" %s %s  %s" % (G.sel, num, label)).ljust(bar), A["sel"])
				else:
					self.put(row, 2, "   %s  " % num, A["dim"])
					self.put(row, 8, label)
				if hint and 2 + bar + 2 + len(hint) < w:
					self.put(row, 2 + bar + 2, hint, A["dim"])
			k = self.getkey(500)
			if k in (curses.KEY_UP, "k"):
				sel = (sel - 1) % n
			elif k in (curses.KEY_DOWN, "j"):
				sel = (sel + 1) % n
			elif k == curses.KEY_HOME:
				sel = 0
			elif k == curses.KEY_END:
				sel = n - 1
			elif k in ENTER:
				return sel
			elif k in (ESC, "q"):
				return None
			elif k == "r":
				self.watcher.poke()
			elif isinstance(k, str) and len(k) == 1 and k in keys and keys.index(k) < n:
				return keys.index(k)

	def viewer(self, title, build, footer=None, tattr=None) -> bool:
		"""scrollable page. Returns True on Enter, False on Esc/q."""
		top = 0
		while True:
			h, w = self.scr.getmaxyx()
			y = self.page(title, "", tattr)
			lines = build(max(10, w - 4))
			avail = max(1, h - 1 - y)
			maxtop = max(0, len(lines) - avail)
			self.put(h - 1, 2, footer or ("Enter continue   %s scroll   Esc close" % G.ud if maxtop
			                                else "Enter continue"), self.A["dim"])
			top = min(max(top, 0), maxtop)
			for i, segs in enumerate(lines[top:top + avail]):
				self.putseg(y + i, 2, segs)
			if maxtop and title:
				s = "%d-%d / %d" % (top + 1, min(top + avail, len(lines)), len(lines))
				self.put(y - 2, max(2, w - 2 - len(s)), s, self.A["dim"])
			k = self.getkey(500)
			if k in ENTER:
				return True
			if k in (ESC, "q"):
				return False
			if k in (curses.KEY_UP, "k"):
				top -= 1
			elif k in (curses.KEY_DOWN, "j"):
				top += 1
			elif k == curses.KEY_PPAGE:
				top -= avail
			elif k in (curses.KEY_NPAGE, " "):
				top += avail
			elif k == curses.KEY_HOME:
				top = 0
			elif k == curses.KEY_END:
				top = maxtop

	def notice(self, title, msg, kind="info", pairs=None):
		A = self.A
		attr = {"info": 0, "ok": A["ok"], "err": A["err"], "warn": A["warn"]}[kind]
		tattr = A["accent"] if kind == "info" else attr
		self.viewer(title, lambda w: self.body_lines(msg, pairs, w, attr), tattr=tattr)

	def confirm(self, title, text="", pairs=None, default=False, yes="Yes", no="No", kind="warn") -> bool:
		A = self.A
		tattr = {"info": A["accent"], "warn": A["warn"], "err": A["err"]}[kind]
		sel = 0 if default else 1
		while True:
			h, w = self.scr.getmaxyx()
			y = self.page(title, "%s choose   Enter confirm   y / n" % G.lr, tattr)
			lines = self.body_lines(text, pairs, w - 4)
			for segs in lines[:max(1, h - 1 - y - 3)]:
				self.putseg(y, 2, segs)
				y += 1
			y += 1
			x = 2
			for i, label in enumerate((yes, no)):
				btn = "  %s  " % label
				self.put(y, x, btn, A["sel"] if sel == i else A["dim"])
				x += len(btn) + 3
			k = self.getkey(500)
			if k in (curses.KEY_LEFT, curses.KEY_RIGHT, "\t", "h", "l"):
				sel = 1 - sel
			elif k in ("y", "Y"):
				return True
			elif k in ("n", "N", ESC):
				return False
			elif k in ENTER:
				return sel == 0

	def text_input(self, title, label, *, secret=False, default="", hint="", validate=None,
	               error="Invalid input", allow_empty=False, strip=True, msg="", rows=1, maxlen=None):
		"""Returns the result of validate() (or the raw string), None on Esc.
		rows > 1: multi-line input box (text is wrapped per character, wider).
		maxlen: character limit (extra characters are ignored, including when pasting)."""
		A = self.A
		buf, reveal, err = list(default), False, msg
		pos = len(buf)
		self.cursor(True)
		try:
			while True:
				h, w = self.scr.getmaxyx()
				foot = "Enter confirm   Esc cancel" + ("   Tab show/hide" if secret else "")
				y = self.page(title, foot)
				if hint:
					for ln in textwrap.wrap(hint, max(10, w - 4)):
						self.put(y, 2, ln, A["dim"])
						y += 1
					y += 1
				self.put(y, 2, label, A["bold"])
				y += 1
				wrap = rows > 1
				fw = max(8, min(w - 8, 120 if wrap else 72))
				shown = G.mask * len(buf) if secret and not reveal else "".join(buf)
				if wrap:
					nr = max(1, min(rows, h - y - 5))
					chunks = [shown[i:i + fw] for i in range(0, len(shown), fw)] or [""]
					cy, cx = divmod(pos, fw)
					while len(chunks) <= cy:
						chunks.append("")
					first = max(0, cy - nr + 1)
					vis = chunks[first:first + nr]
					vis += [""] * (nr - len(vis))
					cur = (y + 1 + cy - first, 4 + cx)
				else:
					nr = 1
					off = max(0, pos - (fw - 1))
					vis = [shown[off:off + fw]]
					cur = (y + 1, 4 + pos - off)
				self.put(y, 2, G.tl + G.h * (fw + 2) + G.tr, A["accent"])
				for i, ln in enumerate(vis):
					self.put(y + 1 + i, 2, G.v + " " + ln.ljust(fw) + " " + G.v, A["accent"])
					self.put(y + 1 + i, 4, ln, A["bold"])
				self.put(y + nr + 1, 2, G.bl + G.h * (fw + 2) + G.br, A["accent"])
				if wrap:
					if maxlen:
						cnt = " %d / %d chars " % (len(buf), maxlen)
						cattr = A["warn"] if len(buf) >= maxlen else A["dim"]
					else:
						cnt, cattr = " %d chars " % len(buf), A["dim"]
					self.put(y + nr + 1, max(4, fw + 4 - len(cnt)), cnt, cattr)
				if err:
					for i, ln in enumerate(textwrap.wrap(err, max(10, w - 4))):
						self.put(y + nr + 3 + i, 2, ln, A["err"])
				try:
					self.scr.move(*cur)
				except curses.error:
					pass

				k = self.getkey(500)
				if k is None or k == curses.KEY_RESIZE:
					continue
				if k == ESC:
					return None
				if k in ENTER:
					val = "".join(buf)
					if strip:
						val = val.strip()
					if val == "" and not allow_empty:
						err = "This field can't be empty"
						continue
					if validate is None:
						return val
					try:
						return validate(val)
					except Invalid as e:
						err = str(e) or error
					except Exception:
						err = error
					continue
				err = ""
				if k == curses.KEY_LEFT:
					pos = max(0, pos - 1)
				elif k == curses.KEY_RIGHT:
					pos = min(len(buf), pos + 1)
				elif k == curses.KEY_UP and rows > 1:
					pos = max(0, pos - fw)
				elif k == curses.KEY_DOWN and rows > 1:
					pos = min(len(buf), pos + fw)
				elif k in (curses.KEY_HOME, "\x01"):
					pos = 0
				elif k in (curses.KEY_END, "\x05"):
					pos = len(buf)
				elif k in BACKSPACE:
					if pos > 0:
						del buf[pos - 1]
						pos -= 1
				elif k == curses.KEY_DC:
					if pos < len(buf):
						del buf[pos]
				elif k == "\x15":  # ctrl-u
					del buf[:pos]
					pos = 0
				elif k == "\t":
					reveal = not reveal
				elif isinstance(k, str) and k.isprintable():
					if maxlen is None or len(buf) < maxlen:
						buf.insert(pos, k)
						pos += 1
		finally:
			self.cursor(False)

	def work(self, msg, fn, *args):
		"""run fn in a thread with a spinner; Esc = cancel (raises Cancelled)."""
		res = {}

		def target():
			try:
				res["v"] = fn(*args)
			except BaseException as e:  # forwarded to the caller
				res["e"] = e

		t = threading.Thread(target=target, daemon=True)
		t.start()
		i = 0
		while t.is_alive():
			y = self.page("Please wait", "Esc cancel")
			self.put(y, 2, "%s  %s" % (G.spin[i % len(G.spin)], msg), self.A["accent"])
			i += 1
			if self.getkey(100) == ESC:
				raise Cancelled
		if "e" in res:
			raise res["e"]
		return res.get("v")


	def need_wallet(self) -> bool:
		if self.wallet is None:
			self.notice("No wallet", "No wallet loaded. Create, import or load a wallet first (Wallet setting).", "warn")
			return False
		return True

	def replace_guard(self) -> bool:
		if self.wallet is None:
			return True
		return self.confirm(
			"Replace wallet",
			"A wallet is already loaded:\n%s\n\nReplacing it removes it from memory. "
			"Make sure it is backed up. Continue?" % self.wallet.address)

	def set_wallet(self, w, offer=True):
		self.wallet = w
		self.watcher.set_address(w.address)
		self.notice("Wallet ready", "Active address:\n%s" % w.address, "ok")
		if offer and self.confirm("Keystore", "Save this wallet to an encrypted keystore now?",
		                          default=True, kind="info"):
			self.ws_save_keystore()

	def ask_index(self, hint, default=""):
		def v(x):
			n = int(x)
			return n if 0 <= n < MAX_INDEX else throw()
		return self.text_input("Account index", "Account index", hint=hint, default=default,
		                       validate=v, error="Must be a number between 0 and 2147483647")


	def do_transfer(self):
		if not self.need_wallet():
			return
		to = self.text_input("Transfer", "To address", hint="Recipient: rx + 40 hex characters",
		                     validate=lambda v: is_hex_address(v) if v.startswith("rx") else throw(),
		                     error="Address must be rx + 40 length hexstring")
		if to is None:
			return
		amount = self.text_input("Transfer", "Amount (coin)", hint="e.g. 1.5 - positive, max 18 decimals",
		                         validate=backend.parse_amount,
		                         error="Please input a positive number, max 18 decimals (e.g. 1.5)")
		if amount is None:
			return
		w = self.wallet
		plan = self.work("Checking balance and fees...", prepare_transfer, w, to, amount)
		pairs = [
			("From", w.address),
			("To", to),
			("Amount", backend.to_coin(amount)),
			("Fee", backend.to_coin(plan["fee"])),
			("Tip", backend.to_coin(plan["tip"])),
			("Total", backend.to_coin(plan["total"]), self.A["bold"]),
		]
		if not self.confirm("Confirm transfer", "Review before sending. Transactions cannot be undone.",
		                    pairs=pairs, yes="Send", no="Cancel"):
			self.notice("Transfer", "Cancelled.", "info")
			return
		r = self.work("Signing and broadcasting...", send_transfer, w, to, amount, plan)
		if "hash" not in r:
			self.notice("Rejected", "The node rejected the transaction.", "err", self.dict_pairs(r))
			return
		self.watcher.poke()
		txh, tx = r["hash"], {}
		try:
			for n in range(1, 11):
				try:
					tx = self.work("Waiting for confirmation (%d/10)..." % n, backend.get_transaction_detail, txh)
				except requests.RequestException:
					tx = {}
				if isinstance(tx.get("status"), int) and tx["status"] > 0:
					break
				self.work("Waiting for confirmation (%d/10)..." % n, time.sleep, 1)
		except Cancelled:
			pass
		self.watcher.poke()
		if isinstance(tx.get("status"), int) and tx["status"] > 0:
			ok = tx["status"] == 1
			self.viewer("Transaction " + ("success" if ok else "failed"),
			            lambda wd: self.kv_lines(self.dict_pairs(backend.format_tx(tx)), wd),
			            tattr=self.A["ok"] if ok else self.A["err"])
		else:
			self.notice("Still pending", "Not confirmed yet. Check again later with Search TxHash.",
			            "warn", [("tx hash", txh)])

	def do_search_address(self):
		addr = self.text_input("Search address", "Account address", hint="rx + 40 hex characters",
		                       validate=lambda v: is_hex_address(v), error="Address must be rx + 40 length hexstring")
		if addr is None:
			return
		acc = self.work("Looking up account...", backend.get_account, addr)
		if "balance" in acc:
			d = dict(acc)
			d["balance_raw"] = d["balance"]
			d["balance"] = backend.to_coin(d["balance"])
			first = [] if "address" in d else [("address", addr)]
			self.viewer("Account", lambda w: self.kv_lines(self.dict_pairs(d, first), w))
		elif acc.get("error") == "account not found":
			self.notice("Account", "Account not found on chain (no balance / no transactions yet).\nBalance: 0",
			            "info", [("address", addr)])
		else:
			self.notice("Account", "Unexpected response from node.", "warn", self.dict_pairs(acc))

	def do_search_tx(self):
		txh = self.text_input("Search TxHash", "Transaction hash", hint="rx + 64 hex characters",
		                      validate=lambda v: "rx" + remove_prefix(is_hex32b(v)),
		                      error="TxHash must be rx + 64 length hexstring")
		if txh is None:
			return
		tx = self.work("Looking up transaction...", backend.get_transaction_detail, txh)
		if tx.get("error") == "transaction not found":
			self.notice("Transaction", "Transaction not found (not yet included in a block, or the hash is wrong).", "warn")
		else:
			self.viewer("Transaction", lambda w: self.kv_lines(self.dict_pairs(backend.format_tx(tx)), w))

	def do_search_block(self):
		number = self.text_input("Search block", "Block number", hint="Non-negative integer",
		                         validate=lambda v: int(v) if int(v) >= 0 else throw(),
		                         error="Block number must be a non-negative integer")
		if number is None:
			return
		blk = self.work("Looking up block...", backend.get_block, number)
		if blk.get("error") == "block not found":
			self.notice("Block", "Block %d not found (it may not have been produced yet)." % number, "warn")
		else:
			self.viewer("Block %d" % number, lambda w: self.kv_lines(self.dict_pairs(backend.format_block(blk)), w))

	def do_sign(self):
		if not self.need_wallet():
			return
		msg = self.text_input("Sign message", "Message", strip=False, rows=10, maxlen=MAX_MESSAGE,
		                      hint="Signed exactly as typed, including spaces. The proof embeds the current time.")
		if msg is None:
			return
		w, A = self.wallet, self.A
		proof = sign_message(w, msg)
		pairs = [("Message", msg), ("", ""), ("Proof", proof, A["ok"])]
		self.viewer("Message signed", lambda wd: self.kv_lines(pairs, wd), tattr=A["ok"])
		if not self.confirm("Save proof", "Save the proof to a file? (a terminal copy of the wrapped proof "
		                    "may contain line breaks; a file does not)", kind="info"):
			return
		path = self.text_input("Save proof", "File name", default="proof.txt")
		if path is None:
			return
		if os.path.exists(path) and not self.confirm("Overwrite", "%s already exists. Overwrite?" % path):
			return
		with open(path, "w") as f:
			f.write(proof + "\n")
		self.notice("Saved", "Proof saved to %s" % path, "ok")

	def do_verify(self):
		msg = self.text_input("Verify message", "Message", strip=False, rows=10, maxlen=MAX_MESSAGE,
		                      hint="Must match the signed message exactly (including spaces).")
		if msg is None:
			return

		def parse(v):
			if os.path.isfile(v):
				with open(v) as f:
					v = f.read().strip()
			h = is_hex(v)
			if len(bytes.fromhex(h)) != PROOF_LEN:
				raise Invalid("Proof must be %d bytes (%d hex chars)" % (PROOF_LEN, PROOF_LEN * 2))
			return h

		proof = self.text_input("Verify message", "Proof (hex, or path to a proof file)",
		                        hint="public key + signature + timestamp. rx / 0x prefix is allowed.",
		                        validate=parse, error="Proof must be a hex string")
		if proof is None:
			return
		try:
			r = verify_message(msg, proof)
		except Exception as e:
			self.notice("Invalid signature", str(e), "err")
			return
		self.notice("Signature valid", "The message was signed by the key below.\n"
		            "The timestamp is set by the signer and is not verified.", "ok",
		            [("Address", r["address"], self.A["bold"]), ("Public key", r["public_key"]),
		             ("Signed at", fmt_ts(r["timestamp"])), ("Message", msg)])

	def ws_show_info(self):
		if not self.need_wallet():
			return
		w = self.wallet
		pairs = [
			("Address", w.address, self.A["bold"]),
			("Public key", w.public_key.hex()),
			("Path", account_index(w.index) if w.mnemonic else "- (imported from private key)"),
			("", ""),
		]
		try:
			acc = self.work("Fetching balance...", backend.get_account, w.address)
			if "balance" in acc:
				acc = dict(acc)
				acc["balance_raw"] = acc["balance"]
				acc["balance"] = backend.to_coin(acc["balance"])
				pairs += self.dict_pairs(acc)
			elif acc.get("error") == "account not found":
				pairs.append(("Balance", "0 (account not found on chain yet)"))
			else:
				pairs += self.dict_pairs(acc)
		except Cancelled:
			raise
		except Exception as e:
			pairs.append(("Balance", "could not fetch balance: %s" % e, self.A["err"]))
		self.viewer("Wallet", lambda wd: self.kv_lines(pairs, wd))

	def ws_create(self):
		if not self.replace_guard():
			return
		phrase = generate_mnemonic()
		words = phrase.split()
		A = self.A

		def build(width):
			cols = 3 if width >= 52 else 2 if width >= 36 else 1
			rows = -(-len(words) // cols)
			lines = self.text_lines("Write these 12 words on paper and keep them offline.\n"
			                        "Anyone with these words controls your funds.", width, A["warn"])
			lines.append([])
			for r in range(rows):
				segs = []
				for c in range(cols):
					i = c * rows + r
					if i < len(words):
						segs += [("%2d. " % (i + 1), A["dim"]), (words[i].ljust(12), A["bold"])]
				lines.append(segs)
			return lines

		while True:
			if not self.viewer("New wallet - recovery phrase", build,
			                   footer="Enter: I wrote it down   Esc: cancel", tattr=A["warn"]):
				return
			n = secrets.randbelow(len(words))
			ans = self.text_input("Confirm backup", "Type word #%d" % (n + 1),
			                      hint="Esc to see the phrase again.",
			                      validate=lambda v: v.lower() if v.lower() == words[n] else throw(),
			                      error="Wrong word. Check your backup and try again")
			if ans is not None:
				break
		self.set_wallet(backend.Wallet.from_mnemonic(phrase, 0))

	def ws_import_mnemonic(self):
		if not self.replace_guard():
			return

		def v(x):
			p = " ".join(x.lower().split())
			if not Mnemonic("english").check(p):
				raise Invalid("Invalid mnemonic (check the words and their order)")
			return p

		phrase = self.text_input("Import mnemonic", "Mnemonic phrase", secret=True, validate=v,
		                         hint="12 / 24 words separated by spaces. Hidden while typing; Tab to reveal.")
		if phrase is None:
			return
		idx = self.ask_index("Press Enter for the default index 0.", default="0")
		if idx is None:
			return
		self.set_wallet(backend.Wallet.from_mnemonic(phrase, idx))

	def ws_import_private_key(self):
		if not self.replace_guard():
			return
		key = self.text_input("Import private key", "Private key (hex)", secret=True,
		                      hint="64 hex characters. Hidden while typing; Tab to reveal.",
		                      validate=lambda v: bytes.fromhex(remove_prefix(is_hex32b(v))),
		                      error="Invalid private key (must be 64 hex chars)")
		if key is None:
			return
		self.set_wallet(backend.Wallet.from_private_key(key))

	def ws_switch_account(self):
		if not self.need_wallet():
			return
		if not self.wallet.mnemonic:
			self.notice("Switch account", "Only wallets created from a mnemonic can switch account index.", "warn")
			return
		idx = self.ask_index("Current index: %d" % self.wallet.index)
		if idx is None:
			return
		self.set_wallet(backend.Wallet.from_mnemonic(self.wallet.mnemonic, idx))

	def ws_export_secret(self):
		if not self.need_wallet():
			return
		go = self.text_input("Export secrets", "Type SHOW to continue",
		                     hint="WARNING: never share this with anyone and never paste it into a website or chat.",
		                     validate=lambda v: v if v == "SHOW" else throw(), error="Type SHOW (uppercase) to continue")
		if go is None:
			return
		w, A = self.wallet, self.A
		pairs = []
		if w.mnemonic:
			pairs.append(("Mnemonic", w.mnemonic, A["bold"]))
		pairs.append(("Private key", w.private_key.hex(), A["bold"]))
		self.viewer("Secrets", lambda wd: self.text_lines(
			"Anyone who sees this controls your funds. Close this screen when you are done.", wd, A["err"])
			+ [[]] + self.kv_lines(pairs, wd), tattr=A["err"])

	def ws_save_keystore(self):
		if not self.need_wallet():
			return
		path = self.text_input("Save keystore", "File name", default=backend.KEYSTORE_FILE,
		                       hint="Wallet is stored encrypted (Argon2id + XChaCha20-Poly1305).")
		if path is None:
			return
		if os.path.exists(path) and not self.confirm("Overwrite", "%s already exists. Overwrite?" % path):
			return
		while True:
			p1 = self.text_input("Save keystore", "New password (min 8 chars)", secret=True, strip=False,
			                     validate=lambda v: v if len(v) >= 8 else (_ for _ in ()).throw(Invalid("Password too short")))
			if p1 is None:
				return
			p2 = self.text_input("Save keystore", "Repeat password", secret=True, strip=False,
			                     validate=lambda v: v if v == p1 else (_ for _ in ()).throw(Invalid("Password does not match")))
			if p2 is not None:
				break
		self.work("Encrypting...", backend.save_keystore, self.wallet, p1, path)
		self.notice("Saved", "Saved to %s (encrypted).\nKeep your password, it cannot be recovered." % path, "ok")

	def ws_load_keystore(self):
		path = self.text_input("Load keystore", "File name", default=backend.KEYSTORE_FILE)
		if path is None:
			return
		if not os.path.exists(path):
			self.notice("Load keystore", "File not found: %s" % path, "err")
			return
		if not self.replace_guard():
			return
		msg = ""
		for attempt in range(1, 4):
			pw = self.text_input("Load keystore", "Password", secret=True, strip=False, msg=msg,
			                     hint="%s   (attempt %d/3)" % (path, attempt))
			if pw is None:
				return
			try:
				w = self.work("Decrypting...", backend.load_keystore, path, pw)
			except DecryptError:
				msg = "Wrong password or corrupted keystore"
				continue
			except Cancelled:
				return
			except Exception as e:
				self.notice("Load keystore", "Failed to read keystore: %s" % e, "err")
				return
			self.set_wallet(w, offer=False)
			return
		self.notice("Load keystore", "Too many wrong attempts.", "err")

	def ws_rpc_url(self):
		url = self.text_input("RPC URL", "Node URL", default=backend.CONFIG["rpc_url"],
		                      hint="Current: %s" % backend.CONFIG["rpc_url"],
		                      validate=lambda v: v if v.startswith(("http://", "https://")) else (_ for _ in ()).throw(
			                      Invalid("URL must start with http:// or https://")))
		if url is None:
			return
		if not url.endswith("/"):
			url += "/"
		if url != backend.CONFIG["rpc_url"]:
			backend.CONFIG["rpc_url"] = url
			backend.save_config()
			if self.wallet:
				self.watcher.set_address(self.wallet.address)
		try:
			t = self.work("Testing connection...", backend.get_traffic)
			self.notice("RPC URL", "Connection OK.", "ok", self.dict_pairs(t, [("node", url)]))
		except Cancelled:
			pass
		except Exception as e:
			self.notice("RPC URL", "Cannot reach node: %s" % e, "err", [("node", url)])

	def guarded(self, fn):
		try:
			fn()
		except Cancelled:
			pass
		except requests.RequestException as e:
			self.notice("Network error", str(e), "err")
		except Exception as e:
			self.notice("Error", str(e) or e.__class__.__name__, "err")

	def wallet_setting(self):
		sel = 0
		while True:
			items = [
				("Show address / balance", ""),
				("Create new wallet", "new 12-word phrase"),
				("Import mnemonic", ""),
				("Import private key", ""),
				("Switch account index", "index %d" % self.wallet.index if self.wallet and self.wallet.mnemonic else ""),
				("Export mnemonic / private key", ""),
				("Save encrypted keystore", backend.display_path(backend.KEYSTORE_FILE)),
				("Load encrypted keystore", ""),
				("RPC URL", backend.CONFIG["rpc_url"]),
				("Back", ""),
			]
			fns = [self.ws_show_info, self.ws_create, self.ws_import_mnemonic, self.ws_import_private_key,
			       self.ws_switch_account, self.ws_export_secret, self.ws_save_keystore, self.ws_load_keystore,
			       self.ws_rpc_url]
			i = self.menu("Wallet setting", items, sel)
			if i is None or i == len(fns):
				return
			sel = i
			self.guarded(fns[i])

	def startup(self):
		path = backend.KEYSTORE_FILE
		if not os.path.exists(path):
			self.notice("Welcome", "No wallet found. Create or import one first.", "info")
			return self.wallet_setting()
		msg = ""
		for attempt in range(1, 4):
			pw = self.text_input("Unlock wallet", "Password", secret=True, strip=False, msg=msg,
			                     hint="Keystore found: %s   (attempt %d/3)" % (path, attempt))
			if pw is None:
				break
			try:
				self.wallet = self.work("Unlocking...", backend.load_keystore, path, pw)
				self.watcher.set_address(self.wallet.address)
				return
			except DecryptError:
				msg = "Wrong password"
			except Cancelled:
				break
			except Exception as e:
				self.notice("Keystore", "Failed to read keystore: %s" % e, "err")
				break
		self.notice("Wallet locked", "Use Wallet setting to create / import / load another wallet.", "warn")
		self.wallet_setting()

	def main_menu(self):
		items = [
			("Transfer", "send coins"),
			("Search address", "balance & nonce"),
			("Search TxHash", "transaction detail"),
			("Search block", "block detail"),
			("Sign message", "prove ownership of address"),
			("Verify message", "check message + proof"),
			("Wallet setting", "create / import / keystore / RPC"),
			("Exit", ""),
		]
		fns = [self.do_transfer, self.do_search_address, self.do_search_tx, self.do_search_block,
		       self.do_sign, self.do_verify, self.wallet_setting]
		sel = 0
		while True:
			i = self.menu("Main menu", items, sel,
			              footer="%s move   Enter select   1-%d jump   r refresh balance   q quit" % (G.ud, len(items)))
			if i is None or i == len(fns):
				if self.confirm("Exit", "Quit the wallet?", kind="info"):
					return
				continue
			sel = i
			self.guarded(fns[i])

	def run(self):
		self.guarded(self.startup)
		self.main_menu()


def main(scr):
	App(scr).run()


def cli():
	"""entry point of the `zecowallet` command."""
	if not (sys.stdin.isatty() and sys.stdout.isatty()):
		sys.exit("zecowallet needs an interactive terminal")
	locale.setlocale(locale.LC_ALL, "")
	set_glyphs("utf" in (locale.getpreferredencoding(False) or "").lower())
	os.environ.setdefault("ESCDELAY", "25")
	backend.load_config()
	try:
		curses.wrapper(main)
	except KeyboardInterrupt:
		pass


if __name__ == "__main__":
	cli()
