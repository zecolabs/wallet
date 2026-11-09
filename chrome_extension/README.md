# License
Licensed under either of Apache License 2.0 or MIT license at your option.
Unless you explicitly state otherwise, any contribution you submit shall be dual licensed as above, without additional terms.

# Zeco Wallet - Chrome Extension

Manifest V3 extension. The crypto code (BIP39, SLIP-0010 Ed25519, Keccak-256, signing) is Rust
compiled to WebAssembly; the UI is plain HTML/JS. You build the WebAssembly part yourself, which
creates the `pkg/` folder the extension needs, then load the folder into Chrome.

No Node.js or npm is required.

## 1. Requirements

- Google Chrome or Chromium 114+
- Rust installed with [rustup](https://rustup.rs). Rust from `apt` / `brew` has no WebAssembly
  target, so use rustup. Tested with Rust 1.85.
- A C compiler / linker (`build-essential` on Linux, Xcode Command Line Tools on macOS,
  *Build Tools for Visual Studio - Desktop development with C++* on Windows)

Install Rust (Linux / macOS):

```bash
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
source "$HOME/.cargo/env"
```

On Windows run `rustup-init.exe` from <https://rustup.rs> and open a new PowerShell window afterwards.

## 2. Build

All commands are run inside the `chrome_extension` folder.

```bash
cd chrome_extension

# 1) WebAssembly target for Rust (once)
rustup target add wasm32-unknown-unknown

# 2) Create Cargo.lock (skip if it already exists) and see which wasm-bindgen version it uses
cargo generate-lockfile
grep -A1 'name = "wasm-bindgen"$' Cargo.lock
```

The output looks like `version = "0.2.129"`. Install the **same version** of `wasm-bindgen-cli`
(a different version fails with *"schema version mismatch"*):

```bash
cargo install wasm-bindgen-cli --version 0.2.129 --locked   # replace 0.2.129 with your version
```

On Windows, open `Cargo.lock` in a text editor and search for `name = "wasm-bindgen"` to read the version.
This step compiles a tool and takes a few minutes, but you only do it once.

```bash
# 3) Compile Rust to WebAssembly
cargo build --release --target wasm32-unknown-unknown

# 4) Generate the JS glue code into pkg/
wasm-bindgen target/wasm32-unknown-unknown/release/libcrypto.wasm --out-dir pkg --target web
```

After this, `pkg/` contains `libcrypto.js` and `libcrypto_bg.wasm`, next to `manifest.json`,
`popup.html` and `background.js`. Run steps 3 and 4 again every time you change the Rust code.

## 3. Load into Chrome

1. Open `chrome://extensions`.
2. Turn on **Developer mode** (top right).
3. Click **Load unpacked** and select the `chrome_extension` folder (the one containing `manifest.json`).
4. Pin the **ZecoWallet** icon from the puzzle menu and click it.

After a rebuild, click the reload icon on the extension card.

By default the extension talks to a node at `http://127.0.0.1:3000/`; change it in *Wallet setting* or *manifest.json*.
```bash
# alpha mainnet rpc
https://alpha.zecolabs.com/
```

## 4. Troubleshooting

| Problem | Fix |
|---------|-----|
| Popup shows "wasm module not found" | `pkg/` is missing or in the wrong place; redo step 4 and make sure it is next to `popup.html` |
| `Failed to init wasm` in the extension console | `pkg/libcrypto.js` and `pkg/libcrypto_bg.wasm` must both exist; rebuild |
| `can't find crate for core` / target not installed | `rustup target add wasm32-unknown-unknown`; with Rust from apt/brew, install rustup instead |
| `schema version mismatch` | `wasm-bindgen-cli` version differs from `Cargo.lock`; reinstall with the exact version |
| `wasm-bindgen: command not found` | Open a new terminal or `source "$HOME/.cargo/env"` |
| Error mentioning a required `rustc` version | `rustup update` |
| `link.exe not found` (Windows) | Install Build Tools for Visual Studio with the C++ workload |
