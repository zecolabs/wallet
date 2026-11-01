# Zeco Wallet

[![License: MIT OR Apache-2.0](https://img.shields.io/badge/license-MIT%20OR%20Apache--2.0-blue)](#license)

Wallet for the Zeco blockchain, with two front-ends that share the same Rust crypto core
(Keccak-256, Ed25519, Argon2id + XChaCha20-Poly1305 encrypted keystore):

- **Terminal wallet** (`zecowallet`): curses UI, installable with `pip`.
- **Chrome extension**: browser wallet (Manifest V3).

## License

Licensed under either of

- [Apache License, Version 2.0](LICENSE-APACHE)
- [MIT license](LICENSE-MIT)

at your option.

Unless you explicitly state otherwise, any contribution intentionally submitted for
inclusion in this project by you, as defined in the Apache-2.0 license, shall be dual
licensed as above, without any additional terms or conditions.

The bundled font (Figtree) in `chrome_extension/fonts/` is licensed separately under the
SIL Open Font License 1.1, see [`chrome_extension/fonts/OFL.txt`](chrome_extension/fonts/OFL.txt).

---

## Terminal wallet

### Install from PyPI (Linux, macOS, Windows)

Requires Python 3.8 or newer. Prebuilt wheels are published, so no Rust toolchain or
compiler is needed.

```bash
pip install zecowallet
zecowallet
```

Tip (Linux/macOS): install it into its own virtual environment (or use
`pipx install zecowallet`) so it does not touch your system Python:

```bash
python3 -m venv ~/.zecowallet-venv
~/.zecowallet-venv/bin/pip install zecowallet
~/.zecowallet-venv/bin/zecowallet
```

Prebuilt wheels are available for:

| OS | Architectures |
|----|---------------|
| Linux (glibc, `manylinux`) | x86_64, aarch64 |
| Linux (musl, e.g. Alpine) | x86_64, aarch64 |
| macOS | Apple Silicon (arm64) |
| Windows | x64 |

On any other platform (for example an Intel Mac) `pip` falls back to building from source,
which needs [Rust](https://rustup.rs) and a C compiler. See
[Build from source](#build-from-source).

On Windows, the curses dependency (`windows-curses`) is installed automatically.

### Termux (Android, arm64)

Compiling the Rust core on a phone takes a long time, so install the prebuilt wheel
from the [Releases page](https://github.com/zecolabs/wallet/releases) instead of
`pip install zecowallet`:

```bash
pkg install -y python
pip install https://github.com/zecolabs/wallet/releases/download/0.1.0/zecowallet-0.1.0-cp38-abi3-android_24_arm64_v8a.whl
zecowallet
```

If you prefer to build it yourself, follow [`python3_cli/README.md`](python3_cli/README.md).
In our tests this is much lighter than `pip install zecowallet`, which compiles the whole
Rust core from source on the phone.

### Build from source

For the terminal wallet (maturin + Rust), see
[`python3_cli/README.md`](python3_cli/README.md).

---

## Chrome extension

### Prebuilt release (recommended)

**Desktop (Chrome, Edge, Brave, ...)**

1. Download the extension `.zip` from the
   [Releases page](https://github.com/zecolabs/wallet/releases) and extract it to a folder.
2. Open `chrome://extensions` in your browser.
3. Turn on **Developer mode** (top right).
4. Click **Load unpacked** and select the extracted folder (the one that contains
   `manifest.json`).
5. Pin the extension from the puzzle-piece menu if you want quick access.

To update, download the newer release, extract it over the same folder, and press the
reload button on the extension card in `chrome://extensions`.

**Android**

Android browsers that support Chrome extensions cannot load an
extracted folder. They install directly from the `.zip`, so **do not extract it**:

1. Download the extension `.zip` from the
   [Releases page](https://github.com/zecolabs/wallet/releases) and keep it as a `.zip`.
2. Open `chrome://extensions` in the browser.
3. Turn on **Developer mode**.
4. Tap **+ (from .zip/.crx/.user.js)** and choose the downloaded `.zip` file.
5. The extension appears in the list. Open it from the browser menu.

To update, install the newer `.zip` the same way (remove the old version first if the
browser reports a conflict).

### Build manually

See [`chrome_extension/README.md`](chrome_extension/README.md).

---

## Security notes

- The wallet is stored encrypted (Argon2id + XChaCha20-Poly1305). **Keep your password and
  recovery phrase safe: they cannot be recovered.**
- Only install releases from this repository's
  [Releases page](https://github.com/zecolabs/wallet/releases) or from PyPI under the name
  `zecowallet`.
