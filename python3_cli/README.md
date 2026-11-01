# License

Licensed under either of Apache License 2.0 or MIT license at your option.
Unless you explicitly state otherwise, any contribution you submit shall be dual licensed as above, without additional terms.

# Zeco Wallet CLI

Terminal wallet (curses UI) with a Rust crypto core (Keccak-256, Ed25519, encrypted keystore).
The Rust part is compiled with [maturin](https://www.maturin.rs/) and installed together with the
Python code as one package. After installing, just run:

```bash
zecowallet
```

## 1. Requirements

| Tool | Notes |
|------|-------|
| Python 3.8+ | with `venv` and `pip` |
| Rust (stable) | install with [rustup](https://rustup.rs). Tested with Rust 1.85 |
| C compiler / linker | `build-essential` (Linux), Xcode Command Line Tools (macOS), MSVC Build Tools (Windows) |

maturin and the Python libraries (`requests`, `mnemonic`) are installed automatically by `pip`.

### Linux (Debian / Ubuntu)

```bash
sudo apt update
sudo apt install -y python3 python3-venv python3-pip build-essential curl git
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
source "$HOME/.cargo/env"
```

### macOS

```bash
xcode-select --install
brew install python git
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
source "$HOME/.cargo/env"
```

### Windows

1. Install Python from <https://www.python.org/downloads/> (tick **Add python.exe to PATH**).
2. Install **Build Tools for Visual Studio** and select the workload **Desktop development with C++**.
3. Install Rust with `rustup-init.exe` from <https://rustup.rs>.
4. Open a **new** PowerShell window and continue with "Manual install" below.

### Termux (Android)

```bash
pkg update && pkg upgrade -y
pkg install -y python rust clang make git
```

If the build stops with an error about the Android API level, run
`export ANDROID_API_LEVEL=$(getprop ro.build.version.sdk)` and try again.

## 2. Quick install (Linux / macOS / Termux)

```bash
git clone <repository-url>
cd <repository>/python3_cli
bash install.sh
zecowallet
```

The script builds the Rust core, installs everything into its own virtualenv
(`~/.zecowallet-venv`) and links the `zecowallet` command into `~/.local/bin`
(Termux: `$PREFIX/bin`). If it prints a note about `PATH`, add the line it shows to
`~/.bashrc` or `~/.zshrc` and open a new terminal.

## 3. Manual install (any OS)

Linux / macOS / Termux:

```bash
cd python3_cli
python3 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
pip install .
zecowallet
```

Windows (PowerShell):

```powershell
cd python3_cli
py -m venv .venv
# if activation is blocked:  Set-ExecutionPolicy -Scope Process Bypass
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
pip install .
zecowallet
```

`pip install .` does everything: it builds the Rust library with maturin, installs the Python
package and creates the `zecowallet` command. Every new terminal needs
`source .venv/bin/activate` (Windows: `.\.venv\Scripts\Activate.ps1`) before `zecowallet` works.
You can also run it as `python -m zecowallet`.

## 4. Where are my files?

The wallet and settings are stored in a per-user folder, **not** in the folder where you
start `zecowallet`:

| OS | Folder |
|----|--------|
| Linux / Termux | `~/.local/share/zecowallet/` (or `$XDG_DATA_HOME/zecowallet/`) |
| macOS | `~/Library/Application Support/zecowallet/` |
| Windows | `%APPDATA%\zecowallet\` |

Files in that folder: `wallet.json` (encrypted keystore) and `config.json` (RPC URL).
To use another folder, set `ZECOWALLET_HOME` (for example `export ZECOWALLET_HOME=~/my-wallet`).

Uninstalling the package does **not** delete this folder. **Back up `wallet.json` and keep your
password and mnemonic safe; they cannot be recovered.**

Coming from an older version that kept `wallet.json` in the working directory? Copy it to the
folder above, or use *Wallet setting -> Load encrypted keystore* and type its path.

The node address defaults to `http://127.0.0.1:3000/`; change it in *Wallet setting -> RPC URL*.

## 5. Update / uninstall

```bash
git pull
pip install --upgrade --force-reinstall .      # inside the virtualenv, from python3_cli/
pip uninstall zecowallet
```

## 6. Development

```bash
pip install maturin
maturin develop --release     # builds the Rust core and installs the package in editable mode
python -m zecowallet
```

## 7. Troubleshooting

| Problem | Fix |
|---------|-----|
| `cargo: command not found` | Open a new terminal or run `source "$HOME/.cargo/env"`; install Rust if missing |
| `linker 'cc' not found` / `link.exe not found` | Install the C compiler / build tools (see Requirements) |
| `ensurepip is not available` | `sudo apt install python3-venv` |
| `externally-managed-environment` | Do not install globally; use a virtualenv (sections 2 or 3) |
| `zecowallet: command not found` | Activate the virtualenv, or run `~/.zecowallet-venv/bin/zecowallet` |
| Error mentioning a required `rustc` version | `rustup update` |
| `zecowallet needs an interactive terminal` | Run it in a normal terminal, not piped or from a script |
