#!/usr/bin/env bash
# One-shot installer for Linux / macOS / Termux.
# Builds the Rust core with maturin, installs the package into its own virtualenv
# and puts a `zecowallet` launcher on your PATH.
#
#   bash install.sh
#
# Optional: ZECOWALLET_VENV=/some/path bash install.sh   (default: ~/.zecowallet-venv)
set -euo pipefail
cd "$(dirname "$0")"

need() {
	if ! command -v "$1" >/dev/null 2>&1; then
		echo "ERROR: '$1' not found. $2" >&2
		exit 1
	fi
}

need python3 "Install Python 3.8 or newer."
need cargo   "Install Rust first: https://rustup.rs  (then open a new terminal or run: source \$HOME/.cargo/env)"

python3 - <<'PY'
import sys
if sys.version_info < (3, 8):
    sys.exit("ERROR: Python 3.8 or newer is required (found %s)" % sys.version.split()[0])
PY

VENV="${ZECOWALLET_VENV:-$HOME/.zecowallet-venv}"

echo ">> Creating virtualenv: $VENV"
if ! python3 -m venv "$VENV"; then
	echo "ERROR: could not create a virtualenv." >&2
	echo "       Debian/Ubuntu: sudo apt install python3-venv" >&2
	exit 1
fi

echo ">> Building and installing zecowallet (the first build takes a few minutes)"
"$VENV/bin/python" -m pip install --upgrade pip
"$VENV/bin/python" -m pip install --upgrade --force-reinstall .

# Put the launcher on PATH (Termux: $PREFIX/bin, otherwise ~/.local/bin)
if [ -n "${PREFIX:-}" ] && [ -d "$PREFIX/bin" ]; then
	BIN_DIR="$PREFIX/bin"
else
	BIN_DIR="$HOME/.local/bin"
fi
mkdir -p "$BIN_DIR"
ln -sf "$VENV/bin/zecowallet" "$BIN_DIR/zecowallet"

echo
echo "Done. Start the wallet with:  zecowallet"
case ":$PATH:" in
	*":$BIN_DIR:"*) ;;
	*) echo "NOTE: $BIN_DIR is not in your PATH. Add this line to ~/.bashrc or ~/.zshrc:"
	   echo "      export PATH=\"$BIN_DIR:\$PATH\"" ;;
esac
