#!/usr/bin/env bash
# install.sh — Install SecureLens AI CLI into the project venv
# Run from the repo root: ./cli/install.sh
set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BACKEND_ROOT="$(dirname "$SCRIPT_DIR")"

echo ""
echo "  ╔══════════════════════════════════════╗"
echo "  ║    SecureLens AI CLI — Installer     ║"
echo "  ╚══════════════════════════════════════╝"
echo ""

# ── Detect pip ────────────────────────────────────────────────────────────────
VENV_PIP=""
if [ -f "$BACKEND_ROOT/venv/bin/pip" ]; then
    VENV_PIP="$BACKEND_ROOT/venv/bin/pip"
    VENV_PYTHON="$BACKEND_ROOT/venv/bin/python"
    echo "  ✓ Using backend venv: $BACKEND_ROOT/venv"
elif command -v pip3 &>/dev/null; then
    VENV_PIP="pip3"
    VENV_PYTHON="python3"
    echo "  ✓ Using system pip3"
else
    VENV_PIP="pip"
    VENV_PYTHON="python"
    echo "  ✓ Using system pip"
fi

echo ""

# ── Install build tools + CLI dependencies ────────────────────────────────────
echo "  [1/2] Installing CLI dependencies..."
$VENV_PIP install setuptools wheel \
    "click>=8.1" \
    "rich>=13.0" \
    "pyyaml>=6.0" \
    "pathspec>=0.12" \
    "questionary>=2.0" \
    "litellm>=1.0" \
    "httpx>=0.27" \
    --quiet

echo "  ✓ Dependencies installed"

# ── Install the securelens package ────────────────────────────────────────────
echo "  [2/2] Installing securelens CLI..."
$VENV_PIP install setuptools --quiet   # ensure build backend is available
$VENV_PIP install -e "$SCRIPT_DIR" --no-build-isolation --quiet
echo "  ✓ securelens command registered"

echo ""
echo "  ════════════════════════════════════════"
echo "  ✓ Installation complete!"
echo ""
echo "  Next steps:"
if [ -f "$BACKEND_ROOT/venv/bin/activate" ]; then
    echo "    source $BACKEND_ROOT/venv/bin/activate"
fi
echo "    securelens configure        # set your API key"
echo "    securelens scan .           # scan this repo"
echo "    securelens --help           # see all commands"
echo ""
