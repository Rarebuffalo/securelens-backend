#!/usr/bin/env bash
# install.sh — Install SecureLens AI CLI into the project venv
set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BACKEND_ROOT="$(dirname "$SCRIPT_DIR")"

echo "🔍 SecureLens AI CLI — Installer"
echo "================================="

# Detect venv
VENV_PIP=""
if [ -f "$BACKEND_ROOT/venv/bin/pip" ]; then
    VENV_PIP="$BACKEND_ROOT/venv/bin/pip"
    echo "  Using backend venv: $BACKEND_ROOT/venv"
elif command -v pip3 &>/dev/null; then
    VENV_PIP="pip3"
    echo "  Using system pip3"
else
    VENV_PIP="pip"
    echo "  Using system pip"
fi

echo ""
echo "  Installing dependencies..."
$VENV_PIP install click rich litellm httpx pyyaml pathspec questionary --quiet

echo "  Installing securelens-ai CLI..."
$VENV_PIP install -e "$SCRIPT_DIR" --no-build-isolation --quiet

echo ""
echo "✓ Done! Run: securelens --help"
echo ""
echo "  Or if using venv directly:"
echo "  source $BACKEND_ROOT/venv/bin/activate"
echo "  securelens configure"
