#!/bin/bash
set -euo pipefail

# Setup virtual environment for nemotron-security using uv
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
VENV_DIR="$SCRIPT_DIR/.venv"

if ! command -v uv &>/dev/null; then
  echo "ERROR: uv not installed. Run: curl -LsSf https://astral.sh/uv/install.sh | sh"
  exit 1
fi

if [[ -d "$VENV_DIR" ]]; then
  echo "Virtual environment already exists at $VENV_DIR"
else
  echo "Creating virtual environment with uv..."
  uv venv "$VENV_DIR"
fi

source "$VENV_DIR/bin/activate"
uv pip install openai

echo "Virtual environment ready: $VENV_DIR"
echo "Activate with: source $VENV_DIR/bin/activate"
