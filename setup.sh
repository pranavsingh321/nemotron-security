#!/bin/bash
set -euo pipefail

# Setup virtual environment for nemotron-security
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
VENV_DIR="$SCRIPT_DIR/.venv"

if [[ -d "$VENV_DIR" ]]; then
  echo "Virtual environment already exists at $VENV_DIR"
else
  echo "Creating virtual environment..."
  python3 -m venv "$VENV_DIR"
fi

source "$VENV_DIR/bin/activate"
pip install --upgrade pip -q
pip install openai -q

echo "Virtual environment ready: $VENV_DIR"
echo "Activate with: source $VENV_DIR/bin/activate"
