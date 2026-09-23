#!/usr/bin/env bash
set -e

DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SENTINEL_ROOT="$(dirname "$DIR")"
VENV_STREAMLIT="$SENTINEL_ROOT/.venv/bin/streamlit"

export PYTHONPATH="$SENTINEL_ROOT/src:$DIR:$PYTHONPATH"

TARGET_APP="${1:-app2.py}"
TARGET_PATH="$DIR/$TARGET_APP"

echo "=========================================================="
echo "  SENTINEL Observability & Defense Console ($TARGET_APP)"
echo "  INDABAX TUNISIA 2026 · Technical Challenge"
echo "=========================================================="
echo "Starting Streamlit dashboard on http://localhost:8501"

if [ -f "$VENV_STREAMLIT" ]; then
    "$VENV_STREAMLIT" run "$TARGET_PATH" --server.port=8501 --server.address=0.0.0.0 --server.headless=true
else
    echo "Error: Virtual environment streamlit not found at $VENV_STREAMLIT"
    echo "Attempting system streamlit..."
    streamlit run "$TARGET_PATH" --server.port=8501 --server.address=0.0.0.0 --server.headless=true
fi
