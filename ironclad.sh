#!/bin/bash
TOOL_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PYTHON_CORE="${TOOL_DIR}/ironclad_tool/ironclad.py"

echo "IRONCLAD Security Tool - By Syed Sameer ul Hassan"

if [[ $EUID -ne 0 ]]; then
   if [[ "$1" != "--help" ]]; then
      echo "Error: Must run as root (sudo)."
      exit 1
   fi
fi

if [ ! -f "$PYTHON_CORE" ]; then
    echo "Error: Core engine missing."
    exit 1
fi

python3 "$PYTHON_CORE" "$@"
