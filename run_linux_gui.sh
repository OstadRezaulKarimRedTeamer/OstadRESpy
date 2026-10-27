#!/usr/bin/env bash
DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
cd "$DIR"
echo "=============================================================================="
echo "  🛡️ OstadRESpy - Universal Cyber Defense Suite [Linux Edition]"
echo "  Created by: Ostad Rezaul Karim (Director, Ostad Red Team Forge)"
echo "=============================================================================="
which python3 >/dev/null 2>&1 || { echo "[ERROR] python3 is required. Run: sudo apt install python3"; exit 1; }
python3 gui_server.py
