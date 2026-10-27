#!/usr/bin/env bash
DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
cd "$DIR"
echo "=============================================================================="
echo "  🛡️ OstadRESpy - Universal Cyber Defense Suite [macOS Edition]"
echo "  Created by: Ostad Rezaul Karim (Director, Ostad Red Team Forge)"
echo "=============================================================================="
python3 gui_server.py
