#!/bin/bash
DIR="$( cd "$( dirname "$0" )" && pwd )"
cd "$DIR"
echo "=============================================================================="
echo "  🛡️ OstadRESpy - Universal Cyber Defense Suite [macOS Double-Click Runner]"
echo "  Created by: Ostad Rezaul Karim (Director, Ostad Red Team Forge)"
echo "=============================================================================="
python3 gui_server.py
