#!/data/data/com.termux/files/usr/bin/bash
DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
cd "$DIR"
echo "=============================================================================="
echo "  🛡️ OstadRESpy - Universal Cyber Defense Suite [Android Termux GUI]"
echo "  Created by: Ostad Rezaul Karim (Director, Ostad Red Team Forge)"
echo "=============================================================================="
which python >/dev/null 2>&1 || { echo "[ERROR] Python required. Run: pkg install python -y"; exit 1; }
am start -a android.intent.action.VIEW -d "http://localhost:5050" 2>/dev/null || termux-open-url "http://localhost:5050" 2>/dev/null
python gui_server.py
