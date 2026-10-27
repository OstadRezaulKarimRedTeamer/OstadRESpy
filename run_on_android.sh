#!/data/data/com.termux/files/usr/bin/bash
# ===============================================================================
#                🛡️ OstadRESpy - Android Mobile Runner (Termux Engine)
#                   Created by: Ostad Rezaul Karim (Director)
#                            Ostad Red Team Forge
#                       Email: ostadrezaulkarimofficial@gmail.com
# ===============================================================================

echo "==============================================================================="
echo "       🛡️ OstadRESpy - Android Phone Real-Time Analyzer (Termux)"
echo "            Author: Ostad Rezaul Karim | Ostad Red Team Forge"
echo "==============================================================================="
echo ""

# Check Termux environment
if [ -d "/data/data/com.termux" ]; then
    echo "[*] Detected Android Termux Environment!"
    
    # Check Python
    if ! command -v python &> /dev/null; then
        echo "[*] Installing Python on Termux..."
        pkg update -y && pkg install python clang -y
    fi
    
    # Request Storage permission if not granted
    if [ ! -d "/sdcard" ]; then
        echo "[*] Requesting Android storage permission..."
        termux-setup-storage
    fi
else
    echo "[*] Running on generic Linux/Android shell..."
fi

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Install cryptography if not present
python -c "import cryptography" >/dev/null 2>&1 || {
    echo "[*] Installing required cryptography library..."
    pip install cryptography --quiet
}

TARGET="${1:-$SCRIPT_DIR/base.apk}"

if [ ! -f "$TARGET" ]; then
    echo "[-] File not found: $TARGET"
    echo "Usage on Android: bash run_on_android.sh /sdcard/Download/your_file.apk"
    exit 1
fi

echo "[*] Scanning & Analyzing: $TARGET"
echo ""
python "$SCRIPT_DIR/ostadrespy.py" "$TARGET"

echo ""
echo "==============================================================================="
echo "  [+] Scan Completed! View your audit report in OstadRESpy_AUDIT_REPORT.md"
echo "==============================================================================="
