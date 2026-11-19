#!/data/data/com.termux/files/usr/bin/bash
set -euo pipefail
pkg update -y
pkg install -y python ca-certificates
python -m pip install -r requirements.txt
printf '\nInstalado. Execute: python scanner.py\n'
