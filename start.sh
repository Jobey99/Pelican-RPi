#!/bin/bash

# Ensure script is run with sudo
if [ "$EUID" -ne 0 ]; then
  echo "⚠️ Warning: This software requires root privileges to sniff packets and configure interfaces."
  echo "Please run as root: sudo ./start.sh"
  exit 1
fi

echo "🚀 Starting Pelican AV/IT Network Powerhouse..."

# Change to backend directory
cd "$(dirname "$0")/backend" || exit 1

# Check if python3 is installed
if ! command -v python3 &> /dev/null; then
    echo "❌ Error: Python 3 is not installed. Please run: apt-get install python3 python3-pip"
    exit 1
fi

# Check if dependencies are installed, if not install them
echo "📦 Verifying python dependencies..."
python3 -c "import fastapi, uvicorn, serial, scapy, psutil" &> /dev/null
if [ $? -ne 0 ]; then
    echo "💾 Dependencies missing. Installing from requirements.txt..."
    # Install dependencies globally or in environment
    pip3 install -r requirements.txt --break-system-packages || pip3 install -r requirements.txt
fi

# Set raw socket capabilities for python3 if not running as root (though sudo is safer)
# setcap cap_net_raw,cap_net_admin=eip $(readlink -f $(which python3))

echo "🖥️ Starting FastAPI Server on port 8000..."
echo "🔗 Access the dashboard via your browser at http://<pi-ip-address>:8000"
echo "--------------------------------------------------------"

python3 main.py
