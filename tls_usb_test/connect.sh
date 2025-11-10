#!/bin/bash
# Simple script to connect device to TLS server using socat bridge

USB_PORT="${1:-/dev/ttyACM0}"
TCP_HOST="${2:-localhost}"
TCP_PORT="${3:-11111}"

echo "USB-to-TCP Bridge for TLS Testing"
echo "=================================="
echo "USB Port: $USB_PORT"
echo "TCP Server: $TCP_HOST:$TCP_PORT"
echo ""
echo "This will bridge USB serial to TCP so your device can connect to the TLS server."
echo "Make sure:"
echo "  1. The TLS server is running: ./tls_server"
echo "  2. Your device is connected to $USB_PORT"
echo "  3. You have permissions to access $USB_PORT (may need sudo)"
echo ""
read -p "Continue? (Y/n): " -n 1 -r
echo
if [[ $REPLY =~ ^[Nn]$ ]]; then
    exit 0
fi

# Check if socat is installed
if ! command -v socat &> /dev/null; then
    echo "Error: socat is not installed"
    echo "Install it with: sudo apt-get install socat"
    exit 1
fi

# Check if USB port exists
if [ ! -e "$USB_PORT" ]; then
    echo "Error: USB port $USB_PORT does not exist"
    echo "Make sure your device is connected"
    exit 1
fi

echo ""
echo "Starting bridge..."
echo "Press Ctrl+C to stop"
echo ""

# Use socat to bridge USB serial to TCP
# - raw,echo=0: raw mode, no echo
# - TCP:...: connect to TCP server
socat "$USB_PORT,raw,echo=0,b115200" "TCP:$TCP_HOST:$TCP_PORT"


