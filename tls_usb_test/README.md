# TLS Server for STM32U5 Device Testing

This directory contains a simplified TLS 1.3 server that supports ML-KEM-768 for testing the TLS handshake with your STM32U5 device.

## Overview

The STM32U5 device acts as a TLS client and uses USB for I/O, while this server uses TCP sockets. To connect them, you have two options:

1. **Use a USB-to-TCP bridge** (recommended for testing)
2. **Modify the device code** to use TCP sockets instead of USB

## Building the Server

```bash
cd tls_usb_test
make
```

This will create the `tls_server` executable.

## Generating Server Certificate

Generate the server certificate and key:

```bash
cd tls_usb_test
chmod +x setup_certs.sh
./setup_certs.sh
```

Or manually:
```bash
mkdir -p certs
openssl req -x509 -newkey rsa:2048 -keyout certs/server-key.pem \
  -out certs/server-cert.pem -days 365 -nodes
```

## Running the Server

```bash
./tls_server [port] [cert_file] [key_file]
```

Default values:
- Port: 11111
- Certificate: `certs/server-cert.pem`
- Private Key: `certs/server-key.pem`

Example:
```bash
./tls_server 11111 certs/server-cert.pem certs/server-key.pem
```

## Testing the Handshake

### Quick Start

**Step 1: Generate certificates (first time only)**
```bash
cd tls_usb_test
chmod +x setup_certs.sh
./setup_certs.sh
```

**Step 2: Start the TLS server**
```bash
# Terminal 1
cd tls_usb_test
./tls_server
```

**Step 3: Start the USB-to-TCP bridge and connect to device**
```bash
# Terminal 2 - This replaces picocom and bridges USB to TCP
cd tls_usb_test
python3 usb_tcp_bridge.py /dev/ttyACM0 localhost 11111

# In the bridge terminal, type commands like:
TLS
```

**How it works:**
- The Python bridge connects to your device via USB (`/dev/ttyACM0`)
- It also connects to the TLS server via TCP (`localhost:11111`)
- When you type "TLS", it sends the command to the device
- The device starts a TLS handshake and sends data over USB
- The bridge automatically forwards TLS data between USB and TCP
- You see device responses in the bridge terminal

### Connection Methods

#### Method 1: Direct USB-to-TCP Bridge (Recommended)

Since the device sends TLS data over USB but the server expects TCP, use `socat` to bridge them:

**Terminal 1: Start TLS server**
```bash
./tls_server
```

**Terminal 2: Bridge USB to TCP (use the connect script)**
```bash
chmod +x connect.sh
./connect.sh /dev/ttyACM0 localhost 11111
```

**Terminal 3: Connect to device with picocom**
```bash
# Note: You may need to use a different USB port or connect before starting the bridge
picocom /dev/ttyACM0 -b 115200
# Then type: TLS
```

**Note:** If `socat` is not available, install it:
```bash
sudo apt-get install socat
```

#### Method 2: Python Bridge (Recommended - Replaces picocom)

The Python bridge script acts as both a bridge AND a terminal, so you don't need picocom:

```bash
# Terminal 1: Start TLS server
./tls_server

# Terminal 2: Start Python bridge (this replaces picocom)
python3 usb_tcp_bridge.py /dev/ttyACM0 localhost 11111

# In the Python bridge terminal, you can now:
# - Type commands like "TLS" to send to the device
# - See device responses
# - TLS handshake data is automatically forwarded to/from the server
```

**Note:** You need the `pyserial` package:
```bash
pip3 install pyserial
```

### Understanding the Flow

When you type `TLS` in picocom:

1. **Command Phase**: The "TLS" command is sent over USB serial to the device
2. **Device Processing**: The device receives the command and starts TLS handshake
3. **TLS Handshake**: The device sends TLS handshake data over USB (via `usb_cdc_tx`)
4. **Bridge**: The USB-to-TCP bridge forwards this data to the TCP server
5. **Server Response**: The server responds with TLS handshake data
6. **Bridge Back**: The bridge forwards server response back to USB serial
7. **Device Receives**: The device receives TLS data via `tls_pqc_usb_rx_handler`

**Important**: The bridge must be running **before** you execute the TLS command, and it must handle bidirectional communication.

## Expected Output

**Server side:**
```
TLS 1.3 Server with ML-KEM-768 support
=======================================
Port: 11111
Certificate: certs/server-cert.pem
Private Key: certs/server-key.pem

ML-KEM-768 key share enabled
Server listening on port 11111...
Waiting for client connection...
(Connect your device and execute: TLS)

Client connected from 127.0.0.1:xxxxx
Performing TLS handshake...
✓ TLS handshake successful!
  Version: TLSv1.3
  Cipher: TLS_AES_256_GCM_SHA384
Connection closed.
```

**Device side:**
```
TLS: Initializing...
TLS: Starting handshake...
TLS: Handshake complete!
TLS: Version: TLSv1.3, Cipher: TLS_AES_256_GCM_SHA384
TLS: HANDSHAKE_OK
OK
```

## Troubleshooting

1. **"ML-KEM-768 not compiled in wolfSSL"**
   - Rebuild wolfSSL with ML-KEM-768 support enabled
   - Check `user_settings.h` for PQC configuration

2. **"Connection refused"**
   - Ensure the server is running
   - Check firewall settings
   - Verify the port number matches

3. **"Handshake failed"**
   - Check that both client and server support ML-KEM-768
   - Verify TLS 1.3 is enabled
   - Check certificate validity

4. **USB connection issues**
   - Verify USB device is connected and recognized
   - Check USB serial port permissions
   - Ensure correct baud rate and settings

## Notes

- The server supports only one connection at a time (simplified for testing)
- The server will continue listening for new connections after each handshake
- ML-KEM-768 must be compiled into both the server and client wolfSSL libraries

