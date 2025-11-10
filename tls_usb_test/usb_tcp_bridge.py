#!/usr/bin/env python3
"""
USB-to-TCP Bridge for TLS Testing

This script bridges USB serial communication to TCP, allowing the STM32U5
device (which uses USB for TLS I/O) to connect to the TCP-based TLS server.

The bridge handles bidirectional communication:
- USB -> TCP: Forwards TLS handshake data from device to server
- TCP -> USB: Forwards TLS handshake data from server to device
- User input: Allows typing commands (like "TLS") to send to device

Usage:
    python3 usb_tcp_bridge.py <usb_port> <tcp_host> <tcp_port>

Example:
    python3 usb_tcp_bridge.py /dev/ttyACM0 localhost 11111

Note: This replaces picocom - you can type commands directly in this script.
"""

import sys
import socket
import serial
import select
import argparse
import time

def bridge_usb_to_tcp(usb_port, tcp_host, tcp_port, baudrate=115200):
    """Bridge USB serial port to TCP socket with user input support"""
    
    print(f"USB-to-TCP Bridge for TLS Testing")
    print(f"==================================")
    print(f"USB Port: {usb_port}")
    print(f"TCP Target: {tcp_host}:{tcp_port}")
    print(f"Baudrate: {baudrate}")
    print()
    
    # Open USB serial port
    try:
        ser = serial.Serial(usb_port, baudrate, timeout=0.1)
        print(f"✓ Connected to USB device: {usb_port}")
    except serial.SerialException as e:
        print(f"✗ Error opening USB port {usb_port}: {e}")
        print(f"  Make sure the device is connected and you have permissions")
        return 1
    
    # Connect to TCP server
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.connect((tcp_host, tcp_port))
        sock.setblocking(False)
        print(f"✓ Connected to TCP server: {tcp_host}:{tcp_port}")
    except socket.error as e:
        print(f"✗ Error connecting to TCP server: {e}")
        print(f"  Make sure the TLS server is running on {tcp_host}:{tcp_port}")
        ser.close()
        return 1
    
    print()
    print("Bridge active!")
    print("You can now type commands (like 'TLS') to send to the device.")
    print("TLS handshake data will be automatically forwarded to/from the server.")
    print("Press Ctrl+C to stop")
    print()
    print("> ", end="", flush=True)
    
    try:
        while True:
            # Check USB -> TCP (device to server)
            if ser.in_waiting > 0:
                data = ser.read(ser.in_waiting)

                # Detect if this looks like TLS data (starts with 0x16 = Handshake, 0x17 = Application Data, etc.)
                record_types = {0x14: "ChangeCipherSpec", 0x15: "Alert", 0x16: "Handshake",
                                0x17: "Application", 0x18: "Heartbeat"}
                is_tls_record = len(data) >= 5 and data[0] in record_types
                has_control_bytes = any((b < 32 and b not in [9, 10, 13]) or b >= 0x80 for b in data)
                should_forward = is_tls_record or has_control_bytes

                # Verbose logging
                if is_tls_record:
                    version = f"{data[1]:02x}{data[2]:02x}"
                    length = (data[3] << 8) | data[4]
                    tls_info = f" [TLS {record_types[data[0]]} v{version} len={length}]"
                else:
                    tls_info = ""

                if should_forward:
                    try:
                        sock.sendall(data)
                    except socket.error:
                        print("\n✗ TCP connection closed")
                        break

                # Decide how to display the data locally
                if has_control_bytes or is_tls_record:
                    hex_dump = data[:64].hex()
                    if len(data) > 64:
                        hex_dump += "..."
                    sys.stdout.write(
                        f"\n[USB->TCP] {len(data)} bytes (binary){tls_info} hex={hex_dump}\n> "
                    )
                else:
                    # This is printable ASCII, likely CLI output – keep it local and do NOT forward
                    if not should_forward:
                        text = data.decode('utf-8', errors='ignore')
                        sys.stdout.write(f"\n{text}")
                        if not text.endswith('\n'):
                            sys.stdout.write("\n")
                        sys.stdout.write("> ")
                    else:
                        # Forwarded ASCII (e.g., application data) – still show it
                        text = data.decode('utf-8', errors='ignore')
                        sys.stdout.write(
                            f"\n[USB->TCP] {len(data)} bytes (text){tls_info}\n{text}\n> "
                        )
                sys.stdout.flush()
            
            # Check TCP -> USB (server to device)
            try:
                ready = select.select([sock], [], [], 0.1)
                if ready[0]:
                    data = sock.recv(4096)
                    if len(data) == 0:
                        print("\n✗ TCP connection closed")
                        break
                    ser.write(data)
                    # Detect TLS data from server
                    is_tls = len(data) > 0 and (data[0] in [0x14, 0x15, 0x16, 0x17, 0x18])
                    tls_info = ""
                    if is_tls and len(data) >= 5:
                        record_type = data[0]
                        version = f"{data[1]:02x}{data[2]:02x}"
                        length = (data[3] << 8) | data[4]
                        type_names = {0x14: "ChangeCipherSpec", 0x15: "Alert",
                                      0x16: "Handshake", 0x17: "Application",
                                      0x18: "Heartbeat"}
                        tls_info = f" [TLS {type_names.get(record_type, 'Unknown')} v{version} len={length}]"
                    if is_tls:
                        hex_dump = data[:64].hex()
                        if len(data) > 64:
                            hex_dump += "..."
                        sys.stdout.write(
                            f"\n[TCP->USB] {len(data)} bytes{tls_info} hex={hex_dump}\n> "
                        )
                    else:
                        sys.stdout.write(f"\n[TCP->USB] {len(data)} bytes{tls_info}\n> ")
                    sys.stdout.flush()
            except socket.error:
                print("\n✗ TCP connection error")
                break
            
            # Check stdin for user input (non-blocking)
            ready = select.select([sys.stdin], [], [], 0.1)
            if ready[0]:
                line = sys.stdin.readline()
                if line:
                    # Send user input to USB device
                    ser.write(line.encode('utf-8'))
                    # Echo what we're sending (except newline)
                    if line.strip():
                        sys.stdout.write(f"[SENT] {line.rstrip()}\n> ")
                    else:
                        sys.stdout.write("> ")
                    sys.stdout.flush()
            
    except KeyboardInterrupt:
        print("\n\nBridge stopped by user")
    except Exception as e:
        print(f"\n✗ Error: {e}")
        import traceback
        traceback.print_exc()
    finally:
        ser.close()
        sock.close()
        print("Bridge closed")
    
    return 0

def main():
    parser = argparse.ArgumentParser(
        description='Bridge USB serial to TCP for TLS testing',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Bridge USB device to local TLS server
  python3 usb_tcp_bridge.py /dev/ttyUSB0 localhost 11111
  
  # Bridge with custom baudrate
  python3 usb_tcp_bridge.py /dev/ttyACM0 192.168.1.100 11111 --baudrate 9600
  
  # On Windows, use COM port
  python3 usb_tcp_bridge.py COM3 localhost 11111
        """
    )
    
    parser.add_argument('usb_port', help='USB serial port (e.g., /dev/ttyUSB0 or COM3)')
    parser.add_argument('tcp_host', help='TCP server hostname or IP')
    parser.add_argument('tcp_port', type=int, help='TCP server port')
    parser.add_argument('--baudrate', type=int, default=115200,
                       help='USB serial baudrate (default: 115200)')
    
    args = parser.parse_args()
    
    return bridge_usb_to_tcp(args.usb_port, args.tcp_host, args.tcp_port, args.baudrate)

if __name__ == '__main__':
    sys.exit(main())

