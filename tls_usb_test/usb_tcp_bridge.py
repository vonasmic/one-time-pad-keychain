import sys
import socket
import serial
import select
import os

# --- Configuration ---
DEFAULT_USB_PORT = '/dev/ttyACM0' 
DEFAULT_HOST = '127.0.0.1'
DEFAULT_TCP_PORT = 11111

def main():
    usb_port = sys.argv[1] if len(sys.argv) > 1 else DEFAULT_USB_PORT
    host = sys.argv[2] if len(sys.argv) > 2 else DEFAULT_HOST
    port = int(sys.argv[3]) if len(sys.argv) > 3 else DEFAULT_TCP_PORT

    try:
        # 1. Open Serial Port
        # timeout=0 is critical for non-blocking behavior
        ser = serial.Serial(usb_port, 115200, timeout=0, write_timeout=0)
        print(f"[+] Opened serial port {usb_port}")

        # 2. Connect to TLS Server
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.connect((host, port))
        sock.setblocking(False)
        print(f"[+] Connected to TLS Server at {host}:{port}")

    except Exception as e:
        print(f"[-] Setup failed: {e}")
        return

    print("="*60)
    print(f"[*] Bridge Ready. Type commands below (e.g., 'TLS test').")
    print(f"[*] ALL USB output will be printed to this screen.")
    print("="*60)

    inputs = [ser, sock, sys.stdin]
    tls_active = False
    
    try:
        while True:
            readable, _, exceptional = select.select(inputs, [], inputs, 0.1)

            for s in readable:
                # -----------------------------------------------------------
                # 1. Keyboard Input -> USB Device
                # -----------------------------------------------------------
                if s is sys.stdin:
                    line = sys.stdin.readline()
                    if line:
                        # Send exactly what was typed
                        ser.write(line.encode('utf-8'))
                        # print(f"    >>> Sent: {line.strip()}") 

                # -----------------------------------------------------------
                # 2. USB Device -> TCP Server (AND Screen)
                # -----------------------------------------------------------
                elif s is ser:
                    try:
                        data = ser.read(4096)
                        if data:
                            # A. ALWAYS print to screen (Safe decoding)
                            # We use 'replace' so binary bytes become '?' instead of crashing
                            text_view = data.decode('utf-8', errors='replace')
                            sys.stdout.flush()
                            if "DEBUG:" in data.decode("utf-8", "ignore"):
                                print(data)
                                print("works")
                                continue

                            # B. Forwarding Logic
                            if tls_active:
                                # Forward everything once TLS has started
                                sock.sendall(data)
                            else:
                                # Check for TLS ClientHello (0x16) to engage bridge
                                if b'\x16' in data:
                                    print(f"\n[+] TLS Handshake detected! Forwarding to Server...")
                                    tls_active = True
                                    
                                    # Forward only the binary part (skip echoed text)
                                    start_index = data.find(b'\x16')
                                    sock.sendall(data[start_index:])
                    except Exception as e:
                        print(f"\n[!] Error reading Serial: {e}")
                        return

                # -----------------------------------------------------------
                # 3. TCP Server -> USB Device
                # -----------------------------------------------------------
                elif s is sock:
                    try:
                        data = sock.recv(4096)
                        if not data:
                            print("\n[-] TLS Server closed connection")
                            return
                        
                        # Forward to USB
                        ser.write(data)
                        print(f"[< TCP Data: {len(data)} bytes forwarded to USB >]")
                    except Exception as e:
                        print(f"\n[!] Error reading Socket: {e}")
                        return

            if exceptional:
                print("\n[-] Exception in connection")
                break

    except KeyboardInterrupt:
        print("\n[*] Stopping bridge...")
    finally:
        ser.close()
        sock.close()

if __name__ == "__main__":
    main()