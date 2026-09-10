import sys
import socket
import serial
import select
import os

DEBUG_PREFIX = b"DEBUG:"
DEBUG_SUFFIX = b":DEBUG"

DEFAULT_USB_PORT = '/dev/ttyACM0'
DEFAULT_HOST = '127.0.0.1'
DEFAULT_TCP_PORT = 11111


def split_debug_and_tls(buf: bytes) -> tuple[bytes, bytes, list[bytes]]:
    """Return (kept_buf, tls_from_hello, debug_frames). Incomplete DEBUG stays in kept_buf."""
    frames: list[bytes] = []
    tls = b""
    while buf:
        buf = buf.lstrip(b"\r\n")
        if not buf:
            break
        if buf.startswith(DEBUG_PREFIX):
            closer = buf.find(DEBUG_SUFFIX, len(DEBUG_PREFIX))
            if closer < 0:
                break
            frames.append(buf[: closer + len(DEBUG_SUFFIX)])
            buf = buf[closer + len(DEBUG_SUFFIX) :]
            continue
        hello = buf.find(b"\x16")
        if hello >= 0:
            if hello > 0:
                frames.append(buf[:hello])
            tls = buf[hello:]
            buf = b""
            break
        frames.append(buf)
        buf = b""
        break
    return buf, tls, frames

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
    usb_buf = b""
    
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
                            if tls_active:
                                sock.sendall(data)
                                continue
                            usb_buf += data
                            usb_buf, tls, frames = split_debug_and_tls(usb_buf)
                            for frame in frames:
                                print(frame.decode("utf-8", errors="replace"), end="" if frame.endswith((b"\r", b"\n")) else "\n")
                            sys.stdout.flush()
                            if tls:
                                print("\n[+] TLS Handshake detected! Forwarding to Server...")
                                tls_active = True
                                sock.sendall(tls)
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