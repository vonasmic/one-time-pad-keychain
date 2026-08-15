package fel.cvut.terminalapp;

import com.fazecast.jSerialComm.SerialPort;
import com.fazecast.jSerialComm.SerialPortInvalidPortException;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.Socket;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.concurrent.atomic.AtomicBoolean;

/**
 * Transparent USB-serial ↔ TCP byte pump (same role as
 * {@code socat /dev/ttyACM0,b115200,raw,echo=0 TCP:host:port}).
 * No SAE READY / TLS_START handling — every byte is forwarded both ways.
 */
final class UsbTcpBridge {

    static final String DEFAULT_PORT = "/dev/ttyACM0";

    private static final long POLL_INTERVAL_MS = 500;
    private static final int SERIAL_READ_TIMEOUT_MS = 50;

    private final String serialPortName;
    private final int baudRate;
    private final String nodeHost;
    private final int nodePort;

    UsbTcpBridge(String serialPortName, int baudRate, String nodeHost, int nodePort) {
        this.serialPortName = serialPortName;
        this.baudRate = baudRate;
        this.nodeHost = nodeHost;
        this.nodePort = nodePort;
    }

    void run() {
        while (!Thread.currentThread().isInterrupted()) {
            SerialPort serial;
            try {
                serial = openWhenPresent();
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                return;
            }
            System.out.println("[usb-bridge] Opened " + serialPortName + " @ " + baudRate
                    + " → " + nodeHost + ":" + nodePort);
            try {
                bridgeOnce(serial);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                return;
            } finally {
                serial.closePort();
            }
            System.out.println("[usb-bridge] Session closed; waiting for " + serialPortName);
        }
    }

    private SerialPort openWhenPresent() throws InterruptedException {
        boolean waitingLogged = false;
        while (!Thread.currentThread().isInterrupted()) {
            if (!Files.exists(Path.of(serialPortName))) {
                if (!waitingLogged) {
                    System.out.println("[usb-bridge] Waiting for " + serialPortName + " ...");
                    waitingLogged = true;
                }
                Thread.sleep(POLL_INTERVAL_MS);
                continue;
            }
            try {
                SerialPort serial = SerialPort.getCommPort(serialPortName);
                serial.setComPortParameters(baudRate, 8, SerialPort.ONE_STOP_BIT, SerialPort.NO_PARITY);
                serial.setComPortTimeouts(
                        SerialPort.TIMEOUT_READ_SEMI_BLOCKING, SERIAL_READ_TIMEOUT_MS, 0);
                if (!serial.openPort()) {
                    Thread.sleep(POLL_INTERVAL_MS);
                    continue;
                }
                serial.setDTR();
                serial.setRTS();
                return serial;
            } catch (SerialPortInvalidPortException e) {
                if (!waitingLogged) {
                    System.out.println("[usb-bridge] Waiting for " + serialPortName + " ...");
                    waitingLogged = true;
                }
                Thread.sleep(POLL_INTERVAL_MS);
            }
        }
        throw new InterruptedException("Interrupted while waiting for " + serialPortName);
    }

    private void bridgeOnce(SerialPort serial) throws InterruptedException {
        while (serial.isOpen() && !Thread.currentThread().isInterrupted()) {
            Socket socket;
            try {
                socket = new Socket(nodeHost, nodePort);
                socket.setTcpNoDelay(true);
            } catch (IOException e) {
                System.err.println("[usb-bridge] TCP connect failed: " + e.getMessage());
                Thread.sleep(POLL_INTERVAL_MS);
                continue;
            }
            System.out.println("[usb-bridge] TCP connected — opaque bidirectional pump");
            try (socket) {
                pumpBothWays(serial, socket);
            } catch (IOException e) {
                System.err.println("[usb-bridge] TCP ended: " + e.getMessage());
            }
            if (!serial.isOpen()) {
                return;
            }
            Thread.sleep(POLL_INTERVAL_MS);
        }
    }

    private static void pumpBothWays(SerialPort serial, Socket socket) throws InterruptedException {
        AtomicBoolean stop = new AtomicBoolean(false);
        InputStream serialIn = serial.getInputStream();
        OutputStream serialOut = serial.getOutputStream();

        Thread toNode = new Thread(() -> {
            byte[] buf = new byte[8192];
            try {
                OutputStream out = socket.getOutputStream();
                while (!stop.get() && serial.isOpen() && !socket.isClosed()) {
                    int n;
                    try {
                        n = serialIn.read(buf);
                    } catch (IOException e) {
                        n = 0;
                    }
                    if (n < 0) {
                        break;
                    }
                    if (n > 0) {
                        out.write(buf, 0, n);
                        out.flush();
                    }
                }
            } catch (IOException e) {
                System.out.println("[usb-bridge] serial→node: " + e.getMessage());
            } finally {
                stop.set(true);
                try {
                    socket.close();
                } catch (IOException ignored) {
                }
            }
        }, "usb-bridge-serial-to-node");

        Thread toSerial = new Thread(() -> {
            byte[] buf = new byte[8192];
            try {
                InputStream in = socket.getInputStream();
                while (!stop.get() && serial.isOpen() && !socket.isClosed()) {
                    int n = in.read(buf);
                    if (n < 0) {
                        break;
                    }
                    if (n > 0) {
                        serialOut.write(buf, 0, n);
                        serialOut.flush();
                    }
                }
            } catch (IOException e) {
                System.out.println("[usb-bridge] node→serial: " + e.getMessage());
            } finally {
                stop.set(true);
                try {
                    socket.close();
                } catch (IOException ignored) {
                }
            }
        }, "usb-bridge-node-to-serial");

        toNode.setDaemon(true);
        toSerial.setDaemon(true);
        toNode.start();
        toSerial.start();
        toNode.join();
        toSerial.join();
    }
}
