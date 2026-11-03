# usb-cdc

Shared USB CDC library (`fel.cvut.usb`). Both [SaeNode](../sae-node/README.md)
and [UserApp](../user-app/README.md) open the keychain serial port themselves.
The port is opened in-process; no separate terminal process is involved.

Maven module: `usb-cdc`. Sources live in this tree under `fel/cvut/usb`.

## What it does

- Opens CDC ACM (`USB_SERIAL_PORT`, default `auto` scans for USB `0483:5710`)
- Frames type `0x00` console commands and type `0x01` Secure payloads
- `SeUsbLink.armTls` then `SeUsbTls.run` wraps the stream as a TLS **server**
  (`SoftwareTls.wrapServer`): the device is the TLS client

SaeNode arms `PROVISION`. UserApp arms `ENCRYPT` / `DECRYPT` / `MANAGE`.

## Source layout

```text
modules/usb-cdc/
  README.md
  src/main/java/fel/cvut/usb/   SeUsbLink, SeUsbTls, UsbFrame, CdcPortScan, StreamSocket, TimedInputStream
  src/test/java/fel/cvut/usb/   CdcPortScanTest, TimedInputStreamTest, UsbFrameTest
```
