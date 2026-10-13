# usb-cdc

Shared USB CDC library (`fel.cvut.usb`). Both [SaeNode](../SaeNode/README.md)
and [UserApp](../UserApp/README.md) open the keychain serial port themselves.
There is no USB-to-TCP relay and no standalone terminal process.

Maven module: `usb-cdc`. Sources live in this tree under `fel/cvut/usb`.

## What it does

- Opens CDC ACM (`USB_SERIAL_PORT`, default `auto` scans for USB `0483:5710`)
- Frames type `0x00` console commands and type `0x01` Secure payloads
- `SeUsbLink.armTls` then `SeUsbTls.run` wraps the stream as a TLS **server**
  (`SoftwareTls.wrapServer`): the device is the TLS client

SaeNode arms `PROVISION`. UserApp arms `ENCRYPT` / `DECRYPT` / `MANAGE`.

## Source layout

```text
src/TerminalBridge/
  README.md
  main/java/fel/cvut/usb/   SeUsbLink, SeUsbTls, UsbFrame, CdcPortScan
  test/java/fel/cvut/usb/   CdcPortScanTest
```
