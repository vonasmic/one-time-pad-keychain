# Building and flashing

Current SE firmware is the CubeIDE project in [`stm32u535-trustzone-usb/`](stm32u535-trustzone-usb/README.md) (`SE_firmware_Secure` then `SE_firmware_NonSecure`).

Full steps (option bytes, both ELFs, first Tropic bring-up):
[`stm32u535-trustzone-usb/docs/HOW_TO_RUN.md`](stm32u535-trustzone-usb/docs/HOW_TO_RUN.md).

Flash map and pins: [`docs/HARDWARE.md`](stm32u535-trustzone-usb/docs/HARDWARE.md).

Host model without a board: [`stm32u535-trustzone-usb/host/README.md`](stm32u535-trustzone-usb/host/README.md). Lab stack: [`RUN_ALL.md`](RUN_ALL.md).

Expected Cube outputs:

- `stm32u535-trustzone-usb/Secure/Debug/SE_firmware_Secure.elf`
- `stm32u535-trustzone-usb/NonSecure/Debug/SE_firmware_NonSecure.elf`

After flash, USB enumerates as CDC ACM. Open the serial port; `HELP` lists commands ([`API.md`](API.md) / [`COMMANDS.md`](stm32u535-trustzone-usb/docs/COMMANDS.md)).
