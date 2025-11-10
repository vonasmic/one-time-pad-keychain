## Project overview

STM32U535 firmware providing a USB CDC-ACM (Virtual COM Port) to SPI bridge with a command interface. The STM32 is the command handler: it parses named commands and executes logic locally, optionally interacting with the target over SPI.

## Directory layout

- app/
  - `main.c`: System boot, GPIO, watchdog, timer, USB init, main loop (TTY, USB tasks, LED, watchdog).
  - `cmd.c`/`cmd.h`: Command parser and handlers (e.g., AUTO, CLKDIV, CS, GPO, HELP, ID, PWR, RESET, SN, VER).
  - `stm32u5xx_hal_conf.h`: HAL configuration.
  - `Makefile`: App build linking the SDK makefile.
- usb/
  - `usb_device.c`/`.h`: USB device init and task, PCD setup, USBX stack bring-up.
  - `ux_device_cdc_acm.c`/`.h`: CDC-ACM glue (activate/deactivate, RX/TX, poll task).
  - `ux_device_descriptors.c`/`.h`: Descriptor builder and endpoint assignment, serial number.
  - `ux_user.h`, `ux_stm32_config.h`: USBX configuration (standalone device side, CDC options).
- sdk/
  - common/: `util.c` (hex parsing, string utils), base types.
  - hal/: `tty.c` (USB+UART stream, line buffering), `led.c` (patterns), `log.c` (optional logging), `os_minimal.h` (OS-lite macros).
  - drv_u5/: STM32U5 drivers: `sys.c` (clock, CRS, HAL tick), `gpio.c`, `irq.c`, `time.c` (TIM2 ms tick), `uart.c` (LPUART1), `spi.c` (SPI1 master + DMA), `reset.c`, `wd.c` (IWDG).
  - stm32/: Vendor HAL, USBX, CMSIS, startup and linker script.
  - `sdk_stm32u535.mk`: Toolchain flags, include paths, vendor/USBX sources.
- hw/
  - `hardware.h`: Board-level includes and IRQ priorities.
  - `pcb_ts1302.h`: Pinout and macros (LED, button, UART, SPI CS, power switch, USB D+ reset).

## Build

- `app/Makefile` includes `sdk/sdk_stm32u535.mk`, using ARM GCC for Cortex-M33, linking HAL and USBX sources, startup `startup_stm32u535xx.s`, and `STM32U535xx.ld` linker script.

## Runtime flow

1. `main()` initializes system (`sys_init`, `sys_clock_config`), GPIO, watchdog, reset cause, timers, then initializes TTY (`tty_init`) and logs startup.
2. `usb_device_init()` sets up the USB device controller (PCD), configures PMA, initializes USBX core stack and CDC-ACM class, and starts USB.
3. `spi1_init()` configures SPI1 master (software CS, DMA-based TX/RX).
4. Main loop runs:
   - `tty_rx_task()` to consume USB/UART input, assemble lines, and call the parser callback.
   - `usb_device_task()` to run USBX device and CDC tasks.
   - Every 100 ms: update LED state based on USB connection, feed watchdog, and optional SPI auto-response task if enabled.

## Data paths

- Input: Host sends text over USB CDC (or UART). USBX CDC task reads into a ring buffer; `tty_rx_task()` builds full lines and invokes the command parser.
- Output: `printf` and `OS_PUTTEXT` are routed to USB CDC and mirrored to UART.

## Command handling

- Commands are parsed and handled in `app/cmd.c`. Examples:
  - `HELP`: list commands and usage.
  - `CLKDIV[=value]`: get/set SPI prescaler.
  - `CS[=0|1]`: get/set software chip-select.
  - `PWR[=0|1]`: get/set target power and level shifter enable.
  - `AUTO[=state[,get_resp[,no_resp]]]`: get/set automatic SPI response polling.
  - `ID`, `SN`, `VER`, `GPO`, `RESET`.

Note: Raw hex pass-through to SPI is disabled; STM32 is the primary command handler, deciding when/how to interact with the target device.

## Timing and interrupts

- TIM2 provides a millisecond timebase (IRQ increments `timer_ms`). USB FS IRQ is handled by HAL PCD. SPI1 DMA completion signals unblock transfers. LPUART1 IRQ handles RX/TX FIFO when enabled.

## Configuration touchpoints

- USB VID/PID, strings, and endpoints: `usb/ux_device_descriptors.h`/`.c`.
- USBX settings: `usb/ux_user.h` (standalone device-only, CDC write auto-ZLP, buffer sizes).
- Clocks and CRS (USB 48 MHz): `sdk/drv_u5/sys.c`.
- Board pins and toggles: `hw/pcb_ts1302.h`.


