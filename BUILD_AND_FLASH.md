# Building and Flashing Instructions

## Building the Firmware with SPHINCS+

### Build with liboqs static library

```bash
cd app
make clean          # optional; only needed when you want a full rebuild
make                # automatically builds liboqs (minimal SPHINCS-only)
```

- The firmware build now drives liboqs directly. On the first run it configures
  liboqs via CMake, enables only `SIG_sphincs_sha2_128f_simple`, and reuses the
  cached build on subsequent runs for faster iteration.
- Artifacts are written to `build/app.elf`, `build/app.hex`, and `build/app.bin`.

Need to force liboqs to rebuild (for example, after pulling upstream changes)?

```bash
make LIBOQS_REBUILD=1
```

This wipes `../liboqs/build/` before re-configuring and compiling the minimal
library.

### Verify build size

After building, check the size:
```bash
arm-none-eabi-size build/app.elf
```

SPHINCS+ is large; expect increased flash/RAM usage.

## Flashing the Firmware

You have two options:

### Option 1: Using st-flash (recommended)

1. Connect the STM32 board via SWD (ST-Link or compatible)
2. Put the board in programming mode if required
3. Flash:
   ```bash
   cd app
   make flash
   ```
   This runs: `st-flash --format ihex --reset write build/app.hex`

### Option 2: Using DFU mode (alternative)

1. Use the provided flash script:
   ```bash
   ./flash_tool.sh
   ```
2. Follow the prompts:
   - Connect the board while pressing the button to enter DFU mode
   - Release button when instructed
   - The script will flash and test automatically

Or manually:
```bash
# Enter DFU mode (press button while connecting)
dfu-util -a 0 -s 0x08000000:leave -D app/build/app.bin
```

## Connecting and Testing

### Find the USB CDC device

After flashing, the device appears as a USB CDC/ACM serial port:
- Linux: `/dev/ttyACM0` (or `/dev/ttyACM1`, etc.)
- Windows: `COMx` (check Device Manager)
- macOS: `/dev/cu.usbmodem*` or `/dev/tty.usbmodem*`

### Connect via serial terminal

**Linux/macOS:**
```bash
# Using minicom
minicom -D /dev/ttyACM0 -b 115200

# Using screen
screen /dev/ttyACM0 115200

# Using picocom
picocom /dev/ttyACM0 -b 115200
```

**Windows:**
- Use PuTTY, Tera Term, or similar
- Set baud rate to 115200
- Select the appropriate COM port

### Testing the SPHINCS Command

Once connected, you should see:
```
APP START
# BUILD DATE: ...
# RESET TYPE: ...
```

**Example usage:**

1. **Sign a message:**
   ```
   SPHINCS Hello World
   ```
   
   Expected output:
   ```
   SPHINCS: <hex_signature>
   TIME_US: <microseconds>
   OK
   ```

2. **Get help:**
   ```
   HELP
   ```
   
   Should show SPHINCS in the command list.

3. **Other commands still work:**
   ```
   VER
   ID
   SN
   ```

### Troubleshooting

**"SPHINCS not available" error:**
- Make sure liboqs is built and linked correctly
- Check that the build completed successfully
- Verify with `arm-none-eabi-nm build/app.elf | grep -i sphincs`

**Device not appearing:**
- Check USB connection
- Try resetting the board
- Check `dmesg` (Linux) or Device Manager (Windows) for USB device detection

**Serial communication issues:**
- Verify baud rate is 115200
- Try disconnecting/reconnecting USB
- Check permissions: `sudo chmod 666 /dev/ttyACM0` (Linux)

**WSL (Windows Subsystem for Linux) issues:**
- WSL doesn't automatically forward USB devices. You need to use `usbipd`:
  1. Install `usbipd-win` on Windows: `winget install --id=usbipd -e`
  2. In Windows PowerShell (as Administrator), list devices: `usbipd list`
  3. Attach the STM32 device to WSL: `usbipd bind --busid <BUSID>` then `usbipd attach --wsl --busid <BUSID>`
  4. In WSL, verify: `lsusb` should show the device
  5. The device should appear as `/dev/ttyACM0` (may need `sudo chmod 666 /dev/ttyACM0`)
- Alternatively, use a Windows-native serial terminal (PuTTY, Tera Term) instead of WSL

**Build errors:**
- Ensure you're in the `app/` directory
- Verify liboqs sources exist at `../liboqs/src/...`
- Check that `arm-none-eabi-gcc` is in PATH

## Expected SPHINCS Output Format

```
SPHINCS: <signature_hex>
TIME_US: <time_in_microseconds>
OK
```

The signature is hex-encoded and will be ~17088 bytes (34176 hex characters) for SPHINCS+-SHA2-128f-simple.

Time is measured only for the signing operation (keypair generation happens once on first use).

