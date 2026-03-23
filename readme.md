# SNIFF — Pocket PCAP Capture

One tap. Walk away. Come back to PCAPs.

Built for the **Waveshare ESP32-S3-Touch-LCD-1.47** — a shirt-pocket-sized board with a 172×320 touchscreen, SD card slot, and enough horsepower to sniff the air around you and write it all to disk without a laptop in sight.

Two firmware flavors. Same workflow. Same hardware.

---

## How It Works (Both Models)

1. Flash the firmware
2. Insert an SD card
3. Power on
4. **Tap the screen once** — capture starts
5. Tap again to stop
6. Plug into USB to grab your files

That's it. No laptop required in the field. No app. No config. Tap and go.

---

## WiFi Model — `main.cpp`

**Captures 802.11 frames from the air and writes them as standard PCAP files readable in Wireshark.**

The device enters monitor (promiscuous) mode and passively captures every 802.11 frame it can hear — management, control, and data frames from every device in range. Hops between channels 1, 6, and 11 every 250ms to maximize coverage across the 2.4GHz band.

**File format:** `LINKTYPE_IEEE802_11` (linktype 105) — opens natively in Wireshark, tshark, or any tool that reads pcap.

**Files saved as:** `cap_0000.pcap`, `cap_0001.pcap`, …

**What you can do with the captures:**
- Identify devices by OUI and frame behavior
- Inspect beacon frames, probe requests/responses
- Analyze authentication and association sequences
- Feed into tools like `airodump-ng`, `tshark`, or custom scripts

**UI:** Space Invader crab sprite. White stars at standby, green idle → purple/magenta active. Title pulses **CAPTURING** during a session.

---

## BLE Model — `main_ble.cpp`

**Captures Bluetooth Low Energy advertising packets and scan responses, written as full PCAP files readable in Wireshark with complete LE Link Layer dissection.**

The device runs an active BLE scan at 100% duty cycle, capturing every advertisement it hears from every device in range. Both the advertising packet (ADV_IND, ADV_NONCONN_IND, ADV_SCAN_IND, etc.) and the scan response (SCAN_RSP) are recorded as separate frames — which is where device names, service UUIDs, and manufacturer data typically live.

**File format:** `LINKTYPE_BLUETOOTH_LE_LL_WITH_PHDR` (linktype 256) — Wireshark fully dissects the LE Link Layer PDU, all AD structures (Flags, Complete Name, Manufacturer Specific, Service UUIDs, TX Power, etc.), RSSI, and CRC validity. No plugins required.

**Files saved as:** `ble_0000.pcap`, `ble_0001.pcap`, …

**What you can do with the captures:**
- See device names, manufacturer IDs, and service UUIDs in plain text
- Track unique advertisers per session (shown live on screen as `DEV:N`)
- Identify Apple, Google, and other vendor beacons by manufacturer data
- Analyze BLE advertisement intervals and payload structures

**UI:** Space Invader squid sprite. White stars at standby, blue idle → red active. Title pulses **SCANNING** during a session.

---

## Hardware

| Component | Detail |
|-----------|--------|
| Board | Waveshare ESP32-S3-Touch-LCD-1.47 |
| Display | 172×320 ST7789, SPI |
| Touch | AXS5106L, I2C |
| Storage | MicroSD via 4-bit SDMMC |
| Flash | 16MB |
| PSRAM | 8MB OPI |

Any MicroSD card formatted FAT32 works. Captures are written sequentially and numbered automatically so you never overwrite a previous session.

---

## USB Mode — Grabbing Your PCAPs

When you're done in the field, plug the ESP32-S3 into any computer over USB. The device detects the host at boot and automatically enters **USB Mass Storage mode** — your SD card mounts on your computer like a USB thumb drive.

### Step by Step

1. **Plug in the USB cable** before powering on (or with the device already off)
2. Power on — the device detects the USB host within 500ms
3. The screen shows **USB MODE** with the SD card size and mount status
4. Your computer mounts the SD card as a removable drive
5. Copy your `.pcap` files off — drag and drop, `cp`, whatever you prefer
6. **Eject the drive safely** on your computer before unplugging
7. **Double-tap the touchscreen** to exit USB mode and restart into capture mode

> The device will not enter capture mode while USB mode is active. Double-tap is required to switch back — this prevents SD card corruption from simultaneous access.

### After You Pull the Files

Open any `.pcap` file directly in **Wireshark**. No conversion needed.

For WiFi captures (`cap_*.pcap`):
```
wireshark cap_0000.pcap
```

For BLE captures (`ble_*.pcap`):
```
wireshark ble_0000.pcap
```

Wireshark will fully dissect both formats out of the box. For BLE, filter by device address, PDU type, or AD structure type:

```
# Show only scan responses (where device names live)
btle.advertising_header.pdu_type == 0x04

# Filter by advertiser address
btle.advertising_address == ff:ff:ff:ff:ff:ff

# Show only packets with a Complete Local Name AD structure
btcommon.eir_ad.entry.type == 0x09
```

---

## Build & Flash

Requires [PlatformIO](https://platformio.org/).

```bash
# WiFi firmware
pio run -e ble_sniff_s3 -t upload   # swap main.cpp into src/

# BLE firmware
pio run -e ble_sniff_s3 -t upload   # uses main_ble.cpp in src/

# Serial monitor
pio device monitor
```

The serial monitor prints live status — packet counts, drop counts, unique device counts, and any boot errors — useful during development or if something looks off.

---

## Project Layout

```
.
├── README.md
├── platformio.ini
├── partitions_16mb.csv
├── src/
│   ├── main.cpp          # WiFi sniffer firmware
│   └── main_ble.cpp      # BLE sniffer firmware
└── lib/
    └── esp_lcd_touch_axs5106l/
        ├── esp_lcd_touch_axs5106l.h
        └── esp_lcd_touch_axs5106l.cpp
```

---

## Tips

- **Longer sessions:** Higher-capacity cards work fine. Files flush to disk every 32 packets and on stop, so an unexpected power cut won't corrupt the current file badly.
- **Crowded environments:** Drop count is shown live on the status bar. If drops are high, that's normal in very dense environments — the queue is intentionally sized to keep up with typical advertising rates.
- **Switching firmware:** You only need to reflash. SD card files from both models coexist fine since filenames don't overlap (`cap_*` vs `ble_*`).
- **File numbering:** Starts from `0000` and increments. If you fill the card, clear old files in USB mode and numbering continues from where it left off.
