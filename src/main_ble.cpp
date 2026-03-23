// ============================================================
// SNIFF BLE — Bluetooth LE Packet Capture
// (Waveshare ESP32-S3-Touch-LCD-1.47)
// Backend : SD PCAP capture (LINKTYPE_BLUETOOTH_LE_LL_WITH_PHDR)
//           BLE passive/active GAP scan, touch toggle
// Frontend: Space-invader themed UI — starfield + squid sprite
//           Idle = blue,  Capturing = red
// USB MSC : plug in at boot → SD card mounts as a USB drive
//
// PCAP format: each record = 10-byte RF pseudo-header
//              + 4-byte access address + PDU + 3-byte CRC(zeroed)
//              Opens in Wireshark with full LE LL dissection.
// ============================================================
#include <Arduino.h>
#include <FS.h>
#include <SD_MMC.h>
#include <Wire.h>
#include <Arduino_GFX_Library.h>
#include "esp_lcd_touch_axs5106l.h"
#include <USB.h>
#include <USBMSC.h>
#include <sdmmc_cmd.h>
#include <tusb.h>

// BLE (ESP-IDF Bluedroid stack — used directly, no Arduino BT wrapper)
#include "esp_bt.h"
#include "esp_gap_ble_api.h"
#include "esp_bt_main.h"
#include "esp_timer.h"

// ─── Display ──────────────────────────────────────────────────────────────────
#define GFX_BL 46

Arduino_DataBus *bus = new Arduino_ESP32SPI(
    45 /* DC */, 21 /* CS */, 38 /* SCK */, 39 /* MOSI */
);
Arduino_GFX *gfx = new Arduino_ST7789(
    bus, 40 /* RST */, 0 /* rotation */, false /* IPS */,
    172 /* W */, 320 /* H */, 34, 0, 34, 0
);
static Arduino_Canvas *g_canvas = nullptr;  // PSRAM double-buffer

// ─── Screen layout ────────────────────────────────────────────────────────────
static constexpr int SCREEN_W = 172;
static constexpr int SCREEN_H = 320;
static constexpr int TITLE_H  = 26;
static constexpr int STATUS_H = 24;
static constexpr int ANIM_Y0  = TITLE_H;
static constexpr int ANIM_Y1  = SCREEN_H - STATUS_H;   // 296

// ─── Palette ──────────────────────────────────────────────────────────────────
// RGB565
// Idle  = electric blue  R5=0  G6=32 B5=31 → approx #0080F8
// Capture = pure red     R5=31 G6=0  B5=0  → #F80000
static constexpr uint16_t COL_IDLE   = 0x041F;  // electric blue  (standby)
static constexpr uint16_t COL_CAP    = 0xF800;  // pure red       (capturing)
static constexpr uint16_t COL_DIM    = 0x2945;  // near-black blue-grey
static constexpr uint16_t COL_BAR_BG = 0x0841;  // very dark teal

// ─── Touch ────────────────────────────────────────────────────────────────────
static constexpr int     TOUCH_SDA  = 42;
static constexpr int     TOUCH_SCL  = 41;
static constexpr int     TOUCH_RST  = 47;
static constexpr int     TOUCH_INT  = 48;
static constexpr uint8_t TOUCH_ADDR = 0x63;

volatile int      g_lastTouchX   = -1;
volatile int      g_lastTouchY   = -1;
volatile uint32_t g_touchHits    = 0;
volatile int      g_lastIntState = 1;

void scanI2C() {
    Serial.println("[i2c] scan start");
    int found = 0;
    for (uint8_t addr = 1; addr < 127; addr++) {
        Wire.beginTransmission(addr);
        if (Wire.endTransmission() == 0) {
            Serial.printf("[i2c] found 0x%02X\n", addr);
            found++;
        }
    }
    Serial.printf("[i2c] scan done, found=%d\n", found);
}

bool touchReadReg(uint8_t reg, uint8_t *data, size_t len) {
    Wire.beginTransmission(AXS5106L_ADDR);
    Wire.write(reg);
    if (Wire.endTransmission(true) != 0) return false;
    delayMicroseconds(300);
    size_t got = Wire.requestFrom((int)AXS5106L_ADDR, (int)len, (int)true);
    if (got != len) return false;
    for (size_t i = 0; i < len; i++) data[i] = Wire.read();
    return true;
}

bool initTouch() {
    pinMode(TOUCH_RST, OUTPUT);
    digitalWrite(TOUCH_RST, LOW);
    delay(20);
    digitalWrite(TOUCH_RST, HIGH);
    delay(200);

    pinMode(TOUCH_INT, INPUT);
    Wire.begin(TOUCH_SDA, TOUCH_SCL);
    scanI2C();

    uint8_t id[8] = {0};
    if (touchReadReg(0x01, id, sizeof(id))) {
        Serial.print("[touch] reg01:");
        for (int i = 0; i < 8; i++) Serial.printf(" %02X", id[i]);
        Serial.println();
    } else {
        Serial.println("[touch] read reg01 failed");
    }
    return true;
}

bool readTouch(int &x, int &y) {
    x = -1; y = -1;
    uint8_t data[14] = {0};
    if (!touchReadReg(0x01, data, sizeof(data))) return false;

    static uint8_t last0 = 0xFF, last1 = 0xFF;
    if (data[0] != last0 || data[1] != last1) {
        Serial.print("[touch] raw:");
        for (int i = 0; i < 8; i++) Serial.printf(" %02X", data[i]);
        Serial.println();
        last0 = data[0]; last1 = data[1];
    }

    uint8_t points = data[1];
    if (points == 0 || points > 5) return false;

    uint16_t raw_x = ((uint16_t)(data[2] & 0x0F) << 8) | data[3];
    uint16_t raw_y = ((uint16_t)(data[4] & 0x0F) << 8) | data[5];

    x = SCREEN_W - 1 - (int)raw_x;
    y = (int)raw_y;
    if (x < 0)         x = 0;
    if (x >= SCREEN_W) x = SCREEN_W - 1;
    if (y < 0)         y = 0;
    if (y >= SCREEN_H) y = SCREEN_H - 1;

    g_lastTouchX = x;
    g_lastTouchY = y;
    g_touchHits++;
    return true;
}

// ─── SD ───────────────────────────────────────────────────────────────────────
static constexpr int SD_CLK = 16, SD_CMD = 15, SD_D0 = 17;
static constexpr int SD_D1  = 18, SD_D2  = 13, SD_D3 = 14;

bool initSD() {
    if (!SD_MMC.setPins(SD_CLK, SD_CMD, SD_D0, SD_D1, SD_D2, SD_D3)) {
        Serial.println("[sd] setPins failed");
        return false;
    }
    if (!SD_MMC.begin()) {
        Serial.println("[sd] begin failed");
        return false;
    }
    if (SD_MMC.cardType() == CARD_NONE) {
        Serial.println("[sd] no card");
        return false;
    }
    Serial.printf("[sd] card: %llu MB\n", SD_MMC.cardSize() / (1024ULL * 1024ULL));
    return true;
}

String nextCaptureName() {
    for (int i = 0; i < 10000; i++) {
        char buf[32];
        snprintf(buf, sizeof(buf), "/ble_%04d.pcap", i);
        if (!SD_MMC.exists(buf)) return String(buf);
    }
    return "/ble_cap.pcap";
}

// ─── Device state ─────────────────────────────────────────────────────────────
enum class DeviceMode { STOPPED, CAPTURING };
volatile DeviceMode g_mode = DeviceMode::STOPPED;

File     g_pcap;
String   g_capturePath   = "";
volatile uint32_t g_packetCount  = 0;
volatile uint32_t g_dropCount    = 0;
volatile uint8_t  g_uniqueCount  = 0;   // unique BDA count (saturates at 255)

// ─── Unique device table ──────────────────────────────────────────────────────
// Tracks up to 128 unique Bluetooth addresses per capture session.
// Accessed from the BT event task — protected by a mutex.
#define MAX_UNIQUE_DEVICES 128

static uint8_t         g_devTable[MAX_UNIQUE_DEVICES][6];
static uint8_t         g_devTableLen   = 0;
static SemaphoreHandle_t g_devMutex    = nullptr;

// Returns true if bda is new (and adds it to the table).
static bool trackDevice(const uint8_t *bda) {
    if (!g_devMutex) return false;
    if (xSemaphoreTake(g_devMutex, 0) != pdTRUE) return false;

    bool isnew = true;
    for (uint8_t i = 0; i < g_devTableLen; i++) {
        if (memcmp(g_devTable[i], bda, 6) == 0) { isnew = false; break; }
    }
    if (isnew && g_devTableLen < MAX_UNIQUE_DEVICES) {
        memcpy(g_devTable[g_devTableLen++], bda, 6);
        if (g_uniqueCount < 255) g_uniqueCount++;
    }
    xSemaphoreGive(g_devMutex);
    return isnew;
}

// ─── PCAP ─────────────────────────────────────────────────────────────────────
// Link type 256 = LINKTYPE_BLUETOOTH_LE_LL_WITH_PHDR
// Each record: [10-byte RF pseudo-hdr][4-byte AA][PDU hdr][AdvA][AdvData][3-byte CRC]
// Wireshark fully dissects the LE Link Layer PDU and all AD structures.
struct __attribute__((packed)) PcapGlobalHeader {
    uint32_t magic_number  = 0xa1b2c3d4;
    uint16_t version_major = 2, version_minor = 4;
    int32_t  thiszone      = 0;
    uint32_t sigfigs       = 0;
    uint32_t snaplen       = 512;
    uint32_t network       = 256;   // LINKTYPE_BLUETOOTH_LE_LL_WITH_PHDR
};
struct __attribute__((packed)) PcapRecordHeader {
    uint32_t ts_sec, ts_usec, incl_len, orig_len;
};

// PacketItem: pointer to PSRAM-allocated frame buffer (freed by writer task).
struct PacketItem {
    uint32_t ts_us;
    uint16_t incl_len;
    uint16_t orig_len;
    int8_t   rssi;
    uint8_t  channel;   // BLE advertising channel (37 / 38 / 39)
    uint8_t  *data;
};
QueueHandle_t g_pktQueue = nullptr;

bool openPcap() {
    g_capturePath = nextCaptureName();
    g_pcap = SD_MMC.open(g_capturePath, FILE_WRITE);
    if (!g_pcap) { Serial.println("[pcap] open failed"); return false; }
    PcapGlobalHeader gh;
    size_t w = g_pcap.write((const uint8_t *)&gh, sizeof(gh));
    g_pcap.flush();
    if (w != sizeof(gh)) {
        Serial.println("[pcap] header write failed");
        g_pcap.close();
        return false;
    }
    Serial.printf("[pcap] opened %s\n", g_capturePath.c_str());
    return true;
}

void closePcap() {
    if (g_pcap) { g_pcap.flush(); g_pcap.close(); Serial.println("[pcap] closed"); }
}

// ─── LCD register init (Waveshare demo sequence) ──────────────────────────────
void lcd_reg_init(void) {
    static const uint8_t init_operations[] = {
        BEGIN_WRITE,
        WRITE_COMMAND_8, 0x11,
        END_WRITE,
        DELAY, 120,

        BEGIN_WRITE,
        WRITE_C8_D16, 0xDF, 0x98, 0x53,
        WRITE_C8_D8,  0xB2, 0x23,

        WRITE_COMMAND_8, 0xB7,
        WRITE_BYTES, 4,
        0x00, 0x47, 0x00, 0x6F,

        WRITE_COMMAND_8, 0xBB,
        WRITE_BYTES, 6,
        0x1C, 0x1A, 0x55, 0x73, 0x63, 0xF0,

        WRITE_C8_D16, 0xC0, 0x44, 0xA4,
        WRITE_C8_D8,  0xC1, 0x16,

        WRITE_COMMAND_8, 0xC3,
        WRITE_BYTES, 8,
        0x7D, 0x07, 0x14, 0x06, 0xCF, 0x71, 0x72, 0x77,

        WRITE_COMMAND_8, 0xC4,
        WRITE_BYTES, 12,
        0x00, 0x00, 0xA0, 0x79, 0x0B, 0x0A, 0x16, 0x79, 0x0B, 0x0A, 0x16, 0x82,

        WRITE_COMMAND_8, 0xC8,
        WRITE_BYTES, 32,
        0x3F, 0x32, 0x29, 0x29, 0x27, 0x2B, 0x27, 0x28,
        0x28, 0x26, 0x25, 0x17, 0x12, 0x0D, 0x04, 0x00,
        0x3F, 0x32, 0x29, 0x29, 0x27, 0x2B, 0x27, 0x28,
        0x28, 0x26, 0x25, 0x17, 0x12, 0x0D, 0x04, 0x00,

        WRITE_COMMAND_8, 0xD0,
        WRITE_BYTES, 5,
        0x04, 0x06, 0x6B, 0x0F, 0x00,

        WRITE_C8_D16, 0xD7, 0x00, 0x30,
        WRITE_C8_D8,  0xE6, 0x14,
        WRITE_C8_D8,  0xDE, 0x01,

        WRITE_COMMAND_8, 0xB7,
        WRITE_BYTES, 5,
        0x03, 0x13, 0xEF, 0x35, 0x35,

        WRITE_COMMAND_8, 0xC1,
        WRITE_BYTES, 3,
        0x14, 0x15, 0xC0,

        WRITE_C8_D16, 0xC2, 0x06, 0x3A,
        WRITE_C8_D16, 0xC4, 0x72, 0x12,
        WRITE_C8_D8,  0xBE, 0x00,
        WRITE_C8_D8,  0xDE, 0x02,

        WRITE_COMMAND_8, 0xE5,
        WRITE_BYTES, 3,
        0x00, 0x02, 0x00,

        WRITE_COMMAND_8, 0xE5,
        WRITE_BYTES, 3,
        0x01, 0x02, 0x00,

        WRITE_C8_D8,  0xDE, 0x00,
        WRITE_C8_D8,  0x35, 0x00,
        WRITE_C8_D8,  0x3A, 0x05,

        WRITE_COMMAND_8, 0x2A,
        WRITE_BYTES, 4,
        0x00, 0x22, 0x00, 0xCD,

        WRITE_COMMAND_8, 0x2B,
        WRITE_BYTES, 4,
        0x00, 0x00, 0x01, 0x3F,

        WRITE_C8_D8,  0xDE, 0x02,

        WRITE_COMMAND_8, 0xE5,
        WRITE_BYTES, 3,
        0x00, 0x02, 0x00,

        WRITE_C8_D8,  0xDE, 0x00,
        WRITE_C8_D8,  0x36, 0x00,
        WRITE_COMMAND_8, 0x21,
        END_WRITE,

        DELAY, 10,

        BEGIN_WRITE,
        WRITE_COMMAND_8, 0x29,
        END_WRITE
    };
    bus->batchOperation(init_operations, sizeof(init_operations));
}

// RTC_NOINIT_ATTR survives ESP.restart() — used by double-tap MSC exit.
#define USB_SKIP_MAGIC 0xDEAD5541u
RTC_NOINIT_ATTR static uint32_t g_skipUsbDetect;

// ============================================================
// ═══════════════  SQUID SPRITE  ═════════════════════════════
// ============================================================
// Classic Space Invader squid — 11 cols × 8 rows @ scale 4.
// Bitmask: bit 10 = leftmost col (col 0), bit 0 = col 10.
// Shared between the MSC screen (gfx) and main UI (canvas).
//
// Frame 0 layout (col 0..10):
//   Row 0  . . . X . X . X . . .   antennae tips
//   Row 1  . . . X X X X X . . .   narrow head
//   Row 2  . X X X X X X X X X .   upper body
//   Row 3  X X . X X . X X . X X   eyes / mid-body
//   Row 4  X X X X X X X X X X X   solid core
//   Row 5  . . X . X X X . X . .   lower body
//   Row 6  X . . . . . . . . . X   outer legs
//   Row 7  . X . . . . . . . X .   leg tips

#define SQUID_COLS  11
#define SQUID_ROWS   8
#define SQUID_SCALE  4
#define SQUID_CX     (SCREEN_W / 2)
#define SQUID_CY     115

// Frame 0 — antennae out, legs together
static const uint16_t SQUID_F0[SQUID_ROWS] = {
    0x0A8,   // . . . X . X . X . . .
    0x0F8,   // . . . X X X X X . . .
    0x3FE,   // . X X X X X X X X X .
    0x6DB,   // X X . X X . X X . X X
    0x7FF,   // X X X X X X X X X X X
    0x174,   // . . X . X X X . X . .
    0x401,   // X . . . . . . . . . X
    0x202,   // . X . . . . . . . X .
};
// Frame 1 — antennae shifted, legs splayed
static const uint16_t SQUID_F1[SQUID_ROWS] = {
    0x154,   // . . X . X . X . X . .
    0x0F8,
    0x3FE,
    0x6DB,
    0x7FF,
    0x174,
    0x202,   // legs swap with frame 0
    0x401,
};

// ============================================================
// ═══════════════  USB MASS STORAGE (MSC)  ═══════════════════
// ============================================================
static USBMSC g_msc;

namespace {
    class SDMMCAccessor : public fs::SDMMCFS {
    public:
        sdmmc_card_t* card() { return _card; }
    };
    static sdmmc_card_t* sdRawCard() {
        return reinterpret_cast<SDMMCAccessor*>(&SD_MMC)->card();
    }
}

static int32_t onMscRead(uint32_t lba, uint32_t offset,
                          void *buffer, uint32_t bufsize) {
    (void)offset;
    sdmmc_card_t *card = sdRawCard();
    if (!card) return -1;
    return (sdmmc_read_sectors(card, buffer, lba, bufsize / 512) == ESP_OK)
           ? (int32_t)bufsize : -1;
}

static int32_t onMscWrite(uint32_t lba, uint32_t offset,
                           uint8_t *buffer, uint32_t bufsize) {
    (void)offset;
    sdmmc_card_t *card = sdRawCard();
    if (!card) return -1;
    return (sdmmc_write_sectors(card, buffer, lba, bufsize / 512) == ESP_OK)
           ? (int32_t)bufsize : -1;
}

// Draw MSC status screen with squid sprite in cyan
static void drawMscScreen(const char *line1, const char *line2,
                           uint16_t statusColor,
                           const char *footer = nullptr) {
    gfx->fillScreen(RGB565_BLACK);

    // Squid sprite (cyan in USB mode)
    int16_t x0 = SQUID_CX - (SQUID_COLS * SQUID_SCALE) / 2;
    int16_t y0 = 55       - (SQUID_ROWS * SQUID_SCALE) / 2;
    for (int row = 0; row < SQUID_ROWS; row++) {
        uint16_t bits = SQUID_F0[row];
        for (int col = 0; col < SQUID_COLS; col++) {
            if (bits & (1u << (SQUID_COLS - 1 - col))) {
                gfx->fillRect(x0 + col * SQUID_SCALE,
                               y0 + row * SQUID_SCALE,
                               SQUID_SCALE, SQUID_SCALE, 0x07FF);
            }
        }
    }

    gfx->setTextSize(3);
    gfx->setTextColor(0x07FF);
    int16_t tw = (int16_t)(8 * 18);
    gfx->setCursor((SCREEN_W - tw) / 2, 90);
    gfx->print("USB MODE");

    gfx->drawFastHLine(10, 120, SCREEN_W - 20, 0x07FF);

    gfx->setTextSize(1);
    gfx->setTextColor(statusColor);
    tw = (int16_t)(strlen(line1) * 6);
    gfx->setCursor((SCREEN_W - tw) / 2, 132);
    gfx->print(line1);

    if (line2 && line2[0]) {
        gfx->setTextColor(0x8410);
        tw = (int16_t)(strlen(line2) * 6);
        gfx->setCursor((SCREEN_W - tw) / 2, 144);
        gfx->print(line2);
    }

    const char *hint = footer ? footer : "Eject safely before unplug";
    gfx->setTextColor(COL_DIM);
    tw = (int16_t)(strlen(hint) * 6);
    gfx->setCursor((SCREEN_W - tw) / 2, SCREEN_H - 16);
    gfx->print(hint);
}

static void updateMscFooter(const char *hint, uint16_t color) {
    gfx->fillRect(0, SCREEN_H - 20, SCREEN_W, 20, RGB565_BLACK);
    gfx->setTextSize(1);
    gfx->setTextColor(color);
    int16_t tw = (int16_t)(strlen(hint) * 6);
    gfx->setCursor((SCREEN_W - tw) / 2, SCREEN_H - 16);
    gfx->print(hint);
}

static void enterMscMode() {
    initTouch();
    drawMscScreen("Initialising SD...", "", RGB565_WHITE);

    if (!initSD()) {
        drawMscScreen("SD card failed!", "Check card and reboot", RGB565_RED);
        while (true) delay(1000);
    }

    uint32_t numSectors = (uint32_t)(SD_MMC.cardSize() / 512);
    uint64_t cardMB     = SD_MMC.cardSize() / (1024ULL * 1024ULL);

    g_msc.vendorID("ESP32-S3");
    g_msc.productID("BLE-SNIFF");
    g_msc.productRevision("1.0");
    g_msc.mediaPresent(true);
    g_msc.onRead(onMscRead);
    g_msc.onWrite(onMscWrite);
    g_msc.begin(numSectors, 512);

    Serial.printf("[msc] %u sectors (%llu MB) ready\n", numSectors, cardMB);

    char line1[32], line2[32];
    snprintf(line1, sizeof(line1), "Drive ready  (%llu MB)", cardMB);
    snprintf(line2, sizeof(line2), "Waiting for host mount...");
    drawMscScreen(line1, line2, COL_IDLE, "Double-tap to exit to capture");

    uint32_t t0 = millis();
    while (!tud_mounted() && (millis() - t0 < 5000)) delay(50);

    if (tud_mounted()) {
        snprintf(line2, sizeof(line2), "Disk mounted by host");
        drawMscScreen(line1, line2, COL_IDLE, "Double-tap to exit to capture");
        Serial.println("[msc] mounted by host");
    } else {
        drawMscScreen(line1, "Mount timeout — still accessible", 0xFFE0,
                      "Double-tap to exit to capture");
        Serial.println("[msc] mount timeout (drive still usable)");
    }

    uint32_t lastTouchMs = 0;
    uint32_t firstTapMs  = 0;
    bool     firstTap    = false;

    for (;;) {
        int tx, ty;
        uint32_t now = millis();

        if ((now - lastTouchMs) > 80 && readTouch(tx, ty)) {
            lastTouchMs = now;

            if (!firstTap) {
                firstTap   = true;
                firstTapMs = now;
                updateMscFooter("Tap again to exit  (400 ms)", 0xFFE0);
                Serial.println("[msc] first tap — waiting for double-tap");
            } else {
                updateMscFooter("Restarting...", RGB565_WHITE);
                Serial.println("[msc] double-tap — restarting into capture mode");
                delay(300);
                g_skipUsbDetect = USB_SKIP_MAGIC;
                ESP.restart();
            }
        }

        if (firstTap && (millis() - firstTapMs > 400)) {
            firstTap = false;
            updateMscFooter("Double-tap to exit to capture", COL_DIM);
        }

        delay(20);
    }
}

// ============================================================
// ═══════════════  BLE CAPTURE  ══════════════════════════════
// ============================================================
// Architecture:
//  • ESP-IDF Bluedroid stack, active scan on all advertising channels.
//  • GAP callback fires on ESP_GAP_BLE_SCAN_RESULT_EVT for every
//    advertisement or scan response received.
//  • Callback reconstructs a LE LL frame (AA + PDU + CRC) preceded by
//    a 10-byte LINKTYPE_BLUETOOTH_LE_LL_WITH_PHDR pseudo-header and
//    posts it to a FreeRTOS queue (never blocks; drop on full).
//  • packetWriterTask dequeues and writes to the open PCAP file on Core 1.
//
// Frame layout per PCAP record:
//  [10 B  RF pseudo-header  ]  rf_channel | rssi | noise | aa_offenses
//                                ref_aa (4 B LE) | flags (2 B LE)
//  [4 B   Access Address    ]  0xD6 BE 89 8E  (advertising channel AA)
//  [2 B   PDU header        ]  pdu_type | tx_add | length
//  [6 B   AdvA              ]  Bluetooth device address (LSB first)
//  [N B   AdvData / ScanRsp ]  raw AD structures  (0-31 bytes)
//  [3 B   CRC               ]  0x00 0x00 0x00  (not valid — zeroed)

static bool g_bleReady = false;

// Forward declarations
static void bleScanResultHandler(
    esp_ble_gap_cb_param_t::ble_scan_result_evt_param *rst);
static void bleGapCallback(esp_gap_ble_cb_event_t event,
                            esp_ble_gap_cb_param_t *param);

bool initBLE() {
    // Release Classic BT memory — we only need BLE.
    esp_err_t err = esp_bt_controller_mem_release(ESP_BT_MODE_CLASSIC_BT);
    if (err != ESP_OK && err != ESP_ERR_INVALID_STATE) {
        Serial.printf("[ble] mem_release warn: %d\n", err);
    }

    esp_bt_controller_config_t bt_cfg = BT_CONTROLLER_INIT_CONFIG_DEFAULT();
    if ((err = esp_bt_controller_init(&bt_cfg)) != ESP_OK) {
        Serial.printf("[ble] controller_init failed: %d\n", err);
        return false;
    }
    if ((err = esp_bt_controller_enable(ESP_BT_MODE_BLE)) != ESP_OK) {
        Serial.printf("[ble] controller_enable failed: %d\n", err);
        return false;
    }
    if ((err = esp_bluedroid_init()) != ESP_OK) {
        Serial.printf("[ble] bluedroid_init failed: %d\n", err);
        return false;
    }
    if ((err = esp_bluedroid_enable()) != ESP_OK) {
        Serial.printf("[ble] bluedroid_enable failed: %d\n", err);
        return false;
    }
    if ((err = esp_ble_gap_register_callback(bleGapCallback)) != ESP_OK) {
        Serial.printf("[ble] register_callback failed: %d\n", err);
        return false;
    }
    Serial.println("[ble] Bluedroid initialised");
    g_bleReady = true;
    return true;
}

// ─── BLE CRC-24 ──────────────────────────────────────────────────────────────
// Polynomial: x^24+x^10+x^9+x^6+x^4+x^3+x+1 (reflected = 0xDA6000)
// Advertising channel CRC init = 0x555555 (BLE spec vol 6 part B §3.1.1)
// Computed over: PDU header (2 B) + PDU payload (AdvA 6 B + AdvData N B)
// — Access Address and pseudo-header are NOT included in the CRC.
static uint32_t ble_crc24(const uint8_t *data, size_t len,
                           uint32_t init = 0x555555u) {
    uint32_t crc = init;
    for (size_t i = 0; i < len; i++) {
        uint8_t b = data[i];
        for (int j = 0; j < 8; j++) {
            uint32_t feedback = ((b >> j) & 1u) ^ (crc & 1u);
            crc >>= 1;
            if (feedback) crc ^= 0xDA6000u;
        }
    }
    return crc & 0xFFFFFFu;
}

// ─── Single-packet frame builder ─────────────────────────────────────────────
// Constructs one complete LINKTYPE_BLUETOOTH_LE_LL_WITH_PHDR record and posts
// it to g_pktQueue.  Called exclusively from the BT event task.
// pdu_type : LE LL PDU type nibble (0=ADV_IND, 2=ADV_NONCONN, 4=SCAN_RSP, …)
// adv_ptr  : pointer to raw AdvData / ScanRsp bytes
// adv_len  : length of that data (clamped to 31)
static void enqueueFrame(
    const esp_ble_gap_cb_param_t::ble_scan_result_evt_param *rst,
    uint8_t pdu_type,
    const uint8_t *adv_ptr,
    uint8_t adv_len)
{
    if (adv_len > 31u) adv_len = 31u;

    uint8_t tx_add   = (rst->ble_addr_type != BLE_ADDR_TYPE_PUBLIC) ? 1u : 0u;
    uint8_t pdu_hdr0 = (pdu_type & 0x0Fu) | (tx_add << 6u);
    uint8_t pdu_hdr1 = (uint8_t)(6u + adv_len);   // AdvA(6) + AdvData(N)

    // Total: 10 (pseudo-hdr) + 4 (AA) + 2 (PDU hdr) + 6 (AdvA) + N + 3 (CRC)
    uint16_t frame_size = 10u + 4u + 2u + 6u + adv_len + 3u;

    uint8_t *buf = (uint8_t *)heap_caps_malloc(
        frame_size, MALLOC_CAP_8BIT | MALLOC_CAP_SPIRAM);
    if (!buf) buf = (uint8_t *)malloc(frame_size);
    if (!buf) { g_dropCount++; return; }

    uint8_t *p = buf;

    // ── RF pseudo-header (10 bytes) ───────────────────────────────────────────
    *p++ = 37u;                          // rf_channel (advertising ch 37)
    *p++ = (uint8_t)(int8_t)rst->rssi;  // signal_power dBm (signed)
    *p++ = 0x80u;                        // noise_power: 0x80 = invalid/unknown
    *p++ = 0x00u;                        // access_address_offenses
    *p++ = 0xD6u; *p++ = 0xBEu; *p++ = 0x89u; *p++ = 0x8Eu;  // ref_aa LE
    // flags: bit0=dewhitened, bit1=signal_power valid, bit4=ref_aa valid
    uint16_t flags = (1u << 0u) | (1u << 1u) | (1u << 4u);  // 0x0013
    *p++ = (uint8_t)(flags & 0xFFu);
    *p++ = (uint8_t)(flags >> 8u);

    // ── LE Link Layer frame ───────────────────────────────────────────────────
    // Access Address — advertising channel AA 0x8E89BED6 little-endian
    *p++ = 0xD6u; *p++ = 0xBEu; *p++ = 0x89u; *p++ = 0x8Eu;

    // PDU header — p is now at buf[14]; CRC is computed from this offset
    *p++ = pdu_hdr0;
    *p++ = pdu_hdr1;

    // AdvA: BDA from controller, already LSB-first
    memcpy(p, rst->bda, 6u); p += 6u;

    // AdvData or ScanRsp payload
    if (adv_len > 0u) { memcpy(p, adv_ptr, adv_len); p += adv_len; }

    // CRC — computed over PDU header + PDU payload (buf[14] … buf[14+2+6+N-1])
    uint32_t crc = ble_crc24(buf + 14u, (size_t)(2u + 6u + adv_len));
    *p++ = (uint8_t)(crc);
    *p++ = (uint8_t)(crc >>  8u);
    *p++ = (uint8_t)(crc >> 16u);

    // ── Enqueue ───────────────────────────────────────────────────────────────
    PacketItem item{};
    item.ts_us    = (uint32_t)esp_timer_get_time();
    item.rssi     = (int8_t)rst->rssi;
    item.channel  = 37u;
    item.orig_len = frame_size;
    item.incl_len = frame_size;
    item.data     = buf;

    if (xQueueSend(g_pktQueue, &item, 0) != pdTRUE) {
        free(buf);
        g_dropCount++;
    }
}

// Called from GAP callback when we have a scan result.
// Runs in the BT event task — must not block; no Serial I/O inside.
//
// Bluedroid merges ADV + SCAN_RSP into a single INQ_RES event: ble_evt_type
// carries the advertising PDU type while scan_rsp_len > 0 signals that a scan
// response was also received in the same scan window.  We emit them as two
// separate PCAP records so Wireshark sees the full exchange.
static void bleScanResultHandler(
    esp_ble_gap_cb_param_t::ble_scan_result_evt_param *rst)
{
    if (g_mode != DeviceMode::CAPTURING) return;

    if (rst->ble_evt_type == ESP_BLE_EVT_SCAN_RSP) {
        // Pure SCAN_RSP event (rare): adv_data holds the scan response payload.
        enqueueFrame(rst, 0x04u, rst->ble_adv, rst->adv_data_len);
        return;
    }

    // ── Track unique advertisers ──────────────────────────────────────────────
    trackDevice(rst->bda);

    // ── Map GAP event type → LE LL PDU type ──────────────────────────────────
    uint8_t pdu_type;
    switch (rst->ble_evt_type) {
        case ESP_BLE_EVT_CONN_ADV:     pdu_type = 0x00u; break;  // ADV_IND
        case ESP_BLE_EVT_CONN_DIR_ADV: pdu_type = 0x01u; break;  // ADV_DIRECT_IND
        case ESP_BLE_EVT_NON_CONN_ADV: pdu_type = 0x02u; break;  // ADV_NONCONN_IND
        case ESP_BLE_EVT_DISC_ADV:     pdu_type = 0x06u; break;  // ADV_SCAN_IND
        default:                       pdu_type = 0x00u; break;
    }

    // ── Emit ADV packet ───────────────────────────────────────────────────────
    if (rst->adv_data_len > 0u) {
        enqueueFrame(rst, pdu_type, rst->ble_adv, rst->adv_data_len);
    }

    // ── Emit merged SCAN_RSP if Bluedroid combined it into this event ─────────
    // For ADV_IND (connectable) and ADV_SCAN_IND (scannable) devices the stack
    // automatically issues a SCAN_REQ and folds the SCAN_RSP data here; this is
    // where Local Name and additional service UUIDs typically appear.
    if (rst->scan_rsp_len > 0u) {
        enqueueFrame(rst, 0x04u,
                     rst->ble_adv + rst->adv_data_len,
                     rst->scan_rsp_len);
    }
}

// GAP event callback — runs in BT event task.
static void bleGapCallback(esp_gap_ble_cb_event_t event,
                            esp_ble_gap_cb_param_t *param) {
    switch (event) {
        case ESP_GAP_BLE_SCAN_PARAM_SET_COMPLETE_EVT:
            // Params are set; start scanning only if capture mode is active.
            if (g_mode == DeviceMode::CAPTURING) {
                esp_err_t e = esp_ble_gap_start_scanning(0);  // 0 = indefinite
                Serial.printf("[ble] start_scanning → %d\n", e);
            }
            break;

        case ESP_GAP_BLE_SCAN_START_COMPLETE_EVT:
            Serial.printf("[ble] scan started, status=%d\n",
                          param->scan_start_cmpl.status);
            break;

        case ESP_GAP_BLE_SCAN_STOP_COMPLETE_EVT:
            Serial.printf("[ble] scan stopped, status=%d\n",
                          param->scan_stop_cmpl.status);
            break;

        case ESP_GAP_BLE_SCAN_RESULT_EVT:
            if (param->scan_rst.search_evt == ESP_GAP_SEARCH_INQ_RES_EVT) {
                bleScanResultHandler(&param->scan_rst);
            }
            break;

        default:
            break;
    }
}

// ─── PCAP writer task ─────────────────────────────────────────────────────────
static volatile uint32_t g_lastPktFlash = 0;

void packetWriterTask(void *param) {
    (void)param;
    PacketItem item;
    while (true) {
        if (xQueueReceive(g_pktQueue, &item, portMAX_DELAY) == pdTRUE) {
            if (g_mode == DeviceMode::CAPTURING && g_pcap) {
                PcapRecordHeader rh{};
                rh.ts_sec   = item.ts_us / 1000000UL;
                rh.ts_usec  = item.ts_us % 1000000UL;
                rh.incl_len = item.incl_len;
                rh.orig_len = item.orig_len;
                g_pcap.write((const uint8_t *)&rh, sizeof(rh));
                g_pcap.write(item.data, item.incl_len);
                g_packetCount++;
                g_lastPktFlash = millis();
                if ((g_packetCount % 32) == 0) g_pcap.flush();
            }
            free(item.data);
            item.data = nullptr;
        }
    }
}

// ─── Capture start / stop ─────────────────────────────────────────────────────
bool startCapture() {
    if (!g_bleReady) {
        Serial.println("[ble] not ready");
        return false;
    }
    if (!openPcap()) return false;

    // Reset counters and device table
    g_packetCount = 0;
    g_dropCount   = 0;
    g_uniqueCount = 0;
    if (g_devMutex && xSemaphoreTake(g_devMutex, pdMS_TO_TICKS(50)) == pdTRUE) {
        g_devTableLen = 0;
        xSemaphoreGive(g_devMutex);
    }

    // Set mode BEFORE calling set_scan_params so the GAP callback can safely
    // call start_scanning when params are confirmed.
    g_mode = DeviceMode::CAPTURING;

    // Active scan: 100 ms interval, 100 ms window (≈ 100% duty cycle),
    // duplicates enabled (we want every packet for the PCAP).
    static const esp_ble_scan_params_t scan_params = {
        .scan_type          = BLE_SCAN_TYPE_ACTIVE,
        .own_addr_type      = BLE_ADDR_TYPE_PUBLIC,
        .scan_filter_policy = BLE_SCAN_FILTER_ALLOW_ALL,
        .scan_interval      = 0x00A0,   // 160 × 0.625 ms = 100 ms
        .scan_window        = 0x00A0,   // 160 × 0.625 ms = 100 ms  (100% duty)
        .scan_duplicate     = BLE_SCAN_DUPLICATE_DISABLE,
    };
    esp_ble_gap_set_scan_params((esp_ble_scan_params_t *)&scan_params);
    // Scanning begins inside bleGapCallback → ESP_GAP_BLE_SCAN_PARAM_SET_COMPLETE_EVT

    Serial.printf("[ble] capture started → %s\n", g_capturePath.c_str());
    return true;
}

void stopCapture() {
    g_mode = DeviceMode::STOPPED;          // halt the GAP callback immediately
    esp_ble_gap_stop_scanning();
    vTaskDelay(pdMS_TO_TICKS(80));         // let the writer drain inflight items
    closePcap();
    Serial.println("[ble] capture stopped");
}

void toggleCapture() {
    if (g_mode == DeviceMode::CAPTURING) stopCapture();
    else                                  startCapture();
}

// ============================================================
// ═══════════════  SPACE INVADER UI  ═════════════════════════
// ============================================================

// ─── Squid sprite (canvas version) ───────────────────────────────────────────
static void drawSquid(bool frame1, bool capturing) {
    const uint16_t *rows  = frame1 ? SQUID_F1 : SQUID_F0;
    const uint16_t  color = capturing ? COL_CAP : COL_IDLE;
    const int16_t   x0    = SQUID_CX - (SQUID_COLS * SQUID_SCALE) / 2;
    const int16_t   y0    = SQUID_CY - (SQUID_ROWS * SQUID_SCALE) / 2;

    for (int row = 0; row < SQUID_ROWS; row++) {
        uint16_t bits = rows[row];
        for (int col = 0; col < SQUID_COLS; col++) {
            if (bits & (1u << (SQUID_COLS - 1 - col))) {
                g_canvas->fillRect(
                    x0 + col * SQUID_SCALE,
                    y0 + row * SQUID_SCALE,
                    SQUID_SCALE, SQUID_SCALE,
                    color
                );
            }
        }
    }
}

// ─── Starfield ────────────────────────────────────────────────────────────────
#define STAR_COUNT 80

struct Star { float x, y, speed; uint8_t bright; };
static Star stars[STAR_COUNT];

static void initStars() {
    for (int i = 0; i < STAR_COUNT; i++) {
        stars[i].x      = (float)(esp_random() % SCREEN_W);
        stars[i].y      = (float)(esp_random() % SCREEN_H);
        int tier        = (int)(esp_random() % 3);
        stars[i].speed  = 0.4f + tier * 0.8f + (float)(esp_random() % 10) * 0.05f;
        stars[i].bright = (uint8_t)(80u + tier * 55u + (esp_random() % 40u));
    }
}

static void updateStars(float mult) {
    for (int i = 0; i < STAR_COUNT; i++) {
        stars[i].y += stars[i].speed * mult;
        if (stars[i].y >= (float)SCREEN_H) {
            stars[i].y = (float)ANIM_Y0;
            stars[i].x = (float)(esp_random() % SCREEN_W);
        }
    }
}

static void drawStars(bool capturing) {
    for (int i = 0; i < STAR_COUNT; i++) {
        uint8_t b = stars[i].bright;
        uint16_t col = capturing
            ? g_canvas->color565(b, b >> 3, b >> 3)   // red tint during scan
            : g_canvas->color565(b, b, b);  // stars at standby
        g_canvas->drawPixel((int16_t)stars[i].x, (int16_t)stars[i].y, col);
    }
}

// ─── Title bar ────────────────────────────────────────────────────────────────
static void drawTitleBar(bool capturing) {
    g_canvas->fillRect(0, 0, SCREEN_W, TITLE_H, RGB565_BLACK);

    uint16_t tcolor = capturing ? COL_CAP : COL_IDLE;

    // Pulse red→orange during capture (400 ms period)
    if (capturing && (millis() / 400) % 2) {
        tcolor = 0xFB40;   // orange-red  R=31,G=26,B=0
    }

    const char *title    = capturing ? "SCANNING" : "INSERT COIN";
    uint8_t     textSize = capturing ? 3 : 2;
    int16_t     charW    = textSize * 6;
    int16_t     charH    = textSize * 8;
    int16_t     tw       = (int16_t)(strlen(title) * charW);
    int16_t     tx       = (SCREEN_W - tw) / 2;
    int16_t     ty       = (TITLE_H - charH) / 2;

    g_canvas->setTextSize(textSize);
    g_canvas->setTextColor(tcolor);
    g_canvas->setCursor(tx, ty);
    g_canvas->print(title);

    g_canvas->drawFastHLine(0, TITLE_H - 1, SCREEN_W, tcolor);
}

// ─── Status bar ───────────────────────────────────────────────────────────────
static void drawStatusBar(bool capturing) {
    g_canvas->fillRect(0, ANIM_Y1, SCREEN_W, STATUS_H, COL_BAR_BG);
    g_canvas->drawFastHLine(0, ANIM_Y1, SCREEN_W, capturing ? COL_CAP : COL_IDLE);

    g_canvas->setTextSize(1);

    if (capturing) {
        // Line 1: filename + packet count
        g_canvas->setTextColor(RGB565_WHITE);
        g_canvas->setCursor(2, ANIM_Y1 + 4);
        char buf[32];
        const char *p = g_capturePath.c_str();
        const char *fname = strrchr(p, '/');
        fname = fname ? fname + 1 : p;
        snprintf(buf, sizeof(buf), "%-12s P:%-5lu", fname, (unsigned long)g_packetCount);
        g_canvas->print(buf);

        // Line 2: unique devices + drops
        g_canvas->setTextColor(0xC618);
        g_canvas->setCursor(2, ANIM_Y1 + 13);
        snprintf(buf, sizeof(buf), "DEV:%-3u  DRP:%-5lu",
                 (unsigned)g_uniqueCount, (unsigned long)g_dropCount);
        g_canvas->print(buf);
    } else {
        // Idle — STANDBY + last filename
        g_canvas->setTextColor(COL_IDLE);
        g_canvas->setCursor(2, ANIM_Y1 + 4);
        g_canvas->print("STANDBY");

        if (g_capturePath.length()) {
            g_canvas->setTextColor(0x8410);
            g_canvas->setCursor(2, ANIM_Y1 + 13);
            char buf[24];
            const char *p = g_capturePath.c_str();
            const char *fname = strrchr(p, '/');
            fname = fname ? fname + 1 : p;
            snprintf(buf, sizeof(buf), "last: %s", fname);
            g_canvas->print(buf);
        }
    }
}

// ─── "Tap to scan" hint (idle, slow blink) ────────────────────────────────────
static void drawIdleHint() {
    if ((millis() / 900) % 2 == 0) {
        const char *hint = "TAP TO SCAN";
        int16_t tw = (int16_t)(strlen(hint) * 6);
        g_canvas->setTextSize(1);
        g_canvas->setTextColor(COL_IDLE);
        g_canvas->setCursor((SCREEN_W - tw) / 2, SQUID_CY + 28);
        g_canvas->print(hint);
    }
}

// ─── BLE badge (capture — top-right, shows unique device count) ───────────────
static void drawBleBadge() {
    char buf[10];
    snprintf(buf, sizeof(buf), "DEV:%u", (unsigned)g_uniqueCount);
    int16_t tw = (int16_t)(strlen(buf) * 6);
    g_canvas->setTextSize(1);
    g_canvas->setTextColor(COL_CAP);
    g_canvas->setCursor(SCREEN_W - tw - 2, ANIM_Y0 + 3);
    g_canvas->print(buf);
}

// ─── Packet flash — yellow burst near squid on new packets ───────────────────
static void drawPacketFlash() {
    uint32_t age = millis() - g_lastPktFlash;
    if (age > 80) return;

    static const int8_t dx[] = { -8,  8,  0,  0 };
    static const int8_t dy[] = {  0,  0, -8,  8 };
    for (int i = 0; i < 4; i++) {
        g_canvas->fillRect(
            SQUID_CX + dx[i] - 1,
            SQUID_CY + dy[i] - 1,
            3, 3, 0xFFE0   // yellow burst
        );
    }
}

// ─── Full-frame render ────────────────────────────────────────────────────────
static int      g_squidFrame = 0;
static uint32_t g_lastFlip   = 0;

static void renderFrame() {
    bool capturing = (g_mode == DeviceMode::CAPTURING);
    uint32_t now = millis();

    if (now - g_lastFlip >= 400) {
        g_squidFrame = 1 - g_squidFrame;
        g_lastFlip   = now;
    }

    float speedMult = capturing ? 2.5f : 1.0f;
    updateStars(speedMult);

    g_canvas->fillScreen(RGB565_BLACK);

    drawStars(capturing);
    drawSquid(g_squidFrame, capturing);

    if (!capturing) drawIdleHint();
    else            drawBleBadge();

    drawPacketFlash();
    drawTitleBar(capturing);
    drawStatusBar(capturing);

    g_canvas->flush();
}

// ─── Setup ────────────────────────────────────────────────────────────────────
void setup() {
    Serial.setTxTimeoutMs(0);
    Serial.begin(115200);
    delay(100);
    Serial.println("\n[boot] SNIFF-BLE starting");

    // ── USB host detection (500 ms) ───────────────────────────────────────────
    if (g_skipUsbDetect == USB_SKIP_MAGIC) {
        g_skipUsbDetect = 0;
        Serial.println("[boot] USB detection skipped (double-tap exit)");
    } else {
        bool hostFound = false;
        uint32_t t0 = millis();
        while (millis() - t0 < 500) {
            if (tud_connected()) { hostFound = true; break; }
            delay(10);
        }
        if (hostFound) {
            Serial.println("[usb] host detected — entering MSC mode");
            if (!gfx->begin()) Serial.println("[gfx] begin failed");
            lcd_reg_init();
            gfx->setRotation(0);
            gfx->fillScreen(RGB565_BLACK);
            pinMode(GFX_BL, OUTPUT);
            digitalWrite(GFX_BL, HIGH);
            enterMscMode();  // loops until double-tap, then ESP.restart()
        }
    }

    Serial.println("[boot] no USB host — BLE capture mode");

    // ── Display ───────────────────────────────────────────────────────────────
    if (!gfx->begin()) Serial.println("[gfx] begin failed");
    lcd_reg_init();
    gfx->setRotation(0);
    gfx->fillScreen(RGB565_BLACK);
    pinMode(GFX_BL, OUTPUT);
    digitalWrite(GFX_BL, HIGH);

    gfx->setTextSize(2);
    gfx->setTextColor(COL_IDLE);
    gfx->setCursor(24, 148);
    gfx->print("BOOTING...");

    // ── Touch ─────────────────────────────────────────────────────────────────
    initTouch();

    // ── Canvas (PSRAM double-buffer) ──────────────────────────────────────────
    g_canvas = new Arduino_Canvas(SCREEN_W, SCREEN_H, gfx, 0, 0, 0);
    if (!g_canvas->begin(GFX_SKIP_OUTPUT_BEGIN)) {
        Serial.println("[canvas] begin failed — halting");
        while (true) delay(1000);
    }
    Serial.printf("[canvas] %dx%d buffer ready\n", SCREEN_W, SCREEN_H);

    // ── SD ────────────────────────────────────────────────────────────────────
    if (!initSD()) {
        gfx->fillScreen(RGB565_BLACK);
        gfx->setTextSize(2);
        gfx->setTextColor(RGB565_RED);
        gfx->setCursor(10, 148);
        gfx->print("SD FAILED");
        while (true) delay(1000);
    }

    // ── Packet queue ──────────────────────────────────────────────────────────
    g_pktQueue = xQueueCreate(128, sizeof(PacketItem));
    if (!g_pktQueue) {
        gfx->fillScreen(RGB565_BLACK);
        gfx->setTextSize(2);
        gfx->setTextColor(RGB565_RED);
        gfx->setCursor(10, 148);
        gfx->print("MEM FAILED");
        while (true) delay(1000);
    }

    // ── Device-tracking mutex ─────────────────────────────────────────────────
    g_devMutex = xSemaphoreCreateMutex();

    // ── Writer task (Core 1) ──────────────────────────────────────────────────
    xTaskCreatePinnedToCore(packetWriterTask, "pktWriter", 8192,
                             nullptr, 1, nullptr, 1);

    // ── BLE ───────────────────────────────────────────────────────────────────
    if (!initBLE()) {
        gfx->fillScreen(RGB565_BLACK);
        gfx->setTextSize(2);
        gfx->setTextColor(RGB565_RED);
        gfx->setCursor(10, 148);
        gfx->print("BLE FAILED");
        while (true) delay(1000);
    }

    // ── Stars ─────────────────────────────────────────────────────────────────
    initStars();

    Serial.println("[boot] ready — tap screen or press 's' to toggle capture");
}

// ─── Loop ─────────────────────────────────────────────────────────────────────
void loop() {
    static uint32_t lastAlive = 0;
    static uint32_t lastFrame = 0;
    static uint32_t lastTouch = 0;

    // Serial toggle ('s' / 'S')
    while (Serial.available()) {
        char c = Serial.read();
        if (c == 's' || c == 'S') toggleCapture();
    }

    // Touch — any tap toggles capture (300 ms debounce)
    g_lastIntState = digitalRead(TOUCH_INT);
    int tx, ty;
    if ((millis() - lastTouch) > 300 && readTouch(tx, ty)) {
        lastTouch = millis();
        Serial.printf("[touch] x=%d y=%d → toggle\n", tx, ty);
        toggleCapture();
    }

    // Render at ~30 fps
    uint32_t now = millis();
    if (now - lastFrame >= 33) {
        lastFrame = now;
        renderFrame();
    } else {
        delay(5);
    }

    // Periodic serial status
    if (now - lastAlive >= 2000) {
        lastAlive = now;
        Serial.printf("[alive] %s pkts=%lu drops=%lu dev=%u\n",
                      (g_mode == DeviceMode::CAPTURING) ? "SCAN" : "IDLE",
                      (unsigned long)g_packetCount,
                      (unsigned long)g_dropCount,
                      (unsigned)g_uniqueCount);
    }
}
