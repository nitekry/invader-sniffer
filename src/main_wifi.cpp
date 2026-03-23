// ============================================================
// SNIFF — WiFi Packet Capture  (Waveshare ESP32-S3-Touch-LCD-1.47)
// Backend : SD PCAP capture, channel hop, touch toggle
// Frontend: Space-invader themed UI — starfield + crab sprite
// USB MSC : plug in at boot → SD card mounts as a USB drive
// ============================================================
#include <Arduino.h>
#include <WiFi.h>
#include <esp_wifi.h>
#include <FS.h>
#include <SD_MMC.h>
#include <Wire.h>
#include <Arduino_GFX_Library.h>
#include "esp_lcd_touch_axs5106l.h"
#include <USB.h>
#include <USBMSC.h>
#include <sdmmc_cmd.h>
#include <tusb.h>

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
static constexpr int TITLE_H  = 26;                     // title bar height
static constexpr int STATUS_H = 24;                     // status bar height
static constexpr int ANIM_Y0  = TITLE_H;               // animation area top
static constexpr int ANIM_Y1  = SCREEN_H - STATUS_H;   // animation area bottom (296)

// ─── Palette ──────────────────────────────────────────────────────────────────
// All RGB565
static constexpr uint16_t COL_IDLE   = 0x07E0;  // arcade green
static constexpr uint16_t COL_CAP    = 0xF81F;  // magenta / purple
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
    if (x < 0)        x = 0;
    if (x >= SCREEN_W) x = SCREEN_W - 1;
    if (y < 0)        y = 0;
    if (y >= SCREEN_H) y = SCREEN_H - 1;

    g_lastTouchX = x;
    g_lastTouchY = y;
    g_touchHits++;
    return true;
}

// ─── SD CARD───────────────────────────────────────────────────────────────────
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
        snprintf(buf, sizeof(buf), "/cap_%04d.pcap", i);
        if (!SD_MMC.exists(buf)) return String(buf);
    }
    return "/capture.pcap";
}

// ─── Device State ─────────────────────────────────────────────────────────────
enum class DeviceMode { STOPPED, CAPTURING };
volatile DeviceMode g_mode = DeviceMode::STOPPED;

File     g_pcap;
String   g_capturePath = "";
volatile uint32_t g_packetCount = 0;
volatile uint32_t g_dropCount   = 0;

const uint8_t    g_channels[]   = {1, 6, 11};
volatile uint8_t g_hopIndex     = 0;
volatile bool    g_hopRequested = false;
hw_timer_t      *g_hopTimer     = nullptr;

// ─── PCAP ─────────────────────────────────────────────────────────────────────
struct __attribute__((packed)) PcapGlobalHeader {
    uint32_t magic_number  = 0xa1b2c3d4;
    uint16_t version_major = 2, version_minor = 4;
    int32_t  thiszone      = 0;
    uint32_t sigfigs       = 0;
    uint32_t snaplen       = 2500;
    uint32_t network       = 105;   // <-- LINKTYPE_IEEE802_11
};
struct __attribute__((packed)) PcapRecordHeader {
    uint32_t ts_sec, ts_usec, incl_len, orig_len;
};
// point to PSRAM-allocated buffer to avoid memory bloat
// writer frees up mem
struct PacketItem {
    uint32_t ts_us;
    uint16_t incl_len;  // bytes actually captured
    uint16_t orig_len;  // over-the-air frame length to get full packet
    int8_t   rssi;
    uint8_t  channel;
    uint8_t  *data;     // heap_caps_malloc'd <--- packetWriterTask
};
QueueHandle_t g_pktQueue = nullptr;

bool openPcap() {
    g_capturePath = nextCaptureName();
    g_pcap = SD_MMC.open(g_capturePath, FILE_WRITE);
    if (!g_pcap) { Serial.println("[pcap] open failed"); return false; }
    PcapGlobalHeader gh;
    size_t w = g_pcap.write((const uint8_t *)&gh, sizeof(gh));
    g_pcap.flush();
    if (w != sizeof(gh)) { Serial.println("[pcap] header write failed"); g_pcap.close(); return false; }
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

// RTC_NOINIT_ATTR: startup code never zeroes or re-initialises this region,
// so the value survives ESP.restart().  We use a magic sentinel to tell the
// difference from an uninitialised cold boot.
#define USB_SKIP_MAGIC 0xDEAD5541u
RTC_NOINIT_ATTR static uint32_t g_skipUsbDetect;

// ─── Crab sprite (shared by MSC screen and main UI) ──────────────────────────
// Classic medium Space Invader "crab" — 11 cols × 8 rows.
// Bitmask: bit 10 = leftmost col (col 0), bit 0 = col 10.
// Each set bit is rendered as a CRAB_SCALE × CRAB_SCALE filled square.

#define CRAB_COLS  11
#define CRAB_ROWS   8
#define CRAB_SCALE  4
#define CRAB_CX     (SCREEN_W / 2)
#define CRAB_CY     115

// Frame 0 — claws out / legs down
static const uint16_t CRAB_F0[CRAB_ROWS] = {
    0x104, 0x28A, 0x3FE, 0x6DB, 0x7FF, 0x1DC, 0x104, 0x28A,
};
// Frame 1 — claws in / legs spread
static const uint16_t CRAB_F1[CRAB_ROWS] = {
    0x104, 0x088, 0x3FE, 0x6DB, 0x7FF, 0x1DC, 0x202, 0x401,
};

// ── USB Storage ─────────────────────────────────────────────────────────────── 

static USBMSC g_msc;

// ── Expose the protected sdmmc_card_t* from SDMMCFS ──────────────────────────
namespace {
    class SDMMCAccessor : public fs::SDMMCFS {
    public:
        sdmmc_card_t* card() { return _card; }
    };
    static sdmmc_card_t* sdRawCard() {
        return reinterpret_cast<SDMMCAccessor*>(&SD_MMC)->card();
    }
}

// ── Sector-level read/write callbacks for TinyUSB MSC ────────────────────────
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

// ── Draw a static MSC status screen directly on gfx ──────────────────────────
// footer=nullptr → default "Eject safely before unplug" hint
static void drawMscScreen(const char *line1, const char *line2,
                           uint16_t statusColor,
                           const char *footer = nullptr) {
    gfx->fillScreen(RGB565_BLACK);

    // Crab sprite in cyan (CRAB_F0 is defined earlier in this file)
    int16_t x0 = CRAB_CX - (CRAB_COLS * CRAB_SCALE) / 2;
    int16_t y0 = 55      - (CRAB_ROWS * CRAB_SCALE) / 2;
    for (int row = 0; row < CRAB_ROWS; row++) {
        uint16_t bits = CRAB_F0[row];
        for (int col = 0; col < CRAB_COLS; col++) {
            if (bits & (1u << (CRAB_COLS - 1 - col))) {
                gfx->fillRect(x0 + col * CRAB_SCALE,
                               y0 + row * CRAB_SCALE,
                               CRAB_SCALE, CRAB_SCALE, 0x07FF);
            }
        }
    }

    // "USB MODE" title
    gfx->setTextSize(3);
    gfx->setTextColor(0x07FF);
    int16_t tw = (int16_t)(8 * 18);
    gfx->setCursor((SCREEN_W - tw) / 2, 90);
    gfx->print("USB MODE");

    // Separator
    gfx->drawFastHLine(10, 120, SCREEN_W - 20, 0x07FF);

    // Line 1
    gfx->setTextSize(1);
    gfx->setTextColor(statusColor);
    tw = (int16_t)(strlen(line1) * 6);
    gfx->setCursor((SCREEN_W - tw) / 2, 132);
    gfx->print(line1);

    // Line 2
    if (line2 && line2[0]) {
        gfx->setTextColor(0x8410);
        tw = (int16_t)(strlen(line2) * 6);
        gfx->setCursor((SCREEN_W - tw) / 2, 144);
        gfx->print(line2);
    }

    // Footer — caller can override to guide the user
    const char *hint = footer ? footer : "Eject safely before unplug";
    gfx->setTextColor(COL_DIM);
    tw = (int16_t)(strlen(hint) * 6);
    gfx->setCursor((SCREEN_W - tw) / 2, SCREEN_H - 16);
    gfx->print(hint);
}

// ── Update only the footer row (avoids full screen redraw) ───────────────────
static void updateMscFooter(const char *hint, uint16_t color) {
    gfx->fillRect(0, SCREEN_H - 20, SCREEN_W, 20, RGB565_BLACK);
    gfx->setTextSize(1);
    gfx->setTextColor(color);
    int16_t tw = (int16_t)(strlen(hint) * 6);
    gfx->setCursor((SCREEN_W - tw) / 2, SCREEN_H - 16);
    gfx->print(hint);
}

// ── Enter MSC mode — called at boot if USB host is detected ──────────────────
// Loops until double-tap is detected, then restarts into capture mode.
static void enterMscMode() {
    // Touch must be initialised here — normal setup() hasn't run yet
    initTouch();

    drawMscScreen("Initialising SD...", "", RGB565_WHITE);

    if (!initSD()) {
        drawMscScreen("SD card failed!", "Check card and reboot", RGB565_RED);
        while (true) delay(1000);
    }

    uint32_t numSectors = (uint32_t)(SD_MMC.cardSize() / 512);
    uint64_t cardMB     = SD_MMC.cardSize() / (1024ULL * 1024ULL);

    g_msc.vendorID("ESP32-S3");
    g_msc.productID("SNIFF-SD");
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

    // Wait up to 5 s for the host to mount the disk
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

    // ── Double-tap detection loop ─────────────────────────────────────────────
    // TinyUSB handles all MSC transfers in the background.
    // We poll touch here; a double-tap (two touches within 400 ms,
    // each separated by at least 80 ms debounce) triggers a soft restart
    // that skips USB detection on the next boot.
    uint32_t lastTouchMs = 0;
    uint32_t firstTapMs  = 0;
    bool     firstTap    = false;

    for (;;) {
        int tx, ty;
        uint32_t now = millis();

        if ((now - lastTouchMs) > 80 && readTouch(tx, ty)) {
            lastTouchMs = now;

            if (!firstTap) {
                // Record first tap; prompt for second
                firstTap   = true;
                firstTapMs = now;
                updateMscFooter("Tap again to exit  (400 ms)", 0xFFE0);
                Serial.println("[msc] first tap — waiting for double-tap");
            } else {
                // Second tap within window → confirmed double-tap
                updateMscFooter("Restarting...", RGB565_WHITE);
                Serial.println("[msc] double-tap — restarting into capture mode");
                delay(300);
                g_skipUsbDetect = USB_SKIP_MAGIC;   // tell next boot to skip USB check
                ESP.restart();
            }
        }

        // If the window expires, reset and restore the original footer
        if (firstTap && (millis() - firstTapMs > 400)) {
            firstTap = false;
            updateMscFooter("Double-tap to exit to capture", COL_DIM);
        }

        delay(20);
    }
}

// ============================================================
// ═══════════════  SPACE INVADER UI  ═════════════════════════
// ============================================================

// ─── Crab sprite ─────────────────────────────────────────────────────────────
// (CRAB_F0, CRAB_F1, and all CRAB_* defines are declared earlier in this file,
//  before the MSC section, so they are shared with drawMscScreen.)

static void drawCrab(bool frame1, bool capturing) {
    const uint16_t *rows  = frame1 ? CRAB_F1 : CRAB_F0;
    const uint16_t  color = capturing ? COL_CAP : COL_IDLE;
    const int16_t   x0    = CRAB_CX - (CRAB_COLS * CRAB_SCALE) / 2;  // 86-22 = 64
    const int16_t   y0    = CRAB_CY - (CRAB_ROWS * CRAB_SCALE) / 2;  // 115-16 = 99

    for (int row = 0; row < CRAB_ROWS; row++) {
        uint16_t bits = rows[row];
        for (int col = 0; col < CRAB_COLS; col++) {
            if (bits & (1u << (CRAB_COLS - 1 - col))) {
                g_canvas->fillRect(
                    x0 + col * CRAB_SCALE,
                    y0 + row * CRAB_SCALE,
                    CRAB_SCALE, CRAB_SCALE,
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
        int tier        = (int)(esp_random() % 3);   // 0=slow,1=med,2=fast
        stars[i].speed  = 0.4f + tier * 0.8f + (float)(esp_random() % 10) * 0.05f;
        stars[i].bright = (uint8_t)(80 + tier * 55 + (esp_random() % 40));
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
            ? g_canvas->color565(b, b >> 2, b)     // magenta tint when capturing
            : g_canvas->color565(b, b, b);          // pure white/grey when idle
        g_canvas->drawPixel((int16_t)stars[i].x, (int16_t)stars[i].y, col);
    }
}

// ─── Title bar ────────────────────────────────────────────────────────────────
static void drawTitleBar(bool capturing) {
    g_canvas->fillRect(0, 0, SCREEN_W, TITLE_H, RGB565_BLACK);

    uint16_t tcolor = capturing ? COL_CAP : COL_IDLE;

    // Pulse title during capture (400 ms on/off)
    if (capturing && (millis() / 400) % 2) {
        tcolor = 0xFC1F;   // lighter magenta
    }

    // "INSERT COIN" (11 chars) needs size 2 to fit in 172 px wide screen.
    // "CAPTURING"   (9 chars)  fits at size 3.
    const char *title    = capturing ? "CAPTURING" : "INSERT COIN";
    uint8_t     textSize = capturing ? 3 : 2;
    int16_t     charW    = textSize * 6;
    int16_t     charH    = textSize * 8;

    int16_t tw = (int16_t)(strlen(title) * charW);
    int16_t tx = (SCREEN_W - tw) / 2;
    int16_t ty = (TITLE_H - charH) / 2;

    g_canvas->setTextSize(textSize);
    g_canvas->setTextColor(tcolor);
    g_canvas->setCursor(tx, ty);
    g_canvas->print(title);

    // Thin separator line
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
        snprintf(buf, sizeof(buf), "%-12s P:%-6lu", fname, (unsigned long)g_packetCount);
        g_canvas->print(buf);

        // Line 2: channel + drops
        g_canvas->setTextColor(0xC618);   // light grey
        g_canvas->setCursor(2, ANIM_Y1 + 13);
        snprintf(buf, sizeof(buf), "CH:%-2u  DRP:%-5lu",
                 g_channels[g_hopIndex], (unsigned long)g_dropCount);
        g_canvas->print(buf);
    } else {
        // Idle — show READY and last filename if any
        g_canvas->setTextColor(COL_IDLE);
        g_canvas->setCursor(2, ANIM_Y1 + 4);
        g_canvas->print("READY");

        if (g_capturePath.length()) {
            g_canvas->setTextColor(0x8410);   // dim grey
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

// ─── "Tap to sniff" hint (idle only, slow blink) ──────────────────────────────
static void drawIdleHint() {
    if ((millis() / 900) % 2 == 0) {
        const char *hint = "TAP TO SNIFF";
        int16_t tw = (int16_t)(strlen(hint) * 6);
        g_canvas->setTextSize(1);
        g_canvas->setTextColor(COL_IDLE);
        g_canvas->setCursor((SCREEN_W - tw) / 2, CRAB_CY + 28);
        g_canvas->print(hint);
    }
}

// ─── Channel badge (capture only, top-right of animation area) ────────────────
static void drawChannelBadge() {
    char buf[8];
    snprintf(buf, sizeof(buf), "CH:%u", g_channels[g_hopIndex]);
    int16_t tw = (int16_t)(strlen(buf) * 6);
    g_canvas->setTextSize(1);
    g_canvas->setTextColor(COL_CAP);
    g_canvas->setCursor(SCREEN_W - tw - 2, ANIM_Y0 + 3);
    g_canvas->print(buf);
}

// ─── Packet flash — brief pixel burst near crab on new packets ────────────────
static volatile uint32_t g_lastPktFlash = 0;

static void drawPacketFlash() {
    uint32_t age = millis() - g_lastPktFlash;
    if (age > 80) return;   // flash lasts 80 ms

    // Draw 4 small dots radiating out from crab centre
    static const int8_t dx[] = { -8,  8,  0,  0 };
    static const int8_t dy[] = {  0,  0, -8,  8 };
    for (int i = 0; i < 4; i++) {
        g_canvas->fillRect(CRAB_CX + dx[i] - 1, CRAB_CY + dy[i] - 1, 3, 3, 0xFFE0);  // yellow burst
    }
}

// ─── Full-frame render ────────────────────────────────────────────────────────
static int      g_crabFrame = 0;
static uint32_t g_lastFlip  = 0;

static void renderFrame() {
    bool capturing = (g_mode == DeviceMode::CAPTURING);
    uint32_t now = millis();

    // Alternate crab frame every 400 ms
    if (now - g_lastFlip >= 400) {
        g_crabFrame = 1 - g_crabFrame;
        g_lastFlip  = now;
    }

    float speedMult = capturing ? 2.5f : 1.0f;
    updateStars(speedMult);

    g_canvas->fillScreen(RGB565_BLACK);

    drawStars(capturing);
    drawCrab(g_crabFrame, capturing);

    if (!capturing) drawIdleHint();
    else            drawChannelBadge();

    drawPacketFlash();
    drawTitleBar(capturing);
    drawStatusBar(capturing);

    g_canvas->flush();
}

// ─── WiFi promiscuous sniffer ─────────────────────────────────────────────────
void ARDUINO_ISR_ATTR hopISR() {
    g_hopRequested = true;
}

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
                g_lastPktFlash = millis();   // trigger flash on screen
                if ((g_packetCount % 32) == 0) g_pcap.flush();
            }
            // Always free the PSRAM buffer, even when capture stopped mid-flight.
            free(item.data);
            item.data = nullptr;
        }
    }
}

void wifiSniffer(void *buf, wifi_promiscuous_pkt_type_t type) {
    if (g_mode != DeviceMode::CAPTURING) return;
    if (type == WIFI_PKT_MISC) return;
    const wifi_promiscuous_pkt_t *ppkt = (const wifi_promiscuous_pkt_t *)buf;
    if (!ppkt) return;

    // rx_ctrl.sig_len is the total over-the-air frame length INCLUDING the
    // 4-byte FCS.  The driver strips the FCS before handing us ppkt->payload,
    // so the valid payload is exactly (sig_len - 4) bytes.
    uint16_t sig_len     = ppkt->rx_ctrl.sig_len;
    uint16_t payload_len = (sig_len >= 4) ? (sig_len - 4) : sig_len;
    if (payload_len == 0) return;

    uint16_t capture_len = min<uint16_t>(payload_len, 2500);

    // Allocate in PSRAM to leave internal SRAM free; fall back to DRAM.
    uint8_t *pkt_data = (uint8_t *)heap_caps_malloc(
        capture_len, MALLOC_CAP_8BIT | MALLOC_CAP_SPIRAM);
    if (!pkt_data) pkt_data = (uint8_t *)malloc(capture_len);
    if (!pkt_data) { g_dropCount++; return; }

    memcpy(pkt_data, ppkt->payload, capture_len);

    PacketItem item{};
    item.ts_us    = micros();
    item.rssi     = ppkt->rx_ctrl.rssi;
    item.channel  = ppkt->rx_ctrl.channel;
    item.orig_len = payload_len;
    item.incl_len = capture_len;
    item.data     = pkt_data;

    if (xQueueSend(g_pktQueue, &item, 0) != pdTRUE) {
        free(pkt_data);
        g_dropCount++;
    }
}

bool startCapture() {
    if (!g_pcap && !openPcap()) return false;
    g_packetCount = 0;
    g_dropCount   = 0;
    g_hopIndex    = 0;

    WiFi.disconnect(true, true);
    WiFi.mode(WIFI_MODE_STA);
    delay(100);

    esp_wifi_set_promiscuous(false);
    esp_wifi_set_promiscuous_rx_cb(nullptr);
    delay(20);

    esp_wifi_set_channel(g_channels[g_hopIndex], WIFI_SECOND_CHAN_NONE);

    wifi_promiscuous_filter_t filt{};
    filt.filter_mask = WIFI_PROMIS_FILTER_MASK_MGMT |
                       WIFI_PROMIS_FILTER_MASK_CTRL |
                       WIFI_PROMIS_FILTER_MASK_DATA;
    esp_wifi_set_promiscuous_filter(&filt);
    esp_wifi_set_promiscuous_rx_cb(&wifiSniffer);
    esp_wifi_set_promiscuous(true);
    timerAlarmEnable(g_hopTimer);

    g_mode = DeviceMode::CAPTURING;
    Serial.printf("[wifi] capture started: %s\n", g_capturePath.c_str());
    return true;
}

void stopCapture() {
    timerAlarmDisable(g_hopTimer);
    esp_wifi_set_promiscuous(false);
    closePcap();
    g_mode = DeviceMode::STOPPED;
    Serial.println("[wifi] capture stopped");
}

void toggleCapture() {
    if (g_mode == DeviceMode::CAPTURING) stopCapture();
    else startCapture();
}

// ─── Setup ────────────────────────────────────────────────────────────────────
void setup() {
    // Non-blocking Serial: writes won't stall if no USB host is connected
    Serial.setTxTimeoutMs(0);
    Serial.begin(115200);
    delay(100);
    Serial.println("\n[boot] SNIFF starting");

    // ── USB host detection (500 ms) ───────────────────────────────────────────
    // Skipped if g_skipUsbDetect is set — that flag is written by the
    // double-tap exit in MSC mode so the device restarts into capture mode
    // even when the USB cable is still plugged in.
    if (g_skipUsbDetect == USB_SKIP_MAGIC) {
        g_skipUsbDetect = 0;   // clear for the next cold boot
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
            enterMscMode();   // loops until double-tap, then ESP.restart()
        }
    }

    Serial.println("[boot] no USB host — capture mode");

    // Initialise physical display
    if (!gfx->begin()) Serial.println("[gfx] begin failed");
    lcd_reg_init();
    gfx->setRotation(0);
    gfx->fillScreen(RGB565_BLACK);
    pinMode(GFX_BL, OUTPUT);
    digitalWrite(GFX_BL, HIGH);

    // Boot splash (direct to gfx — canvas not ready yet)
    gfx->setTextSize(2);
    gfx->setTextColor(COL_IDLE);
    gfx->setCursor(24, 148);
    gfx->print("BOOTING...");

    initTouch();

    // Create PSRAM double-buffer canvas
    g_canvas = new Arduino_Canvas(SCREEN_W, SCREEN_H, gfx, 0, 0, 0);
    // GFX_SKIP_OUTPUT_BEGIN: gfx is already initialised — don't re-run display init
    if (!g_canvas->begin(GFX_SKIP_OUTPUT_BEGIN)) {
        Serial.println("[canvas] begin failed — halting");
        while (true) delay(1000);
    }
    Serial.printf("[canvas] %dx%d buffer ready\n", SCREEN_W, SCREEN_H);

    // SD
    if (!initSD()) {
        gfx->fillScreen(RGB565_BLACK);
        gfx->setTextSize(2);
        gfx->setTextColor(RGB565_RED);
        gfx->setCursor(10, 148);
        gfx->print("SD FAILED");
        while (true) delay(1000);
    }

    // Packet queue
    g_pktQueue = xQueueCreate(128, sizeof(PacketItem));
    if (!g_pktQueue) {
        gfx->fillScreen(RGB565_BLACK);
        gfx->setTextSize(2);
        gfx->setTextColor(RGB565_RED);
        gfx->setCursor(10, 148);
        gfx->print("MEM FAILED");
        while (true) delay(1000);
    }

    xTaskCreatePinnedToCore(packetWriterTask, "pktWriter", 8192, nullptr, 1, nullptr, 1);

    // Channel-hop timer — fires every 250 ms
    g_hopTimer = timerBegin(0, 80, true);
    timerAttachInterrupt(g_hopTimer, &hopISR, false);
    timerAlarmWrite(g_hopTimer, 250000, true);

    WiFi.mode(WIFI_MODE_NULL);

    initStars();

    Serial.println("[boot] ready — press 's' to toggle capture");
}

// ─── Loop ─────────────────────────────────────────────────────────────────────
void loop() {
    static uint32_t lastAlive = 0;
    static uint32_t lastFrame = 0;
    static uint32_t lastTouch = 0;

    // Serial toggle
    while (Serial.available()) {
        char c = Serial.read();
        if (c == 's' || c == 'S') toggleCapture();
    }

    // Channel hop
    if (g_mode == DeviceMode::CAPTURING && g_hopRequested) {
        g_hopRequested = false;
        g_hopIndex = (g_hopIndex + 1) % (sizeof(g_channels) / sizeof(g_channels[0]));
        esp_wifi_set_channel(g_channels[g_hopIndex], WIFI_SECOND_CHAN_NONE);
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
        Serial.printf("[alive] %s pkts=%lu drops=%lu ch=%u\n",
                      (g_mode == DeviceMode::CAPTURING) ? "CAP" : "STOP",
                      (unsigned long)g_packetCount,
                      (unsigned long)g_dropCount,
                      g_channels[g_hopIndex]);
    }
}
