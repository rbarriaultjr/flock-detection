#include <WiFi.h>
#include <NimBLEDevice.h>
#include <NimBLEScan.h>
#include <NimBLEAdvertisedDevice.h>
#include <ArduinoJson.h>
#include <string.h>
#include <ctype.h>
#include <stdio.h>
#include <stdint.h>
#include <vector>
#include "esp_wifi.h"
#include "esp_wifi_types.h"
#include <Wire.h>
#include <Adafruit_GFX.h>
#include <Adafruit_SSD1306.h>
#include <SPI.h>
#include <SD.h>
#include <FS.h>
#include <TinyGPSPlus.h>    
#include <HardwareSerial.h> 
#include <freertos/FreeRTOS.h> 
#include <freertos/task.h>     

// ============================================================================
// CONFIGURATION
// ============================================================================

#define BUZZER_PIN A3
#define SD_CS_PIN  D2
#define BUTTON_PIN D1
#define OLED_RESET -1
#define SCREEN_ADDRESS 0x3C
Adafruit_SSD1306 display(128, 64, &Wire, OLED_RESET);

#define RX_PIN D7
#define TX_PIN D6
#define GPS_BAUD 9600
TinyGPSPlus gps;
HardwareSerial SerialGPS(1); 

#define LOW_FREQ 200
#define HIGH_FREQ 800
#define DETECT_FREQ 1000  
#define BOOT_BEEP_DURATION 300
#define DETECT_BEEP_DURATION 150

#define MAX_CHANNEL 13
#define CHANNEL_HOP_INTERVAL 350   // PERF: Reduced from 500ms - faster channel cycling
#define BLE_SCAN_DURATION 2        // PERF: Increased from 1s - catch more BLE adverts per scan
#define BLE_SCAN_INTERVAL 3000     // PERF: Reduced from 5000ms - scan BLE more often
#define BUZZER_COOLDOWN 60000 
#define LOG_UPDATE_DELAY 500       // PERF: Reduced from 1000ms - more responsive live feed
#define IGNORE_WEAK_RSSI -80  

#define MAX_LOG_BUFFER 10          
#define SD_FLUSH_INTERVAL 10000    

// ============================================================================
// CONFIDENCE SCORING THRESHOLDS
// ============================================================================
// Each detection method contributes points. We alarm at CONFIDENCE_ALARM_THRESHOLD.
// This prevents single weak-signal OUI matches from triggering false positives.

#define CONF_MAC_PREFIX       40   // Known OUI prefix match
#define CONF_SSID_PATTERN     50   // SSID matches known Flock pattern
#define CONF_BLE_NAME         45   // BLE device name matches known pattern
#define CONF_MFG_ID           60   // Manufacturer company ID 0x09C8 (XUNTONG) - very specific
#define CONF_RAVEN_UUID       70   // Raven service UUID match - highly specific
#define CONF_RAVEN_MULTI_UUID 90   // Multiple Raven UUIDs from one device - near certain
#define CONF_PENGUIN_SERIAL   80   // XUNTONG mfg data with TN serial number pattern

// Bonus modifiers
#define CONF_BONUS_STRONG_RSSI  10  // Signal > -50 dBm (very close)
#define CONF_BONUS_MULTI_METHOD 20  // Multiple independent methods match same device

// Thresholds
#define CONFIDENCE_ALARM_THRESHOLD 40   // Minimum to trigger alarm (allows single MAC match)
#define CONFIDENCE_HIGH    70   // "HIGH" confidence label
#define CONFIDENCE_CERTAIN 85   // "CERTAIN" confidence label

// ============================================================================
// DUAL-CORE & GLOBAL VARIABLES
// ============================================================================
TaskHandle_t ScannerTaskHandle;
SemaphoreHandle_t dataMutex; 

static uint8_t current_channel = 1;
static unsigned long last_channel_hop = 0;
static unsigned long last_ble_scan = 0;
static unsigned long last_buzzer_time = 0; 
static NimBLEScan* pBLEScan;
bool sd_available = false;
volatile bool trigger_alarm = false; 

std::vector<String> sd_write_buffer;
unsigned long last_sd_flush = 0;

String current_log_file = "/FlockLog_001.csv"; 

int current_screen = 0; 
unsigned long button_press_start = 0;
bool button_is_pressed = false;
bool stealth_mode = false; 

long session_wifi = 0;
long session_ble = 0;
unsigned long session_start_time = 0;
long lifetime_wifi = 0;
long lifetime_ble = 0;
unsigned long lifetime_seconds = 0;

// Seen-MAC ring buffer (bounded memory, O(1) insert)
#define MAX_SEEN_MACS 200
String seen_macs[MAX_SEEN_MACS];
int seen_macs_count = 0;
int seen_macs_write_idx = 0;

String last_cap_type = "None";
String last_cap_mac = "--:--:--:--:--:--";
int last_cap_rssi = 0;
int last_cap_confidence = 0;
String last_cap_time = "00:00:00";
String last_cap_det_method = "";
String live_logs[5] = {"", "", "", "", ""};

unsigned long last_uptime_update = 0;
unsigned long last_anim_update = 0;
unsigned long last_stats_update = 0;
unsigned long last_time_save = 0;
unsigned long last_log_update = 0; 
int scan_line_x = 0;

#define CHART_BARS 25
int activity_history[CHART_BARS] = {0};
unsigned long last_chart_update = 0;
long last_total_dets = 0;

long session_flock_wifi = 0;
long session_flock_ble = 0;
long session_raven = 0;

// ============================================================================
// UI BITMAPS
// ============================================================================
const unsigned char map_pin_icon[] PROGMEM = { 0x3C, 0x7E, 0x66, 0x66, 0x7E, 0x3C, 0x18, 0x00 };
const unsigned char clock_icon[] PROGMEM = { 0x3C, 0x42, 0x42, 0x52, 0x4A, 0x42, 0x3C, 0x00 };

// ============================================================================
// DETECTION SIGNATURE DATABASE
// ============================================================================

// --- WiFi SSID patterns (case-insensitive substring match) ---
static const char* wifi_ssid_patterns[] = { 
    "flock", "Flock", "FLOCK", 
    "FS Ext Battery", "FS_",
    "Penguin", "Pigvision",
    "FlockOS", "flocksafety",
};
static const int NUM_SSID_PATTERNS = sizeof(wifi_ssid_patterns) / sizeof(wifi_ssid_patterns[0]);

// --- MAC OUI prefixes ---
// Sourced from: deflock.me datasets, WiGLE.net verified captures, GainSec research,
// Ryan O'Horo's Falcon V2 hardware analysis, FlockBack project, Colonel Panic field data.
// 
// These cover: Flock camera mainboards, LiteOn WiFi/BT chipsets (WCBN3510A),
// Sierra Wireless LTE modems, Cradlepoint modems, Murata modules, Penguin batteries,
// and Espressif-based external battery modules.
static const char* mac_prefixes[] = { 
    // === Flock Safety direct / camera mainboard ===
    "58:8e:81",  "cc:cc:cc",  "ec:1b:bd",  "90:35:ea",
    "f0:82:c0",  "1c:34:f1",  "38:5b:44",  "94:34:69",
    "b4:e3:f9",  "3c:91:80",  "d8:f3:bc",  "80:30:49",
    "14:5a:fc",  "9c:2f:9d",  "94:08:53",  "e4:aa:ea",
    "48:e7:29",  // Newer hardware revision
    "c8:c9:a3",  // Condor PTZ models
    // === LiteOn Technology (WCBN3510A WiFi/BT in Falcon V2) ===
    "74:4c:a1",  "70:c9:4e",
    // === Cradlepoint / modem vendors ===
    "04:0d:84",
    // === Murata Manufacturing (BLE modules) ===
    "08:3a:88",
    // === Espressif (some Flock ext battery modules use ESP32) ===
    "a4:cf:12",
    // === Penguin battery BLE (random addresses start d8:a0:d8) ===
    "d8:a0:d8",
};
static const int NUM_MAC_PREFIXES = sizeof(mac_prefixes) / sizeof(mac_prefixes[0]);

// --- BLE device name patterns ---
// UPDATE 2025-03: Penguin firmware now drops "Penguin-" prefix.
// New Penguin name is just a 10-digit decimal number (e.g., "1234567890").
// We handle this separately with is_penguin_numeric_name() below.
static const char* device_name_patterns[] = { 
    "FS Ext Battery",
    "Penguin",          // Still catches older firmware with "Penguin-NNNNNNNNNN"
    "Flock",
    "Pigvision",
    "FlockCam",
    "FS-",
};
static const int NUM_NAME_PATTERNS = sizeof(device_name_patterns) / sizeof(device_name_patterns[0]);

// --- Raven BLE Service UUIDs (full set from GainSec raven_configurations.json) ---
static const char* raven_service_uuids[] = {
    "0000180a-0000-1000-8000-00805f9b34fb",  // Device Information
    "00003100-0000-1000-8000-00805f9b34fb",  // GPS Location
    "00003200-0000-1000-8000-00805f9b34fb",  // Power Management
    "00003300-0000-1000-8000-00805f9b34fb",  // Network Status
    "00003400-0000-1000-8000-00805f9b34fb",  // Upload Statistics
    "00003500-0000-1000-8000-00805f9b34fb",  // Error/Failure
    "00001809-0000-1000-8000-00805f9b34fb",  // Health Thermometer (legacy 1.1.x)
    "00001819-0000-1000-8000-00805f9b34fb",  // Location/Navigation (legacy 1.1.x)
};
static const int NUM_RAVEN_UUIDS = sizeof(raven_service_uuids) / sizeof(raven_service_uuids[0]);

#define FLOCK_MFG_COMPANY_ID 0x09C8

// ============================================================================
// HELPER FUNCTIONS
// ============================================================================

void beep(int frequency, int duration_ms) {
    tone(BUZZER_PIN, frequency, duration_ms);
    delay(duration_ms + 50);
}

void boot_beep_sequence() {
    beep(LOW_FREQ, BOOT_BEEP_DURATION);
    beep(HIGH_FREQ, BOOT_BEEP_DURATION);
}

void flush_sd_buffer() {
    xSemaphoreTake(dataMutex, portMAX_DELAY);
    if (sd_write_buffer.empty() || !sd_available) {
        xSemaphoreGive(dataMutex);
        return;
    }
    std::vector<String> temp_buffer = sd_write_buffer;
    sd_write_buffer.clear(); 
    xSemaphoreGive(dataMutex); 
    
    File file = SD.open(current_log_file.c_str(), FILE_APPEND);
    if (file) {
        for (const String &line : temp_buffer) { file.println(line); }
        file.close();
        last_sd_flush = millis();
    }
}

String format_time(unsigned long total_sec) {
    unsigned long m = (total_sec / 60) % 60;
    unsigned long h = (total_sec / 3600);
    if (h > 99) return String(h) + "h " + String(m) + "m";
    unsigned long s = total_sec % 60;
    char timeStr[10];
    sprintf(timeStr, "%02lu:%02lu:%02lu", h, m, s);
    return String(timeStr);
}

String short_mac(const String& mac) { 
    if (mac.length() > 8) return mac.substring(9);
    return mac;
}

String bytesToHexStr(const std::string& data) {
    String res = "";
    for (size_t i = 0; i < data.length(); i++) {
        char buf[4];
        sprintf(buf, "%02X", (uint8_t)data[i]);
        res += buf;
    }
    return res;
}

String get_gps_datetime() {
    if (!gps.date.isValid() || !gps.time.isValid()) return "No_GPS_Time";
    char dt[24];
    sprintf(dt, "%04d-%02d-%02d %02d:%02d:%02d", 
            gps.date.year(), gps.date.month(), gps.date.day(), 
            gps.time.hour(), gps.time.minute(), gps.time.second());
    return String(dt);
}

bool is_mac_seen(const String& mac) {
    int limit = min(seen_macs_count, MAX_SEEN_MACS);
    for (int i = 0; i < limit; i++) {
        if (seen_macs[i] == mac) return true;
    }
    return false;
}

void add_seen_mac(const String& mac) {
    seen_macs[seen_macs_write_idx] = mac;
    seen_macs_write_idx = (seen_macs_write_idx + 1) % MAX_SEEN_MACS;
    if (seen_macs_count < MAX_SEEN_MACS) seen_macs_count++;
}

// Returns confidence label string for OLED display
const char* confidence_label(int score) {
    if (score >= CONFIDENCE_CERTAIN) return "CERTAIN";
    if (score >= CONFIDENCE_HIGH) return "HIGH";
    if (score >= CONFIDENCE_ALARM_THRESHOLD) return "MEDIUM";
    return "LOW";
}

// ============================================================================
// PENGUIN NUMERIC NAME DETECTION
// ============================================================================
// As of March 2025, Penguin battery firmware dropped the "Penguin-" prefix.
// New BLE name is just a 10-digit decimal number (e.g., "1234567890").
// This alone is LOW confidence — could be any device with a numeric name.
// But combined with XUNTONG mfg ID (0x09C8), it becomes CERTAIN.

bool is_penguin_numeric_name(const char* name) {
    if (!name) return false;
    int len = strlen(name);
    if (len < 8 || len > 12) return false;  // Penguin serials are ~10 digits
    for (int i = 0; i < len; i++) {
        if (!isdigit(name[i])) return false;
    }
    return true;
}

// Check if XUNTONG mfg data contains a Flock TN-serial pattern
// Per GainSec: data includes serial like TN72023022000771 after the MAC bytes
bool has_tn_serial(const std::string& mfg_data) {
    if (mfg_data.length() < 10) return false;
    // Skip first 8 bytes (company ID + MAC echo), look for "TN" in ASCII
    for (size_t i = 8; i < mfg_data.length() - 1; i++) {
        if (mfg_data[i] == 'T' && mfg_data[i + 1] == 'N') return true;
    }
    return false;
}

// ============================================================================
// RAVEN FIRMWARE FINGERPRINTING
// ============================================================================

String classify_raven_firmware(NimBLEAdvertisedDevice* device) {
    if (!device || !device->haveServiceUUID()) return "Unknown";
    
    bool has_health = false, has_location = false;
    bool has_gps = false, has_power = false, has_network = false;
    bool has_upload = false, has_error = false;
    
    int count = device->getServiceUUIDCount();
    for (int i = 0; i < count; i++) {
        std::string uuid = device->getServiceUUID(i).toString();
        if (strcasestr(uuid.c_str(), "00001809")) has_health = true;
        if (strcasestr(uuid.c_str(), "00001819")) has_location = true;
        if (strcasestr(uuid.c_str(), "00003100")) has_gps = true;
        if (strcasestr(uuid.c_str(), "00003200")) has_power = true;
        if (strcasestr(uuid.c_str(), "00003300")) has_network = true;
        if (strcasestr(uuid.c_str(), "00003400")) has_upload = true;
        if (strcasestr(uuid.c_str(), "00003500")) has_error = true;
    }
    
    if (has_gps && has_power && has_network && has_upload && has_error) return "1.3.x";
    if (has_gps && has_power && has_network) return "1.2.x";
    if (has_health || has_location) return "1.1.x";
    return "Unknown";
}

// Count how many Raven UUIDs a device advertises (for confidence scoring)
int count_raven_uuids(NimBLEAdvertisedDevice* device) {
    if (!device || !device->haveServiceUUID()) return 0;
    int matched = 0;
    int count = device->getServiceUUIDCount();
    for (int i = 0; i < count; i++) {
        std::string uuid = device->getServiceUUID(i).toString();
        for (int j = 0; j < NUM_RAVEN_UUIDS; j++) {
            if (strcasecmp(uuid.c_str(), raven_service_uuids[j]) == 0) { matched++; break; }
        }
    }
    return matched;
}

// ============================================================================
// PATTERN MATCHING FUNCTIONS
// ============================================================================

bool check_mac_prefix(const uint8_t* mac) {
    char mac_str[9]; 
    snprintf(mac_str, sizeof(mac_str), "%02x:%02x:%02x", mac[0], mac[1], mac[2]);
    for (int i = 0; i < NUM_MAC_PREFIXES; i++) {
        if (strncasecmp(mac_str, mac_prefixes[i], 8) == 0) return true;
    }
    return false;
}

bool check_ssid_pattern(const char* ssid) {
    if (!ssid || strlen(ssid) == 0) return false;
    for (int i = 0; i < NUM_SSID_PATTERNS; i++) {
        if (strcasestr(ssid, wifi_ssid_patterns[i])) return true;
    }
    return false;
}

bool check_device_name_pattern(const char* name) {
    if (!name || strlen(name) == 0) return false;
    for (int i = 0; i < NUM_NAME_PATTERNS; i++) {
        if (strcasestr(name, device_name_patterns[i])) return true;
    }
    return false;
}

// Returns count of matched Raven UUIDs (0 = no match)
int check_raven_service_uuid(NimBLEAdvertisedDevice* device) {
    if (!device || !device->haveServiceUUID()) return 0;
    return count_raven_uuids(device);
}

bool check_manufacturer_id(const std::string& mfg_data) {
    if (mfg_data.length() >= 2) {
        uint16_t mfg_id = (uint8_t)mfg_data[0] | ((uint8_t)mfg_data[1] << 8);
        if (mfg_id == FLOCK_MFG_COMPANY_ID) return true;
    }
    return false;
}

// ============================================================================
// LOGGING & ALERTS (with confidence scoring)
// ============================================================================

void log_detection(const char* type, const char* proto, int rssi, const char* mac, 
                   const String& name, int channel, int tx_power, const String& extra_data,
                   const char* detection_method, int confidence) {
    String mac_str = String(mac);
    
    xSemaphoreTake(dataMutex, portMAX_DELAY);
    
    bool is_new = !is_mac_seen(mac_str);

    if (is_new) {
        add_seen_mac(mac_str);
        if (strcmp(proto, "WIFI") == 0) { session_wifi++; lifetime_wifi++; session_flock_wifi++; }
        else { session_ble++; lifetime_ble++; }
        if (strstr(type, "RAVEN") != NULL) { session_raven++; }
        else if (strcmp(proto, "BLE") == 0) { session_flock_ble++; }
    }

    last_cap_type = String(type);
    last_cap_mac = String(mac);
    last_cap_rssi = rssi;
    last_cap_confidence = confidence;
    last_cap_time = format_time((millis() - session_start_time) / 1000);
    last_cap_det_method = String(detection_method);

    // Build display log entry
    String logEntry;
    if (name != "Hidden" && name != "Unknown" && name != "") {
        String cleanName = name;
        if (cleanName.length() > 10) cleanName = cleanName.substring(0, 10);
        logEntry = "!" + cleanName + " " + String(confidence) + "%";
    } else {
        logEntry = "!" + String(proto) + " " + short_mac(mac_str) + " " + String(confidence) + "%";
    }
    
    if (millis() - last_log_update > LOG_UPDATE_DELAY) {
        for (int i = 4; i > 0; i--) { live_logs[i] = live_logs[i - 1]; }
        live_logs[0] = logEntry;
        last_log_update = millis();
    }
    
    // CSV logging to SD
    if (is_new && sd_available) {
        String clean_name = name; clean_name.replace(",", " "); 
        String clean_extra = extra_data; clean_extra.replace(",", " ");

        String csv_line;
        csv_line.reserve(200); 
        
        csv_line = String(millis()) + "," + get_gps_datetime() + "," + 
                   String(channel) + "," + String(type) + "," + String(proto) + "," + 
                   String(rssi) + "," + mac_str + "," + clean_name + "," + 
                   String(tx_power) + "," + String(detection_method) + "," +
                   String(confidence) + "," + String(confidence_label(confidence)) + "," +
                   clean_extra + ",";
        
        bool gps_is_fresh = gps.location.isValid() && (gps.location.age() < 2000);
        
        if (gps_is_fresh) {
            csv_line += String(gps.location.lat(), 6) + "," + String(gps.location.lng(), 6) + ",";
            csv_line += String(gps.speed.isValid() && gps.speed.age() < 2000 ? gps.speed.mph() : 0.0, 1) + ",";
            csv_line += String(gps.course.isValid() && gps.course.age() < 2000 ? gps.course.deg() : 0.0, 1) + ",";
            csv_line += String(gps.altitude.isValid() ? gps.altitude.meters() : 0.0, 1);
        } else {
            csv_line += "0.000000,0.000000,0.0,0.0,0.0"; 
        }
        sd_write_buffer.push_back(csv_line);
    }
    
    xSemaphoreGive(dataMutex); 
}

// ============================================================================
// CORE 0 SCANNER TASK
// ============================================================================
void ScannerLoopTask(void * pvParameters) {
    for (;;) {
        unsigned long now = millis();
        if (now - last_channel_hop > CHANNEL_HOP_INTERVAL) {
            current_channel++;
            if (current_channel > MAX_CHANNEL) current_channel = 1;
            esp_wifi_set_channel(current_channel, WIFI_SECOND_CHAN_NONE);
            last_channel_hop = now;
        }

        if (millis() - last_ble_scan >= BLE_SCAN_INTERVAL) {
            if (!pBLEScan->isScanning()) {
                pBLEScan->start(BLE_SCAN_DURATION, false);
                last_ble_scan = millis();
            }
        }
        if (!pBLEScan->isScanning() && (millis() - last_ble_scan > (unsigned long)(BLE_SCAN_DURATION * 1000 + 500))) {
            pBLEScan->clearResults();
        }
        
        vTaskDelay(10 / portTICK_PERIOD_MS); 
    }
}

// ============================================================================
// WIFI PACKET HANDLER (with confidence scoring)
// ============================================================================
typedef struct {
    unsigned frame_ctrl:16; unsigned duration_id:16;
    uint8_t addr1[6]; uint8_t addr2[6]; uint8_t addr3[6];
    unsigned sequence_ctrl:16; uint8_t addr4[6];
} wifi_ieee80211_mac_hdr_t;
typedef struct { wifi_ieee80211_mac_hdr_t hdr; uint8_t payload[0]; } wifi_ieee80211_packet_t;

void wifi_sniffer_packet_handler(void* buff, wifi_promiscuous_pkt_type_t type) {
    // PERF: Early exit for non-management frames at the type level
    if (type != WIFI_PKT_MGMT) return;
    
    const wifi_promiscuous_pkt_t *ppkt = (wifi_promiscuous_pkt_t *)buff;
    if (ppkt->rx_ctrl.sig_len < 24) return;
    
    const wifi_ieee80211_packet_t *ipkt = (wifi_ieee80211_packet_t *)ppkt->payload;
    const wifi_ieee80211_mac_hdr_t *hdr = &ipkt->hdr;
    
    uint8_t frame_type = (hdr->frame_ctrl & 0x0C) >> 2;
    uint8_t frame_subtype = (hdr->frame_ctrl & 0xF0) >> 4;
    
    if (frame_type != 0) return;
    bool is_beacon = (frame_subtype == 8);
    bool is_probe_req = (frame_subtype == 4);
    if (!is_beacon && !is_probe_req) return;
    
    // Extract SSID
    char ssid[33] = {0};
    uint8_t *frame_body = (uint8_t *)ipkt + 24;
    uint8_t *tagged_params;
    int remaining;
    
    if (is_beacon) {
        if (ppkt->rx_ctrl.sig_len < 24 + 12 + 2) return;
        tagged_params = frame_body + 12;
        remaining = ppkt->rx_ctrl.sig_len - 24 - 12 - 4;
    } else {
        tagged_params = frame_body;
        remaining = ppkt->rx_ctrl.sig_len - 24 - 4;
    }
    
    if (remaining > 2 && tagged_params[0] == 0 && tagged_params[1] <= 32 && tagged_params[1] <= remaining - 2) {
        memcpy(ssid, &tagged_params[2], tagged_params[1]);
        ssid[tagged_params[1]] = '\0';
    }
    
    // --- Confidence scoring for WiFi ---
    int confidence = 0;
    String methods = "";
    
    bool ssid_match = (strlen(ssid) > 0 && check_ssid_pattern(ssid));
    bool mac_match = check_mac_prefix(hdr->addr2);
    
    if (ssid_match) { confidence += CONF_SSID_PATTERN; methods += "ssid "; }
    if (mac_match)  { confidence += CONF_MAC_PREFIX;    methods += "mac "; }
    
    // Bonus: both methods matched independently
    if (ssid_match && mac_match) confidence += CONF_BONUS_MULTI_METHOD;
    
    // Bonus: strong signal
    if (ppkt->rx_ctrl.rssi > -50) confidence += CONF_BONUS_STRONG_RSSI;

    char mac_str[18]; 
    snprintf(mac_str, sizeof(mac_str), "%02x:%02x:%02x:%02x:%02x:%02x", 
             hdr->addr2[0], hdr->addr2[1], hdr->addr2[2], 
             hdr->addr2[3], hdr->addr2[4], hdr->addr2[5]);
    String name_str = strlen(ssid) > 0 ? String(ssid) : "Hidden";
    String frame_type_str = is_beacon ? "Beacon" : "ProbeReq";

    if (confidence >= CONFIDENCE_ALARM_THRESHOLD) {
        methods.trim();
        log_detection("FLOCK_WIFI", "WIFI", ppkt->rx_ctrl.rssi, mac_str, name_str, 
                      ppkt->rx_ctrl.channel, 0, frame_type_str, methods.c_str(), confidence);
        if (millis() - last_buzzer_time > BUZZER_COOLDOWN || last_buzzer_time == 0) {
            trigger_alarm = true; last_buzzer_time = millis();
        }
    } else if (ppkt->rx_ctrl.rssi > IGNORE_WEAK_RSSI) {
        if (millis() - last_log_update > LOG_UPDATE_DELAY) {
            xSemaphoreTake(dataMutex, portMAX_DELAY);
            String logEntry;
            if (name_str != "Hidden" && name_str != "") {
                String cleanName = name_str; 
                if (cleanName.length() > 12) cleanName = cleanName.substring(0, 12);
                logEntry = cleanName + " (" + String(ppkt->rx_ctrl.rssi) + ")";
            } else {
                logEntry = "WiFi " + short_mac(String(mac_str)) + " (" + String(ppkt->rx_ctrl.rssi) + ")";
            }
            for (int i = 4; i > 0; i--) { live_logs[i] = live_logs[i - 1]; }
            live_logs[0] = logEntry;
            last_log_update = millis();
            xSemaphoreGive(dataMutex);
        }
    }
}

// ============================================================================
// BLE CALLBACK (with confidence scoring)
// ============================================================================
class AdvertisedDeviceCallbacks: public NimBLEAdvertisedDeviceCallbacks {
    void onResult(NimBLEAdvertisedDevice* advertisedDevice) {
        NimBLEAddress addr = advertisedDevice->getAddress();
        uint8_t mac[6]; 
        sscanf(addr.toString().c_str(), "%02x:%02x:%02x:%02x:%02x:%02x", 
               &mac[0], &mac[1], &mac[2], &mac[3], &mac[4], &mac[5]);
        
        // --- Build confidence score from multiple independent signals ---
        int confidence = 0;
        String methods = "";
        String capture_type = "FLOCK_BLE";
        bool has_xuntong = false;
        
        // Check MAC prefix
        if (check_mac_prefix(mac)) { 
            confidence += CONF_MAC_PREFIX; 
            methods += "mac ";
        }
        
        // Check device name
        String dev_name = advertisedDevice->haveName() ? String(advertisedDevice->getName().c_str()) : "Unknown";
        if (advertisedDevice->haveName()) {
            if (check_device_name_pattern(advertisedDevice->getName().c_str())) {
                confidence += CONF_BLE_NAME;
                methods += "name ";
            }
            // Check for updated Penguin numeric-only name
            else if (is_penguin_numeric_name(advertisedDevice->getName().c_str())) {
                // Low confidence alone — could be any device with a numeric name
                // Will be boosted significantly if paired with XUNTONG mfg ID below
                confidence += 15;
                methods += "penguin_num ";
            }
        }
        
        // Check manufacturer company ID
        if (advertisedDevice->haveManufacturerData()) {
            std::string mfg = advertisedDevice->getManufacturerData();
            if (check_manufacturer_id(mfg)) {
                has_xuntong = true;
                confidence += CONF_MFG_ID;
                methods += "mfg_0x09C8 ";
                
                // Extra: check for TN serial in mfg data (very specific to Flock)
                if (has_tn_serial(mfg)) {
                    confidence += CONF_PENGUIN_SERIAL - CONF_MFG_ID; // Add difference to avoid double-counting
                    methods += "tn_serial ";
                }
            }
        }
        
        // Check Raven UUIDs
        int raven_uuid_count = check_raven_service_uuid(advertisedDevice);
        if (raven_uuid_count > 0) {
            capture_type = "RAVEN_BLE";
            if (raven_uuid_count >= 3) {
                confidence += CONF_RAVEN_MULTI_UUID;
                methods += "raven_multi ";
            } else {
                confidence += CONF_RAVEN_UUID;
                methods += "raven_uuid ";
            }
        }
        
        // Bonus: multiple independent methods
        int method_count = 0;
        if (methods.indexOf("mac") >= 0) method_count++;
        if (methods.indexOf("name") >= 0 || methods.indexOf("penguin_num") >= 0) method_count++;
        if (methods.indexOf("mfg_") >= 0) method_count++;
        if (methods.indexOf("raven") >= 0) method_count++;
        if (method_count >= 2) confidence += CONF_BONUS_MULTI_METHOD;
        
        // Bonus: strong signal
        if (advertisedDevice->getRSSI() > -50) confidence += CONF_BONUS_STRONG_RSSI;
        
        // Cap at 100
        if (confidence > 100) confidence = 100;

        if (confidence >= CONFIDENCE_ALARM_THRESHOLD) {
            int tx_power = advertisedDevice->haveTXPower() ? advertisedDevice->getTXPower() : 0;
            String mfg_data_hex = advertisedDevice->haveManufacturerData() ? 
                bytesToHexStr(advertisedDevice->getManufacturerData()) : "";
            
            // Build extra data
            String extra_data = mfg_data_hex;
            if (capture_type == "RAVEN_BLE") {
                String fw_ver = classify_raven_firmware(advertisedDevice);
                extra_data = "FW:" + fw_ver + " UUIDs:" + String(raven_uuid_count);
                if (advertisedDevice->haveServiceUUID()) {
                    extra_data += " SVCS:";
                    int svc_count = advertisedDevice->getServiceUUIDCount();
                    for (int i = 0; i < svc_count && i < 8; i++) {
                        if (i > 0) extra_data += "|";
                        std::string u = advertisedDevice->getServiceUUID(i).toString();
                        extra_data += String(u.c_str()).substring(0, 8);
                    }
                }
            }
            
            methods.trim();
            log_detection(capture_type.c_str(), "BLE", advertisedDevice->getRSSI(), 
                          addr.toString().c_str(), dev_name, 0, tx_power, extra_data, 
                          methods.c_str(), confidence);
            
            if (millis() - last_buzzer_time > BUZZER_COOLDOWN || last_buzzer_time == 0) {
                trigger_alarm = true; last_buzzer_time = millis();
            }
        } else if (advertisedDevice->getRSSI() > IGNORE_WEAK_RSSI) {
            if (millis() - last_log_update > LOG_UPDATE_DELAY) {
                xSemaphoreTake(dataMutex, portMAX_DELAY);
                String logEntry;
                if (dev_name != "Unknown" && dev_name != "") {
                    String cleanName = dev_name; 
                    if (cleanName.length() > 12) cleanName = cleanName.substring(0, 12);
                    logEntry = cleanName + " (" + String(advertisedDevice->getRSSI()) + ")";
                } else {
                    logEntry = "BLE " + short_mac(String(addr.toString().c_str())) + " (" + String(advertisedDevice->getRSSI()) + ")";
                }
                for (int i = 4; i > 0; i--) { live_logs[i] = live_logs[i - 1]; }
                live_logs[0] = logEntry;
                last_log_update = millis();
                xSemaphoreGive(dataMutex);
            }
        }
    }
};

// ============================================================================
// UI SCREENS
// ============================================================================

void draw_header() {
    display.setTextSize(1); display.setTextColor(SSD1306_WHITE); display.setCursor(0, 0); 
    display.println(F("Flock Detection"));
    display.drawLine(0, 10, 128, 10, SSD1306_WHITE);
    int sats = gps.satellites.isValid() ? gps.satellites.value() : 0;
    String sat_str = String(sats);
    int16_t x1, y1; uint16_t w, h;
    display.getTextBounds(sat_str, 0, 0, &x1, &y1, &w, &h);
    display.drawBitmap(128 - w - 10, 0, map_pin_icon, 8, 8, SSD1306_WHITE);
    display.setCursor(128 - w, 0); display.print(sat_str);
}

void update_animation() {
    int y_min = 28, y_max = 52;
    display.drawFastVLine(scan_line_x, y_min, (y_max - y_min), SSD1306_BLACK);
    display.drawFastVLine(scan_line_x + 1, y_min, (y_max - y_min), SSD1306_BLACK);
    display.drawFastVLine(scan_line_x + 2, y_min, (y_max - y_min), SSD1306_BLACK);
    display.drawFastVLine(scan_line_x + 3, y_min, (y_max - y_min), SSD1306_BLACK);
    if (random(0, 100) < 75) display.drawPixel(random(0, 128), random(y_min, y_max), SSD1306_WHITE);
    scan_line_x += 4; if (scan_line_x >= 128) scan_line_x = 0;
    display.drawFastVLine(scan_line_x, y_min, (y_max - y_min), SSD1306_WHITE);
    display.display();
}

void draw_scanner_screen() {
    if (millis() - last_uptime_update > 1000) {
        display.fillRect(0, 56, 128, 8, SSD1306_BLACK);
        display.drawBitmap(0, 56, clock_icon, 8, 8, SSD1306_WHITE);
        display.setCursor(12, 56);
        display.print(format_time((millis() - session_start_time) / 1000));
        if (sd_available) { display.setCursor(100, 56); display.print(F("SD:OK")); }
        display.fillRect(0, 16, 128, 10, SSD1306_BLACK); display.setCursor(0, 16);
        if (pBLEScan->isScanning()) display.print(F("Scanning: BLE..."));
        else { display.print(F("Scan Ch:")); display.print(current_channel); display.print(F(" WiFi")); }
        display.fillRect(100, 0, 28, 10, SSD1306_BLACK); 
        int sats = gps.satellites.isValid() ? gps.satellites.value() : 0;
        String sat_str = String(sats);
        int16_t x1, y1; uint16_t w, h;
        display.getTextBounds(sat_str, 0, 0, &x1, &y1, &w, &h);
        display.drawBitmap(128 - w - 10, 0, map_pin_icon, 8, 8, SSD1306_WHITE);
        display.setCursor(128 - w, 0); display.print(sat_str);
        display.display();
        last_uptime_update = millis();
    }
}

void draw_stats_screen() {
    if (millis() - last_stats_update > 500) {
        xSemaphoreTake(dataMutex, portMAX_DELAY); 
        long tw = session_flock_wifi, tb = session_flock_ble, tr = session_raven;
        long lw = lifetime_wifi, lb = lifetime_ble;
        xSemaphoreGive(dataMutex);
        display.clearDisplay(); draw_header();
        display.setCursor(0, 13); display.print(F("Detections"));
        display.setCursor(50, 24); display.print(F("SESS"));  display.setCursor(90, 24); display.print(F("ALL"));
        display.setCursor(0, 34); display.print(F("WiFi:"));  display.setCursor(50, 34); display.print(tw); display.setCursor(90, 34); display.print(lw);
        display.setCursor(0, 44); display.print(F("BLE:"));   display.setCursor(50, 44); display.print(tb); display.setCursor(90, 44); display.print(lb);
        display.setCursor(0, 54); display.print(F("Raven:")); display.setCursor(50, 54); display.print(tr);
        display.display(); last_stats_update = millis();
    }
}

void draw_last_capture_screen() {
    if (millis() - last_stats_update > 500) {
        xSemaphoreTake(dataMutex, portMAX_DELAY);
        String t_type = last_cap_type, t_time = last_cap_time;
        String t_mac = last_cap_mac, t_method = last_cap_det_method;
        int t_rssi = last_cap_rssi, t_conf = last_cap_confidence;
        xSemaphoreGive(dataMutex);
        display.clearDisplay(); draw_header();
        display.setCursor(0, 13); display.print(F("Last Capture"));
        if (t_type == "None") { 
            display.setCursor(0, 35); display.print(F("NO DATA YET")); 
        } else {
            display.setCursor(0, 24); display.print(F("T:")); display.print(t_time);
            display.setCursor(64, 24); display.print(F("R:")); display.print(t_rssi);
            display.setCursor(0, 34); display.print(t_type);
            display.setCursor(0, 44); display.print(t_mac);
            // Show confidence score + label
            display.setCursor(0, 54); 
            display.print(F("Conf: ")); display.print(t_conf); display.print(F("% "));
            display.print(confidence_label(t_conf));
        }
        display.display(); last_stats_update = millis();
    }
}

void draw_live_log_screen() {
    if (millis() - last_stats_update > 100) {
        xSemaphoreTake(dataMutex, portMAX_DELAY);
        String t_logs[5]; for (int i = 0; i < 5; i++) t_logs[i] = live_logs[i];
        xSemaphoreGive(dataMutex);
        display.clearDisplay(); draw_header();
        display.setCursor(0, 13); display.print(F("Live Feed"));
        int y = 24;
        for (int i = 0; i < 5; i++) {
            if (t_logs[i] != "") {
                display.setCursor(0, y);
                if (t_logs[i].startsWith("!")) display.setTextColor(SSD1306_INVERSE);
                else display.setTextColor(SSD1306_WHITE);
                display.print(t_logs[i]); display.setTextColor(SSD1306_WHITE); y += 8;
            }
        }
        display.display(); last_stats_update = millis();
    }
}

void draw_gps_screen() {
    if (millis() - last_stats_update > 500) {
        display.clearDisplay(); draw_header();
        display.setCursor(0, 13); display.print(F("GPS Coordinates"));
        bool has_location = gps.location.isValid();
        bool is_stale = has_location && (gps.location.age() > 2000);
        if (has_location && !is_stale) {
            display.setCursor(0, 26); display.print(F("Lat: ")); display.print(gps.location.lat(), 6);
            display.setCursor(0, 38); display.print(F("Lon: ")); display.print(gps.location.lng(), 6);
            display.setCursor(0, 50); display.print(F("Spd: ")); display.print(gps.speed.mph(), 1); 
            display.print(F(" Hdg: ")); display.print(gps.course.deg(), 0);
        } else if (has_location && is_stale) {
            display.setCursor(0, 26); display.print(F("STATUS: SIGNAL LOST"));
            display.setCursor(0, 38); display.print(F("Last Lock: ")); 
            display.print(gps.location.age() / 1000); display.print(F("s ago"));
            display.setCursor(0, 50); display.print(F("Waiting for sats..."));
        } else {
            int sats = gps.satellites.isValid() ? gps.satellites.value() : 0;
            display.setCursor(0, 24); display.print(F("Status: Searching Sky"));
            display.setCursor(0, 36); display.print(F("Sats: ")); display.print(sats); display.print(F(" / 4 Req"));
            display.setCursor(0, 48); display.print(F("Rx: ")); display.print(gps.charsProcessed()); display.print(F(" bytes"));
        }
        display.display(); last_stats_update = millis();
    }
}

void draw_chart_screen() {
    if (millis() - last_stats_update > 500) {
        display.clearDisplay(); draw_header();
        display.setCursor(0, 13); display.print(F("Activity (Last 25s)"));
        int max_val = 1; 
        for (int i = 0; i < CHART_BARS; i++) {
            if (activity_history[i] > max_val) max_val = activity_history[i];
        }
        for (int i = 0; i < CHART_BARS; i++) {
            int bar_h = (activity_history[i] * 35) / max_val;
            int x = i * 5;
            display.fillRect(x, 64 - bar_h, 4, bar_h, SSD1306_WHITE);
        }
        display.display(); last_stats_update = millis();
    }
}

void draw_proximity_screen() {
    if (millis() - last_stats_update > 250) {
        xSemaphoreTake(dataMutex, portMAX_DELAY);
        int rssi = last_cap_rssi;
        String cap_type = last_cap_type;
        int conf = last_cap_confidence;
        xSemaphoreGive(dataMutex);
        display.clearDisplay(); draw_header();
        display.setCursor(0, 13); display.print(F("Signal Proximity"));
        if (cap_type == "None") {
            display.setCursor(0, 35); display.print(F("NO DATA YET"));
        } else {
            int pct = constrain(map(rssi, -100, -30, 0, 100), 0, 100);
            int bar_w = (pct * 120) / 100;
            display.setCursor(0, 24); 
            display.print(F("RSSI: ")); display.print(rssi); display.print(F("dBm "));
            display.print(conf); display.print(F("%"));
            display.drawRect(3, 36, 122, 12, SSD1306_WHITE);
            if (bar_w > 0) display.fillRect(4, 37, bar_w, 10, SSD1306_WHITE);
            display.setCursor(0, 52);
            if (pct > 75) display.print(F(">> VERY CLOSE <<"));
            else if (pct > 50) display.print(F("> NEARBY <"));
            else if (pct > 25) display.print(F("Moderate range"));
            else display.print(F("Weak / distant"));
        }
        display.display(); last_stats_update = millis();
    }
}

void refresh_screen_layout() {
    if (stealth_mode) return;
    display.clearDisplay(); draw_header(); display.display();
}

// ============================================================================
// SETUP
// ============================================================================

void setup() {
    Serial.begin(115200); 
    SerialGPS.begin(GPS_BAUD, SERIAL_8N1, RX_PIN, TX_PIN);
    setCpuFrequencyMhz(240); 
    dataMutex = xSemaphoreCreateMutex();
    
    pinMode(BUZZER_PIN, OUTPUT); digitalWrite(BUZZER_PIN, LOW);
    pinMode(BUTTON_PIN, INPUT_PULLUP);
    pinMode(SD_CS_PIN, OUTPUT); digitalWrite(SD_CS_PIN, HIGH); 
    SPI.begin(); 

    if (!display.begin(SSD1306_SWITCHCAPVCC, SCREEN_ADDRESS)) { 
        Serial.println(F("SSD1306 failed")); 
    }
    Wire.setClock(400000); display.setRotation(2); 
    
    // SD card init with retry
    bool mount_success = false;
    for (int i = 0; i < 3; i++) { 
        if (SD.begin(SD_CS_PIN)) { mount_success = true; break; } 
        delay(100); 
    }
    if (mount_success) {
        sd_available = true;
        int file_num = 1;
        char file_name[32];
        while (file_num <= 999) {
            sprintf(file_name, "/FlockLog_%03d.csv", file_num);
            if (!SD.exists(file_name)) { current_log_file = String(file_name); break; }
            file_num++;
        }
        File file = SD.open(current_log_file.c_str(), FILE_WRITE);
        if (file) { 
            file.println("Uptime_ms,Date_Time,Channel,Capture_Type,Protocol,RSSI,MAC_Address,Device_Name,TX_Power,Detection_Method,Confidence,Confidence_Label,Extra_Data,Latitude,Longitude,Speed_MPH,Heading_Deg,Altitude_M"); 
            file.close(); 
        }
        Serial.print(F("Logging to: ")); Serial.println(current_log_file);
    }
    
    session_start_time = millis(); refresh_screen_layout();

    // WiFi promiscuous mode
    WiFi.mode(WIFI_STA); WiFi.disconnect(); 
    esp_wifi_set_ps(WIFI_PS_NONE); 
    
    // PERF: Set promiscuous filter to only receive management frames
    wifi_promiscuous_filter_t filt;
    filt.filter_mask = WIFI_PROMIS_FILTER_MASK_MGMT;
    esp_wifi_set_promiscuous_filter(&filt);
    
    esp_wifi_set_promiscuous(true); 
    esp_wifi_set_promiscuous_rx_cb(&wifi_sniffer_packet_handler);
    esp_wifi_set_channel(current_channel, WIFI_SECOND_CHAN_NONE);
    
    // BLE setup
    NimBLEDevice::init(""); 
    NimBLEDevice::setPower(ESP_PWR_LVL_P9); 
    pBLEScan = NimBLEDevice::getScan(); 
    pBLEScan->setAdvertisedDeviceCallbacks(new AdvertisedDeviceCallbacks(), false); // false = don't report duplicates
    pBLEScan->setActiveScan(true); 
    pBLEScan->setInterval(97);   // PERF: Prime number intervals reduce aliasing with advert intervals
    pBLEScan->setWindow(97);     // PERF: 100% duty cycle scan window

    boot_beep_sequence();
    last_channel_hop = millis(); last_sd_flush = millis();

    xTaskCreatePinnedToCore(ScannerLoopTask, "ScannerTask", 8192, NULL, 1, &ScannerTaskHandle, 0);
    
    Serial.println(F("=== Flock Detector v2.1 — Confidence Scoring ==="));
    Serial.print(F("MAC prefixes: ")); Serial.println(NUM_MAC_PREFIXES);
    Serial.print(F("SSID patterns: ")); Serial.println(NUM_SSID_PATTERNS);
    Serial.print(F("BLE name patterns: ")); Serial.println(NUM_NAME_PATTERNS);
    Serial.print(F("Raven UUIDs: ")); Serial.println(NUM_RAVEN_UUIDS);
    Serial.print(F("Alarm threshold: ")); Serial.print(CONFIDENCE_ALARM_THRESHOLD); Serial.println(F("%"));
}

// ============================================================================
// MAIN LOOP
// ============================================================================

#define NUM_SCREENS 7

void loop() {
    // Feed GPS parser
    while (SerialGPS.available() > 0) { 
        gps.encode(SerialGPS.read()); 
        yield(); 
    }

    // Activity chart
    if (millis() - last_chart_update >= 1000) {
        last_chart_update = millis();
        xSemaphoreTake(dataMutex, portMAX_DELAY);
        long current_total = session_wifi + session_ble;
        xSemaphoreGive(dataMutex);
        int new_dets = current_total - last_total_dets;
        last_total_dets = current_total;
        for (int i = 0; i < CHART_BARS - 1; i++) activity_history[i] = activity_history[i + 1];
        activity_history[CHART_BARS - 1] = new_dets;
    }

    // Alarm
    if (trigger_alarm) {
        trigger_alarm = false; 
        for (int i = 0; i < 3; i++) {
            if (!stealth_mode) display.invertDisplay(true);
            if (!stealth_mode) tone(BUZZER_PIN, DETECT_FREQ); 
            delay(DETECT_BEEP_DURATION);
            noTone(BUZZER_PIN);
            if (!stealth_mode) display.invertDisplay(false);
            if (i < 2) delay(50);
        }
    }

    // Button
    bool current_button_state = (digitalRead(BUTTON_PIN) == LOW);
    if (current_button_state && !button_is_pressed) {
        button_press_start = millis();
        button_is_pressed = true;
    } else if (!current_button_state && button_is_pressed) {
        unsigned long press_duration = millis() - button_press_start;
        button_is_pressed = false;
        if (press_duration > 1000) {
            stealth_mode = !stealth_mode;
            display.ssd1306_command(stealth_mode ? SSD1306_DISPLAYOFF : SSD1306_DISPLAYON);
            if (!stealth_mode) refresh_screen_layout();
        } else if (press_duration > 50 && !stealth_mode) {
            current_screen++;
            if (current_screen >= NUM_SCREENS) current_screen = 0;
            refresh_screen_layout();
        }
    }

    if (millis() - last_time_save >= 1000) { lifetime_seconds++; last_time_save = millis(); }

    // SD flush
    xSemaphoreTake(dataMutex, portMAX_DELAY);
    bool should_flush = (sd_write_buffer.size() >= MAX_LOG_BUFFER || 
                         (millis() - last_sd_flush > SD_FLUSH_INTERVAL && !sd_write_buffer.empty()));
    xSemaphoreGive(dataMutex);
    if (should_flush) flush_sd_buffer();

    // Screen rendering
    if (!stealth_mode) {
        switch (current_screen) {
            case 0:
                draw_scanner_screen();
                if (millis() - last_anim_update > 40) { update_animation(); last_anim_update = millis(); }
                break;
            case 1: draw_stats_screen(); break;
            case 2: draw_last_capture_screen(); break;
            case 3: draw_live_log_screen(); break;
            case 4: draw_gps_screen(); break;
            case 5: draw_chart_screen(); break;
            case 6: draw_proximity_screen(); break;
        }
    }
    
    vTaskDelay(10 / portTICK_PERIOD_MS);
}
