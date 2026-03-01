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
#define CHANNEL_HOP_INTERVAL 500
#define BLE_SCAN_DURATION 1
#define BLE_SCAN_INTERVAL 5000
#define BUZZER_COOLDOWN 60000 
#define LOG_UPDATE_DELAY 1000 
#define IGNORE_WEAK_RSSI -80  

#define MAX_LOG_BUFFER 10          
#define SD_FLUSH_INTERVAL 10000    

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

std::vector<String> seen_macs;

String last_cap_type = "None";
String last_cap_mac = "--:--:--:--:--:--";
int last_cap_rssi = 0;
String last_cap_time = "00:00:00";
String live_logs[5] = {"", "", "", "", ""};

unsigned long last_uptime_update = 0;
unsigned long last_anim_update = 0;
unsigned long last_stats_update = 0;
unsigned long last_time_save = 0;
unsigned long last_log_update = 0; 
int scan_line_x = 0;

// <-- NEW: Variables for the live bar chart
#define CHART_BARS 25
int activity_history[CHART_BARS] = {0};
unsigned long last_chart_update = 0;
long last_total_dets = 0;

// ============================================================================
// UI BITMAPS & PATTERNS
// ============================================================================
const unsigned char map_pin_icon[] PROGMEM = { 0x3C, 0x7E, 0x66, 0x66, 0x7E, 0x3C, 0x18, 0x00 };
const unsigned char clock_icon[] PROGMEM ={ 0x3C, 0x42, 0x42, 0x52, 0x4A, 0x42, 0x3C, 0x00 };

static const char* wifi_ssid_patterns[] = { "flock", "Flock", "FLOCK", "FS Ext Battery", "Penguin", "Pigvision" };
static const char* mac_prefixes[] = { 
    "58:8e:81", "cc:cc:cc", "ec:1b:bd", "90:35:ea", "04:0d:84", "f0:82:c0", "1c:34:f1", "38:5b:44", "94:34:69", "b4:e3:f9",
    "70:c9:4e", "3c:91:80", "d8:f3:bc", "80:30:49", "14:5a:fc", "74:4c:a1", "08:3a:88", "9c:2f:9d", "94:08:53", "e4:aa:ea"
};
static const char* device_name_patterns[] = { "FS Ext Battery", "Penguin", "Flock", "Pigvision" };
#define RAVEN_GPS_SERVICE "00003100-0000-1000-8000-00805f9b34fb"
static const char* raven_service_uuids[] = { "0000180a-0000-1000-8000-00805f9b34fb", RAVEN_GPS_SERVICE };

// ============================================================================
// SYSTEM & FILE FUNCTIONS
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
        for (const String &line : temp_buffer) {
            file.println(line);
        }
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
    for(int i=0; i<data.length(); i++) {
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

// ============================================================================
// LOGGING & ALERTS
// ============================================================================

void log_detection(const char* type, const char* proto, int rssi, const char* mac, const String& name, int channel, int tx_power, const String& extra_data) {
    String mac_str = String(mac);
    bool is_new = true;

    xSemaphoreTake(dataMutex, portMAX_DELAY);

    for (int i = 0; i < seen_macs.size(); i++) {
        if (seen_macs[i] == mac_str) { is_new = false; break; }
    }

    if (is_new) {
        seen_macs.push_back(mac_str);
        if (seen_macs.size() > 100) seen_macs.erase(seen_macs.begin()); 
        if (strcmp(proto, "WIFI") == 0) { session_wifi++; lifetime_wifi++; }
        else { session_ble++; lifetime_ble++; }
    }

    last_cap_type = String(type);
    last_cap_mac = String(mac);
    last_cap_rssi = rssi;
    last_cap_time = format_time((millis()-session_start_time)/1000);

    String displayMac = mac_str.substring(9); 
    String logEntry;
    if (name != "Hidden" && name != "Unknown" && name != "") {
        String cleanName = name;
        if (cleanName.length() > 12) cleanName = cleanName.substring(0, 12);
        logEntry = "!" + cleanName + " (" + String(rssi) + ")";
    } else {
        logEntry = "!" + String(proto) + " " + short_mac(mac_str) + " (" + String(rssi) + ")";
    }
    
    if (millis() - last_log_update > LOG_UPDATE_DELAY) {
        for (int i = 4; i > 0; i--) { live_logs[i] = live_logs[i-1]; }
        live_logs[0] = logEntry;
        last_log_update = millis();
    }
    
    if (is_new && sd_available) {
        String clean_name = name; clean_name.replace(",", " "); 
        String clean_extra = extra_data; clean_extra.replace(",", " ");

        String csv_line;
        csv_line.reserve(150); 
        
        csv_line = String(millis()) + "," + get_gps_datetime() + "," + 
                   String(channel) + "," + String(type) + "," + String(proto) + "," + 
                   String(rssi) + "," + mac_str + "," + clean_name + "," + 
                   String(tx_power) + "," + clean_extra + ",";
        
        bool gps_is_fresh = gps.location.isValid() && (gps.location.age() < 2000);
        
        if (gps_is_fresh) {
            csv_line += String(gps.location.lat(), 6) + "," + String(gps.location.lng(), 6) + ",";
            csv_line += String(gps.speed.isValid() && gps.speed.age() < 2000 ? gps.speed.mph() : 0.0, 1) + ",";
            csv_line += String(gps.course.isValid() && gps.course.age() < 2000 ? gps.course.deg() : 0.0, 1);
        } else {
            csv_line += "0.000000,0.000000,0.0,0.0"; 
        }
        sd_write_buffer.push_back(csv_line);
    }
    
    xSemaphoreGive(dataMutex); 
}

// ============================================================================
// CORE 0 (PRO_CPU) - THE DEDICATED SCANNER TASK
// ============================================================================
void ScannerLoopTask(void * pvParameters) {
    for(;;) {
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
        if (!pBLEScan->isScanning() && (millis() - last_ble_scan > 1000)) {
            pBLEScan->clearResults();
        }
        
        vTaskDelay(10 / portTICK_PERIOD_MS); 
    }
}

// ============================================================================
// PACKET HANDLERS
// ============================================================================
typedef struct {
    unsigned frame_ctrl:16; unsigned duration_id:16;
    uint8_t addr1[6]; uint8_t addr2[6]; uint8_t addr3[6];
    unsigned sequence_ctrl:16; uint8_t addr4[6];
} wifi_ieee80211_mac_hdr_t;

typedef struct { wifi_ieee80211_mac_hdr_t hdr; uint8_t payload[0]; } wifi_ieee80211_packet_t;

bool check_mac_prefix(const uint8_t* mac) {
    char mac_str[9]; snprintf(mac_str, sizeof(mac_str), "%02x:%02x:%02x", mac[0], mac[1], mac[2]);
    for (int i = 0; i < sizeof(mac_prefixes)/sizeof(mac_prefixes[0]); i++) {
        if (strncasecmp(mac_str, mac_prefixes[i], 8) == 0) return true;
    } return false;
}
bool check_ssid_pattern(const char* ssid) {
    if (!ssid) return false;
    for (int i = 0; i < sizeof(wifi_ssid_patterns)/sizeof(wifi_ssid_patterns[0]); i++) {
        if (strcasestr(ssid, wifi_ssid_patterns[i])) return true;
    } return false;
}
bool check_device_name_pattern(const char* name) {
    if (!name) return false;
    for (int i = 0; i < sizeof(device_name_patterns)/sizeof(device_name_patterns[0]); i++) {
        if (strcasestr(name, device_name_patterns[i])) return true;
    } return false;
}
bool check_raven_service_uuid(NimBLEAdvertisedDevice* device) {
    if (!device || !device->haveServiceUUID()) return false;
    int count = device->getServiceUUIDCount();
    for (int i = 0; i < count; i++) {
        std::string uuid = device->getServiceUUID(i).toString();
        for (int j = 0; j < sizeof(raven_service_uuids)/sizeof(raven_service_uuids[0]); j++) {
            if (strcasecmp(uuid.c_str(), raven_service_uuids[j]) == 0) return true;
        }
    } return false;
}
bool check_manufacturer_id(const std::string& mfg_data) {
    if (mfg_data.length() >= 2) {
        uint16_t mfg_id = (uint8_t)mfg_data[0] | ((uint8_t)mfg_data[1] << 8);
        if (mfg_id == 0x09C8) return true;
    } return false;
}

void wifi_sniffer_packet_handler(void* buff, wifi_promiscuous_pkt_type_t type) {
    const wifi_promiscuous_pkt_t *ppkt = (wifi_promiscuous_pkt_t *)buff;
    const wifi_ieee80211_packet_t *ipkt = (wifi_ieee80211_packet_t *)ppkt->payload;
    const wifi_ieee80211_mac_hdr_t *hdr = &ipkt->hdr;
    uint8_t frame_type = (hdr->frame_ctrl & 0xFF) >> 2;
    if (frame_type != 0x20 && frame_type != 0x80) return;
    
    char ssid[33] = {0}; uint8_t *payload = (uint8_t *)ipkt + 24;
    if (frame_type == 0x20) payload += 0; else payload += 12;
    if (payload[0] == 0 && payload[1] <= 32) { memcpy(ssid, &payload[2], payload[1]); ssid[payload[1]] = '\0'; }
    
    bool match = false;
    if (strlen(ssid) > 0 && check_ssid_pattern(ssid)) match = true;
    else if (check_mac_prefix(hdr->addr2)) match = true;

    char mac_str[18]; snprintf(mac_str, sizeof(mac_str), "%02x:%02x:%02x:%02x:%02x:%02x", hdr->addr2[0], hdr->addr2[1], hdr->addr2[2], hdr->addr2[3], hdr->addr2[4], hdr->addr2[5]);
    String name_str = strlen(ssid)>0 ? String(ssid) : "Hidden";

    if (match) {
        log_detection("FLOCK_WIFI", "WIFI", ppkt->rx_ctrl.rssi, mac_str, name_str, ppkt->rx_ctrl.channel, 0, (frame_type == 0x20) ? "Beacon" : "ProbeReq");
        if (millis() - last_buzzer_time > BUZZER_COOLDOWN || last_buzzer_time == 0) {
            trigger_alarm = true; last_buzzer_time = millis();
        }
    } else if (ppkt->rx_ctrl.rssi > IGNORE_WEAK_RSSI) {
        if (millis() - last_log_update > LOG_UPDATE_DELAY) {
            xSemaphoreTake(dataMutex, portMAX_DELAY);
            String logEntry;
            if (name_str != "Hidden" && name_str != "") {
                String cleanName = name_str; if (cleanName.length() > 12) cleanName = cleanName.substring(0, 12);
                logEntry = cleanName + " (" + String(ppkt->rx_ctrl.rssi) + ")";
            } else {
                logEntry = "WiFi " + short_mac(String(mac_str)) + " (" + String(ppkt->rx_ctrl.rssi) + ")";
            }
            for (int i = 4; i > 0; i--) { live_logs[i] = live_logs[i-1]; }
            live_logs[0] = logEntry;
            last_log_update = millis();
            xSemaphoreGive(dataMutex);
        }
    }
}

class AdvertisedDeviceCallbacks: public NimBLEAdvertisedDeviceCallbacks {
    void onResult(NimBLEAdvertisedDevice* advertisedDevice) {
        NimBLEAddress addr = advertisedDevice->getAddress();
        uint8_t mac[6]; sscanf(addr.toString().c_str(), "%02x:%02x:%02x:%02x:%02x:%02x", &mac[0], &mac[1], &mac[2], &mac[3], &mac[4], &mac[5]);
        
        bool match = false;
        if (check_mac_prefix(mac)) match = true;
        else if (advertisedDevice->haveName() && check_device_name_pattern(advertisedDevice->getName().c_str())) match = true;
        else if (check_raven_service_uuid(advertisedDevice)) match = true;
        else if (advertisedDevice->haveManufacturerData() && check_manufacturer_id(advertisedDevice->getManufacturerData())) match = true;

        String dev_name = advertisedDevice->haveName() ? String(advertisedDevice->getName().c_str()) : "Unknown";

        if (match) {
             int tx_power = advertisedDevice->haveTXPower() ? advertisedDevice->getTXPower() : 0;
             String mfg_data = advertisedDevice->haveManufacturerData() ? bytesToHexStr(advertisedDevice->getManufacturerData()) : "";
             log_detection("FLOCK_BLE", "BLE", advertisedDevice->getRSSI(), addr.toString().c_str(), dev_name, 0, tx_power, mfg_data);
             if (millis() - last_buzzer_time > BUZZER_COOLDOWN || last_buzzer_time == 0) {
                 trigger_alarm = true; last_buzzer_time = millis();
             }
        } else if (advertisedDevice->getRSSI() > IGNORE_WEAK_RSSI) {
             if (millis() - last_log_update > LOG_UPDATE_DELAY) {
                 xSemaphoreTake(dataMutex, portMAX_DELAY);
                 String logEntry;
                 if (dev_name != "Unknown" && dev_name != "") {
                     String cleanName = dev_name; if (cleanName.length() > 12) cleanName = cleanName.substring(0, 12);
                     logEntry = cleanName + " (" + String(advertisedDevice->getRSSI()) + ")";
                 } else {
                     logEntry = "BLE " + short_mac(String(addr.toString().c_str())) + " (" + String(advertisedDevice->getRSSI()) + ")";
                 }
                 for (int i = 4; i > 0; i--) { live_logs[i] = live_logs[i-1]; }
                 live_logs[0] = logEntry;
                 last_log_update = millis();
                 xSemaphoreGive(dataMutex);
             }
        }
    }
};

// ============================================================================
// UI SCREENS (Run exclusively on Core 1)
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
    display.setCursor(128 - w, 0); 
    display.print(sat_str);
}

void update_animation() {
    int y_min = 28; int y_max = 52;
    
    display.drawFastVLine(scan_line_x, y_min, (y_max - y_min), SSD1306_BLACK);
    display.drawFastVLine(scan_line_x + 1, y_min, (y_max - y_min), SSD1306_BLACK);
    display.drawFastVLine(scan_line_x + 2, y_min, (y_max - y_min), SSD1306_BLACK);
    display.drawFastVLine(scan_line_x + 3, y_min, (y_max - y_min), SSD1306_BLACK);

    if (random(0, 100) < 75) {
        display.drawPixel(random(0, 128), random(y_min, y_max), SSD1306_WHITE);
    }
    
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
        if(sd_available) { display.setCursor(100, 56); display.print(F("SD:OK")); }
        
        display.fillRect(0, 16, 128, 10, SSD1306_BLACK); display.setCursor(0, 16);
        if (pBLEScan->isScanning()) display.print(F("Scanning: BLE..."));
        else { display.print(F("Scanning: ")); display.print(current_channel); display.print(F(" (WiFi)")); }

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
        long t_s_wifi=session_wifi; long t_l_wifi=lifetime_wifi;
        long t_s_ble=session_ble;   long t_l_ble=lifetime_ble;
        xSemaphoreGive(dataMutex);

        display.clearDisplay(); draw_header();
        display.setCursor(0, 13); display.print(F("Scanner Stats"));
        display.setCursor(40, 24); display.print(F("SESS")); display.setCursor(80, 24); display.print(F("TOTAL"));
        display.setCursor(0, 34); display.print(F("WiFi:")); display.setCursor(40, 34); display.print(t_s_wifi); display.setCursor(80, 34); display.print(t_l_wifi);
        display.setCursor(0, 44); display.print(F("BLE:")); display.setCursor(40, 44); display.print(t_s_ble); display.setCursor(80, 44); display.print(t_l_ble);
        display.drawLine(0, 53, 128, 53, SSD1306_WHITE);
        display.setCursor(0, 56); display.print(F("Run Time: ")); display.print(format_time(lifetime_seconds));
        display.display(); last_stats_update = millis();
    }
}

void draw_last_capture_screen() {
    if (millis() - last_stats_update > 500) {
        xSemaphoreTake(dataMutex, portMAX_DELAY);
        String t_type = last_cap_type; String t_time = last_cap_time;
        String t_mac = last_cap_mac;   int t_rssi = last_cap_rssi;
        xSemaphoreGive(dataMutex);

        display.clearDisplay(); draw_header();
        display.setCursor(0, 13); display.print(F("Last Capture"));
        if (t_type == "None") { display.setCursor(0, 35); display.print(F("NO DATA YET")); } 
        else {
            display.setCursor(0, 25); display.print(F("Time: ")); display.print(t_time);
            display.setCursor(0, 35); display.print(F("Type: ")); display.print(t_type);
            display.setCursor(0, 45); display.print(F("RSSI: ")); display.print(t_rssi);
            display.setCursor(0, 55); display.print(t_mac);
        }
        display.display(); last_stats_update = millis();
    }
}

void draw_live_log_screen() {
    if (millis() - last_stats_update > 100) {
        xSemaphoreTake(dataMutex, portMAX_DELAY);
        String t_logs[5]; for(int i=0; i<5; i++) t_logs[i] = live_logs[i];
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
        
        // <-- NEW: Advanced Stale GPS logic
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
            display.setCursor(0, 36); display.print(F("Sats: ")); display.print(sats); display.print(F(" / 4 Required"));
            display.setCursor(0, 48); display.print(F("Rx Data: ")); display.print(gps.charsProcessed()); display.print(F(" bytes"));
        }
        display.display(); last_stats_update = millis();
    }
}

// <-- NEW: Screen #5 (Activity Bar Chart)
void draw_chart_screen() {
    if (millis() - last_stats_update > 500) {
        display.clearDisplay(); draw_header();
        display.setCursor(0, 13); display.print(F("Activity (Last 25s)"));

        int max_val = 1; 
        for (int i = 0; i < CHART_BARS; i++) {
            if (activity_history[i] > max_val) max_val = activity_history[i];
        }

        for (int i = 0; i < CHART_BARS; i++) {
            int bar_h = (activity_history[i] * 35) / max_val; // Scale bars to 35 pixels max height
            int x = i * 5;                                    // Space them out 5 pixels apart
            int y = 64 - bar_h;                               // Draw upwards from bottom of screen
            display.fillRect(x, y, 4, bar_h, SSD1306_WHITE);
        }
        display.display(); last_stats_update = millis();
    }
}

void refresh_screen_layout() {
    if (stealth_mode) return;
    display.clearDisplay(); draw_header(); display.display();
}

// ============================================================================
// MAIN SETUP
// ============================================================================

void setup() {
    Serial.begin(115200); SerialGPS.begin(GPS_BAUD, SERIAL_8N1, RX_PIN, TX_PIN);
    setCpuFrequencyMhz(240); 
    dataMutex = xSemaphoreCreateMutex();
    
    // <-- DELETED the LED initialization logic here!
    
    pinMode(BUZZER_PIN, OUTPUT); digitalWrite(BUZZER_PIN, LOW);
    pinMode(BUTTON_PIN, INPUT_PULLUP);
    pinMode(SD_CS_PIN, OUTPUT); digitalWrite(SD_CS_PIN, HIGH); 
    SPI.begin(); 

    if(!display.begin(SSD1306_SWITCHCAPVCC, SCREEN_ADDRESS)) { Serial.println(F("SSD1306 failed")); }
    Wire.setClock(400000); display.setRotation(2); 
    
    bool mount_success = false;
    for(int i=0; i<3; i++) { if (SD.begin(SD_CS_PIN)) { mount_success = true; break; } delay(100); }
    if (mount_success) {
        sd_available = true;
        
        int file_num = 1;
        char file_name[32];
        while (true) {
            sprintf(file_name, "/FlockLog_%03d.csv", file_num);
            if (!SD.exists(file_name)) {
                current_log_file = String(file_name);
                break;
            }
            file_num++;
        }
        
        File file = SD.open(current_log_file.c_str(), FILE_WRITE);
        if (file) { 
            file.println("Uptime_ms,Date_Time,Channel,Capture_Type,Protocol,RSSI,MAC_Address,Device_Name,TX_Power,Extra_Data,Latitude,Longitude,Speed_MPH,Heading_Deg"); 
            file.close(); 
        }
    }
    
    session_start_time = millis(); refresh_screen_layout();

    WiFi.mode(WIFI_STA); WiFi.disconnect(); esp_wifi_set_ps(WIFI_PS_NONE); 
    esp_wifi_set_promiscuous(true); esp_wifi_set_promiscuous_rx_cb(&wifi_sniffer_packet_handler);
    esp_wifi_set_channel(current_channel, WIFI_SECOND_CHAN_NONE);
    
    NimBLEDevice::init(""); NimBLEDevice::setPower(ESP_PWR_LVL_P9); 
    pBLEScan = NimBLEDevice::getScan(); pBLEScan->setAdvertisedDeviceCallbacks(new AdvertisedDeviceCallbacks());
    pBLEScan->setActiveScan(true); pBLEScan->setInterval(100); pBLEScan->setWindow(100); 

    boot_beep_sequence();
    last_channel_hop = millis(); last_sd_flush = millis();

    xTaskCreatePinnedToCore(ScannerLoopTask, "ScannerTask", 8192, NULL, 1, &ScannerTaskHandle, 0);
}

// ============================================================================
// MAIN LOOP (Runs implicitly on Core 1)
// ============================================================================

void loop() {
    while (SerialGPS.available() > 0) { 
        gps.encode(SerialGPS.read()); 
        yield(); 
    }

    // <-- DELETED the visual LED heartbeat logic from here!

    // <-- NEW: Logic to populate the bar chart every 1 second
    if (millis() - last_chart_update >= 1000) {
        last_chart_update = millis();
        
        xSemaphoreTake(dataMutex, portMAX_DELAY);
        long current_total = session_wifi + session_ble;
        xSemaphoreGive(dataMutex);
        
        int new_dets = current_total - last_total_dets;
        last_total_dets = current_total;
        
        for (int i = 0; i < CHART_BARS - 1; i++) {
            activity_history[i] = activity_history[i + 1];
        }
        activity_history[CHART_BARS - 1] = new_dets;
    }

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
            if (current_screen > 5) current_screen = 0; // <-- UPDATED to include the 6th screen
            refresh_screen_layout();
        }
    }

    if (millis() - last_time_save >= 1000) { lifetime_seconds++; last_time_save = millis(); }

    xSemaphoreTake(dataMutex, portMAX_DELAY);
    bool should_flush = (sd_write_buffer.size() >= MAX_LOG_BUFFER || (millis() - last_sd_flush > SD_FLUSH_INTERVAL && !sd_write_buffer.empty()));
    xSemaphoreGive(dataMutex);
    if (should_flush) flush_sd_buffer();

    if (!stealth_mode) {
        if (current_screen == 0) {
            draw_scanner_screen();
            if (millis() - last_anim_update > 40) { update_animation(); last_anim_update = millis(); }
        } else if (current_screen == 1) { draw_stats_screen();
        } else if (current_screen == 2) { draw_last_capture_screen();
        } else if (current_screen == 3) { draw_live_log_screen();
        } else if (current_screen == 4) { draw_gps_screen(); 
        } else if (current_screen == 5) { draw_chart_screen(); } // <-- NEW CHART SCREEN
    }
    
    vTaskDelay(10 / portTICK_PERIOD_MS);
}