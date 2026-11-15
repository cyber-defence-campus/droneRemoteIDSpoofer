#include "transport_wifi_beacon.h"
#include "mode_manager.h"
#include <string.h>
#include <sys/time.h>
#include "esp_rom_sys.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "esp_system.h"
#include "esp_wifi.h"
#include "esp_event.h"
#include "esp_log.h"
#include "esp_timer.h"
#include "nvs_flash.h"

static const char *TAG = "TRANSPORT_WIFI_BEACON";

#ifndef MIN
#define MIN(a, b) (((a) < (b)) ? (a) : (b))
#endif

// Pilot Location (Snapshot of first valid GPS fix)
static int32_t pilot_lat = 0;
static int32_t pilot_lon = 0;

// Strict 25-byte message size per ASTM F3411 specification
static uint8_t f3411_messages[5][25] = {0};

static void transport_wifi_beacon_task(void *arg) {
    uint8_t counter = 0;

    // MAC Address
    uint8_t mac[6] = {0x02, 0x11, 0x22, 0x33, 0x44, 0x55};

    mode_manager_build_static_messages(f3411_messages);

    // Construct the RAW 802.11 Beacon Frame (225 bytes total)
    uint8_t raw_beacon[225] = {
        // --- MAC HEADER (24 bytes) ---
        0x80, 0x00,                         // 0..1: Frame Control (Beacon, Type 0, Subtype 8)
        0x00, 0x00,                         // 2..3: Duration
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, // 4..9: Destination MAC (Broadcast)
        mac[0], mac[1], mac[2], mac[3], mac[4], mac[5], // 10..15: Source MAC
        mac[0], mac[1], mac[2], mac[3], mac[4], mac[5], // 16..21: BSSID
        0x00, 0x00,                         // 22..23: Sequence Control (managed by esp_wifi_80211_tx)

        // --- BEACON FIXED PARAMETERS (12 bytes) ---
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // 24..31: Timestamp (8 bytes, updated in loop)
        0x64, 0x00,                         // 32..33: Beacon Interval in TU (will be overwritten by Kconfig)
        0x01, 0x04,                         // 34..35: Capability Information (ESS, Short Preamble)

        // --- TAGGED PARAMETERS (IEs) ---
        // SSID IE (26 bytes) - Index 36..61
        0x00, 24, 0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
        
        // Supported Rates IE (6 bytes) - Index 62..67
        0x01, 0x04, 0x82, 0x84, 0x8b, 0x96,
        
        // DS Parameter Set IE (3 bytes) - Index 68..70 (Index 70 is channel, overwritten by Kconfig)
        0x03, 0x01, 0x06,
        
        // TIM IE (6 bytes) - Index 71..76
        0x05, 0x04, 0x00, 0x01, 0x00, 0x00,
        
        // ERP Info IE (3 bytes) - Index 77..79
        0x2a, 0x01, 0x00,
        
        // Extended Supported Rates IE (10 bytes) - Index 80..89
        0x32, 0x08, 0x0c, 0x12, 0x18, 0x24, 0x30, 0x48, 0x60, 0x6c,

        // --- ASTM F3411-22 VENDOR SPECIFIC IE HEADER (10 bytes) - Index 90..99 ---
        0xdd, 133,                          // 90..91: Element ID (221), Length (133 bytes)
        0xfa, 0x0b, 0xbc,                   // 92..94: OUI (ASTM)
        0x0d,                               // 95: OUI Type (Application Code)
        0x00,                               // 96: Counter (will dynamically increment)
        0xf2, 0x19, 0x05                    // 97..99: Pack Header (Type 0xF/Ver 2), Msg Size (25), Msg Count (5)
        
        // 100..224: 125 bytes of messages appended in loop
    };

    // Configure dynamic parameters from Kconfig without using string library functions
    raw_beacon[32] = CONFIG_BEACON_INTERVAL_TU & 0xFF;
    raw_beacon[33] = (CONFIG_BEACON_INTERVAL_TU >> 8) & 0xFF;
    raw_beacon[70] = CONFIG_WIFI_CHANNEL;

    // Zero out SSID field and copy drone name up to 24 bytes
    memset(&raw_beacon[38], 0, 24);
    memcpy(&raw_beacon[38], CONFIG_DRONE_NAME, MIN(sizeof(CONFIG_DRONE_NAME) - 1, 24));

    // Calculate loop timing based on configured TU (1 TU = 1.024 ms)
    uint32_t delay_ms = (uint32_t)((CONFIG_BEACON_INTERVAL_TU * 1024) / 1000);
    if (delay_ms < 1) delay_ms = 1;
    const TickType_t xFrequency = pdMS_TO_TICKS(delay_ms);
    TickType_t xLastWakeTime = xTaskGetTickCount();

    // Calculate how many iterations correspond to ~1 second for counter update
    int loops_per_sec = 1000 / delay_ms;
    if (loops_per_sec < 1) loops_per_sec = 1;
    int loop_counter = 0;
    uint64_t last_tick_us = 0; // Monotonic timestamp of the previous kinematic tick

    ESP_LOGI(TAG, "Starting Wi-Fi Beacon loop: Interval=%d TU (%ld ms), Channel=%d",
             CONFIG_BEACON_INTERVAL_TU, (long)delay_ms, CONFIG_WIFI_CHANNEL);

    while (1) {
        vTaskDelayUntil(&xLastWakeTime, xFrequency);

        if (mode_manager_update()) {
            // Advance kinematic simulation by REAL elapsed time (nominal delay_ms on first tick)
            uint64_t now_us = esp_timer_get_time();
            float dt = (last_tick_us == 0) ? ((float)delay_ms / 1000.0f)
                                           : (float)(now_us - last_tick_us) / 1e6f;
            last_tick_us = now_us;
            mode_manager_tick(dt);

            // Pilot/takeoff location for the System message (clone: sniffed; else first fix)
            mode_manager_get_pilot_location(&pilot_lat, &pilot_lon);

            uint8_t count = mode_manager_get_drone_count();

            for (uint8_t i = 0; i < count; i++) {
                drone_telemetry_t drone;
                if (mode_manager_get_drone_telemetry(i, &drone)) {
                    // Update Source MAC & BSSID
                    memcpy(&raw_beacon[10], drone.mac, 6);
                    memcpy(&raw_beacon[16], drone.mac, 6);

                    // Update SSID with drone serial (up to 24 chars)
                    memset(&raw_beacon[38], 0, 24);
                    memcpy(&raw_beacon[38], drone.serial, MIN(strlen(drone.serial), 24));

                    // Overlay live telemetry (Basic ID serial, Location, System pilot location)
                    mode_manager_apply_dynamic_fields(f3411_messages, &drone, pilot_lat, pilot_lon);

                    // Pack all 5 messages into raw beacon starting at index 100
                    for (int m = 0; m < 5; m++) {
                        memcpy(&raw_beacon[100 + (m * 25)], f3411_messages[m], 25);
                    }

                    // Update ASTM message counter
                    raw_beacon[96] = counter;

                    // Update the 8-byte TSF Timestamp field (microsecond precision)
                    uint64_t tsf = esp_timer_get_time();
                    memcpy(&raw_beacon[24], &tsf, 8);

                    // Inject the raw frame directly into the air
                    esp_err_t err = esp_wifi_80211_tx(WIFI_IF_STA, raw_beacon, sizeof(raw_beacon), true);
                    if (err != ESP_OK) {
                        ESP_LOGD(TAG, "TX failed: %s", esp_err_to_name(err));
                    }

                    if (count > 1 && i < count - 1) {
                        esp_rom_delay_us(400);
                    }
                }
            }

            loop_counter++;
            if (loop_counter >= loops_per_sec) {
                counter++;
                loop_counter = 0;
                ESP_LOGI(TAG, "Injected Wi-Fi Raw Beacon (%d drone%s, Ch %d, TU %d) | Counter: %d",
                         count, (count > 1 ? "s" : ""), CONFIG_WIFI_CHANNEL, CONFIG_BEACON_INTERVAL_TU, counter);
            }
        } else {
            ESP_LOGW(TAG, "Wi-Fi Beacon Transport Waiting for GPS Fix...");
        }
    }
}

void transport_wifi_beacon_init(void) {
    esp_err_t ret = nvs_flash_init();
    if (ret == ESP_ERR_NVS_NO_FREE_PAGES || ret == ESP_ERR_NVS_NEW_VERSION_FOUND) {
        ESP_ERROR_CHECK(nvs_flash_erase());
        ret = nvs_flash_init();
    }
    ESP_ERROR_CHECK(ret);

    ESP_ERROR_CHECK(esp_netif_init());
    ESP_ERROR_CHECK(esp_event_loop_create_default());

    // Place in STA mode to prevent SoftAP WMM Vendor Specific IE collisions
    esp_netif_create_default_wifi_sta();
    wifi_init_config_t cfg = WIFI_INIT_CONFIG_DEFAULT();
    ESP_ERROR_CHECK(esp_wifi_init(&cfg));
    ESP_ERROR_CHECK(esp_wifi_set_storage(WIFI_STORAGE_RAM));
    ESP_ERROR_CHECK(esp_wifi_set_mode(WIFI_MODE_STA));
    ESP_ERROR_CHECK(esp_wifi_start());
    
    // Set interface to configured Wi-Fi channel
    ESP_ERROR_CHECK(esp_wifi_set_channel(CONFIG_WIFI_CHANNEL, WIFI_SECOND_CHAN_NONE));
    ESP_LOGI(TAG, "Wi-Fi Interface initialized in STA mode on Channel %d", CONFIG_WIFI_CHANNEL);

    xTaskCreate(transport_wifi_beacon_task, "wifi_beacon_task", 4096, NULL, TRANSPORT_WIFI_BEACON_PRIORITY, NULL);
}
