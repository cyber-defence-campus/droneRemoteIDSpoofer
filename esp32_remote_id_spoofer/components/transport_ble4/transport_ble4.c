#include "transport_ble4.h"
#include "mode_manager.h"
#include <stdio.h>
#include <string.h>
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "freertos/semphr.h"
#include "esp_timer.h"
#include "nvs_flash.h"
#include "esp_bt.h"
#include "esp_log.h"

static const char *TAG = "TRANSPORT_BLE4";
static SemaphoreHandle_t cmd_complete_sem;

// Pilot Location (Snapshot of first fix)
static int32_t pilot_lat = 0;
static int32_t pilot_lon = 0;

static uint8_t f3411_messages[5][25] = {0};

static void notify_host_send_available(void) {}

static int notify_host_recv(uint8_t *data, uint16_t len) {
    if (len >= 3 && data[0] == 0x04) {
        uint8_t event_code = data[1];
        if (event_code == 0x0E || event_code == 0x0F) { 
            if (cmd_complete_sem) xSemaphoreGive(cmd_complete_sem);
        }
    }
    return 0;
}

static const esp_vhci_host_callback_t vhci_cb = {
    .notify_host_send_available = notify_host_send_available,
    .notify_host_recv = notify_host_recv
};

static void send_hci_cmd(uint16_t opcode, const uint8_t *payload, uint8_t len) {
    uint8_t cmd[256];
    cmd[0] = 0x01; 
    cmd[1] = opcode & 0xFF;
    cmd[2] = (opcode >> 8) & 0xFF;
    cmd[3] = len;
    
    if (len > 0) memcpy(&cmd[4], payload, len);
    
    while (!esp_vhci_host_check_send_available()) {
        vTaskDelay(pdMS_TO_TICKS(2));
    }
    
    esp_vhci_host_send_packet(cmd, len + 4);
    
    if (xSemaphoreTake(cmd_complete_sem, pdMS_TO_TICKS(1000)) != pdTRUE) {
        ESP_LOGW(TAG, "HCI Command 0x%04X timed out!", opcode);
    }
}

#ifndef MIN
#define MIN(a, b) (((a) < (b)) ? (a) : (b))
#endif

static void transport_ble4_task(void *arg) {
    ESP_LOGI(TAG, "Initializing BLE 4 Legacy Advertising (ADV_NONCONN_IND)...");

    // 0. Reset Controller (Opcode 0x0C03)
    send_hci_cmd(0x0C03, NULL, 0);
    vTaskDelay(pdMS_TO_TICKS(100));

    mode_manager_build_static_messages(f3411_messages);

    // 1. Set Random Static Address (Opcode 0x2005) - top two bits of MSB must be 11
    uint8_t addr[6] = { 0x01, 0x11, 0x22, 0x33, 0x44, 0xC6 };
    send_hci_cmd(0x2005, addr, sizeof(addr));

    // 2. Set Advertising Parameters (Opcode 0x2006)
    uint16_t interval = (uint16_t)((CONFIG_BLE4_INTERVAL_MS * 8) / 5); // Convert ms to 0.625ms units
    if (interval < 32) interval = 32; // Minimum BLE advertising interval is 20ms (32 units)
    
    uint8_t adv_params[15] = {
        interval & 0xFF, (interval >> 8) & 0xFF, // Min Interval
        interval & 0xFF, (interval >> 8) & 0xFF, // Max Interval
        0x03,                                    // Adv Type: ADV_NONCONN_IND (non-connectable undirected)
        0x01,                                    // Own Address Type: Random
        0x00,                                    // Peer Address Type: Public
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00,      // Peer Address
        0x07,                                    // Channel Map: All 3 primary channels (37, 38, 39)
        0x00                                     // Filter Policy: Allow all
    };
    send_hci_cmd(0x2006, adv_params, sizeof(adv_params));

    ESP_LOGI(TAG, "BLE 4 Legacy Parameters configured | Adv Interval: %d ms", CONFIG_BLE4_INTERVAL_MS);

    uint8_t msg_counters[5] = {0};
    uint32_t cycle_count = 0;
    int static_ptr = 0;
    const int static_indices[4] = {0, 2, 3, 4}; // Basic ID, Self ID, System, Operator ID

    TickType_t xLastWakeTime = xTaskGetTickCount();
    const TickType_t xFrequency = pdMS_TO_TICKS(1000); // 1Hz overall cadence
    uint64_t last_tick_us = 0; // Monotonic timestamp of the previous kinematic tick

    while (1) {
        vTaskDelayUntil(&xLastWakeTime, xFrequency);

        if (mode_manager_update()) {
            // Advance kinematic simulation by REAL elapsed time (nominal 1.0 s on first tick)
            uint64_t now_us = esp_timer_get_time();
            float dt = (last_tick_us == 0) ? 1.0f : (float)(now_us - last_tick_us) / 1e6f;
            last_tick_us = now_us;
            mode_manager_tick(dt);

            // Pilot/takeoff location for the System message (clone: sniffed; else first fix)
            mode_manager_get_pilot_location(&pilot_lat, &pilot_lon);

            uint8_t count = mode_manager_get_drone_count();
            uint8_t drone_idx = cycle_count % count;

            drone_telemetry_t drone;
            if (mode_manager_get_drone_telemetry(drone_idx, &drone)) {
                // Update Random Static Address for this drone (Opcode 0x2005)
                // HCI BD_ADDR parameter is Little-Endian (LSB at index 0, MSB at index 5).
                // drone.mac is stored Big-Endian (mac[0]=MSB, mac[5]=LSB).
#ifdef CONFIG_MODE_CLONE
                uint8_t msb = drone.mac[0];
#else
                uint8_t msb = (uint8_t)(drone.mac[0] | 0xC0);
#endif
                uint8_t addr[6] = {
                    drone.mac[5], // LSB
                    drone.mac[4],
                    drone.mac[3],
                    drone.mac[2],
                    drone.mac[1],
                    msb           // MSB
                };
                send_hci_cmd(0x2005, addr, sizeof(addr));

                // Overlay live telemetry (Basic ID serial, Location, System pilot location)
                mode_manager_apply_dynamic_fields(f3411_messages, &drone, pilot_lat, pilot_lon);
            }

            // Build staggered sequence: 1x Location + staggered statics (averaging 1.33 per cycle)
            int sequence[3];
            int seq_len = 0;
            
            // Location must be transmitted at 1Hz
            sequence[seq_len++] = 1;

            // Send 2 statics every 3rd cycle, otherwise 1 static
            int num_statics = ((cycle_count % 3) == 0) ? 2 : 1;
            for (int s = 0; s < num_statics; s++) {
                sequence[seq_len++] = static_indices[static_ptr];
                static_ptr = (static_ptr + 1) % 4;
            }
            cycle_count++;

            // Transmit each message in sequence with a 250ms dwell window
            for (int m = 0; m < seq_len; m++) {
                int msg_idx = sequence[m];
                
                uint8_t adv_data_cmd[32];
                memset(adv_data_cmd, 0, sizeof(adv_data_cmd));
                adv_data_cmd[0] = 31;                  // Length of advertising data parameter
                adv_data_cmd[1] = 30;                  // Length of AD structure (Service Data 16-bit UUID + payload)
                adv_data_cmd[2] = 0x16;                // AD Type: Service Data - 16-bit UUID
                adv_data_cmd[3] = 0xFA;                // OpenDroneID UUID (0xFFFA low byte)
                adv_data_cmd[4] = 0xFF;                // OpenDroneID UUID (0xFFFA high byte)
                adv_data_cmd[5] = 0x0D;                // ASTM Application Code
                adv_data_cmd[6] = msg_counters[msg_idx]++; // Packet message counter per message type
                memcpy(&adv_data_cmd[7], f3411_messages[msg_idx], 25);

                // Disable advertising (Opcode 0x200A)
                send_hci_cmd(0x200A, (const uint8_t[]){0x00}, 1);
                // Upload AD payload (Opcode 0x2008)
                send_hci_cmd(0x2008, adv_data_cmd, sizeof(adv_data_cmd));
                // Re-enable advertising (Opcode 0x200A)
                send_hci_cmd(0x200A, (const uint8_t[]){0x01}, 1);

                // Dwell for 250ms allowing multiple packet bursts over the air
                vTaskDelay(pdMS_TO_TICKS(250));
            }

            // Disable advertising at the end of the burst sequence until next 1Hz wakeup
            send_hci_cmd(0x200A, (const uint8_t[]){0x00}, 1);
            ESP_LOGI(TAG, "Sent BLE4 Legacy Burst (%d messages) | Loc Counter: %d", seq_len, msg_counters[1]);
        } else {
            ESP_LOGW(TAG, "BLE4 Transport Waiting for GPS Fix...");
        }
    }
}

void transport_ble4_init(void) {
    esp_err_t ret = nvs_flash_init();
    if (ret == ESP_ERR_NVS_NO_FREE_PAGES || ret == ESP_ERR_NVS_NEW_VERSION_FOUND) {
        ESP_ERROR_CHECK(nvs_flash_erase());
        ret = nvs_flash_init();
    }
    ESP_ERROR_CHECK(ret);

    cmd_complete_sem = xSemaphoreCreateBinary();

    esp_bt_controller_config_t bt_cfg = BT_CONTROLLER_INIT_CONFIG_DEFAULT();
    ESP_ERROR_CHECK(esp_bt_controller_init(&bt_cfg));
    ESP_ERROR_CHECK(esp_bt_controller_enable(ESP_BT_MODE_BLE));

    esp_vhci_host_register_callback(&vhci_cb);

    xTaskCreate(transport_ble4_task, "transport_ble4", 4096, NULL, TRANSPORT_TASK_PRIORITY, NULL);
}
