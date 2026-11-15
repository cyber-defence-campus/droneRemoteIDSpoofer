#include "transport_ble.h"
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

static const char *TAG = "TRANSPORT_BLE";
static SemaphoreHandle_t cmd_complete_sem;
static SemaphoreHandle_t adv_terminated_sem;

// Pilot Location (Snapshot of first fix)
static int32_t pilot_lat = 0;
static int32_t pilot_lon = 0;

static uint8_t f3411_messages[5][25] = {0};

static void notify_host_send_available(void) {}

static int notify_host_recv(uint8_t *data, uint16_t len) {
    if (len >= 3 && data[0] == 0x04) {
        uint8_t event_code = data[1];
        if (event_code == 0x0E || event_code == 0x0F) { 
            if (event_code == 0x0E && len >= 7 && data[6] != 0x00) {
                uint16_t opcode = data[4] | (data[5] << 8);
                // 0x0C "Command Disallowed" when disabling already-disabled handle is benign
                if (data[6] != 0x0C) {
                    ESP_LOGE(TAG, "HCI Cmd 0x%04X returned error status 0x%02X", opcode, data[6]);
                }
            }
            if (cmd_complete_sem) xSemaphoreGive(cmd_complete_sem);
        } else if (event_code == 0x3E && len >= 6 && data[3] == 0x12) {
            // Subevent 0x12: HCI_LE_Advertising_Set_Terminated_Event
            if (adv_terminated_sem) xSemaphoreGive(adv_terminated_sem);
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

static void transport_ble_task(void *arg) {
    ESP_LOGI(TAG, "Initializing BLE 5 Extended Advertising...");

    // 0. Reset Controller
    send_hci_cmd(0x0C03, NULL, 0);
    vTaskDelay(pdMS_TO_TICKS(100));

    mode_manager_build_static_messages(f3411_messages);

    // 1. Set Ext Adv Params (Opcode 0x2036)
    // Extended PDU (properties=0x0000), Primary PHY=Coded (0x03), Secondary PHY=Coded (0x03)
    uint8_t params[] = {
        0x01, 0x00, 0x00,       // Handle (1), Properties (0x0000 = non-connectable non-scannable extended PDU)
        0x20, 0x00, 0x00,       // Min Interval (32 units = 20ms)
        0x20, 0x00, 0x00,       // Max Interval
        0x07, 0x01, 0x00,       // Channel Map (37, 38, 39), Own Addr Type (Random), Peer Addr Type
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // Peer Addr
        0x00, 0x7F, 0x03,       // Filter Policy, TX Power (0x7F), Primary PHY (0x03 = Coded)
        0x00, 0x03, 0x01, 0x00  // Secondary Max Skip, Secondary PHY (0x03 = Coded), SID (0x01), Scan Req Notif (0x00)
    };
    send_hci_cmd(0x2036, params, sizeof(params));

    // 138-byte payload header: Handle(0x01), Op(0x03=Complete), FragPref(0x01=NoFrag), Len(0x86=134)
    uint8_t payload[138] = {
        0x01, 0x03, 0x01, 0x86, 0x85, 0x16, 0xFA, 0xFF, 0x0D, 0x00, 0xF2, 0x19, 0x05
    };
    
    uint8_t counter = 0;
    TickType_t xLastWakeTime = xTaskGetTickCount();
    const TickType_t xFrequency = pdMS_TO_TICKS(1000); // 1Hz requirement per ASTM F3411
    uint64_t last_tick_us = 0; // Monotonic timestamp of the previous kinematic tick

    ESP_LOGI(TAG, "BLE 5 Extended Advertising (Coded PHY) initialized in single-event burst mode (max_events=1).");

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

            for (uint8_t i = 0; i < count; i++) {
                drone_telemetry_t drone;
                if (mode_manager_get_drone_telemetry(i, &drone)) {
                    // 1. Disable Extended Advertising on Handle 1 before updating address/data
                    uint8_t disable_cmd[] = { 0x00, 0x01, 0x01, 0x00, 0x00, 0x00 };
                    send_hci_cmd(0x2039, disable_cmd, sizeof(disable_cmd));

                    // 2. Set Random Static Address for this drone (Opcode 0x2035)
                    // HCI BD_ADDR parameter is Little-Endian (LSB at index 0, MSB at index 5).
                    // drone.mac is stored Big-Endian (mac[0]=MSB, mac[5]=LSB).
#ifdef CONFIG_MODE_CLONE
                    uint8_t msb = drone.mac[0];
#else
                    uint8_t msb = (uint8_t)(drone.mac[0] | 0xC0);
#endif
                    uint8_t addr_cmd[7] = {
                        0x01,         // Handle
                        drone.mac[5], // LSB
                        drone.mac[4],
                        drone.mac[3],
                        drone.mac[2],
                        drone.mac[1],
                        msb           // MSB
                    };
                    send_hci_cmd(0x2035, addr_cmd, sizeof(addr_cmd));

                    // 3. Overlay live telemetry (Basic ID serial, Location, System pilot location)
                    mode_manager_apply_dynamic_fields(f3411_messages, &drone, pilot_lat, pilot_lon);

                    // 6. Pack payload (138 bytes)
                    for (int m = 0; m < 5; m++) {
                        memcpy(&payload[13 + (m * 25)], f3411_messages[m], 25);
                    }
                    payload[9] = counter++;

                    // 7. Set Extended Advertising Data (Opcode 0x2037)
                    send_hci_cmd(0x2037, payload, 138);

                    // 8. Flush any stale termination events
                    if (adv_terminated_sem) {
                        xSemaphoreTake(adv_terminated_sem, 0);
                    }

                    // 9. Enable Extended Advertising with max_events = 1 (Opcode 0x2039)
                    // Controller transmits exactly 1 event on air, then automatically terminates!
                    uint8_t enable_cmd[] = { 0x01, 0x01, 0x01, 0x00, 0x00, 0x01 };
                    send_hci_cmd(0x2039, enable_cmd, sizeof(enable_cmd));

                    // 10. Wait for HCI_LE_Advertising_Set_Terminated_Event (0x3E subevent 0x12)
                    if (adv_terminated_sem) {
                        xSemaphoreTake(adv_terminated_sem, pdMS_TO_TICKS(150));
                    }
                }
            }

            ESP_LOGI(TAG, "Sent Remote ID Message Packs over BLE 5 (%d drone%s | Counter: %d)",
                     count, (count > 1 ? "s" : ""), counter);
        } else {
            ESP_LOGW(TAG, "BLE Transport Waiting for GPS Fix...");
        }
    }
}

void transport_ble_init(void) {
    esp_err_t ret = nvs_flash_init();
    if (ret == ESP_ERR_NVS_NO_FREE_PAGES || ret == ESP_ERR_NVS_NEW_VERSION_FOUND) {
        ESP_ERROR_CHECK(nvs_flash_erase());
        ret = nvs_flash_init();
    }
    ESP_ERROR_CHECK(ret);

    cmd_complete_sem = xSemaphoreCreateBinary();
    adv_terminated_sem = xSemaphoreCreateBinary();

    esp_bt_controller_config_t bt_cfg = BT_CONTROLLER_INIT_CONFIG_DEFAULT();
    ESP_ERROR_CHECK(esp_bt_controller_init(&bt_cfg));
    ESP_ERROR_CHECK(esp_bt_controller_enable(ESP_BT_MODE_BLE));

    esp_vhci_host_register_callback(&vhci_cb);

    xTaskCreate(transport_ble_task, "transport_ble", 4096, NULL, TRANSPORT_TASK_PRIORITY, NULL);
}

