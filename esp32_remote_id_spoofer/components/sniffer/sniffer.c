#include "sniffer.h"
#include <stdio.h>
#include <string.h>
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "freertos/semphr.h"
#include "esp_log.h"
#include "nvs_flash.h"
#include "esp_wifi.h"
#include "esp_event.h"
#include "esp_bt.h"
#include "esp_timer.h"

static const char *TAG = "RID_SNIFFER";

#ifndef MIN
#define MIN(a, b) (((a) < (b)) ? (a) : (b))
#endif

#ifndef CONFIG_WIFI_CHANNEL
#define CONFIG_WIFI_CHANNEL 6
#endif

#ifndef CONFIG_CLONE_TARGET_SERIAL
#define CONFIG_CLONE_TARGET_SERIAL ""
#endif

// Pointer to current active result during sniffing session
static sniffer_result_t *s_active_result = NULL;
static const char *s_target_filter = NULL;
static TickType_t s_target_identified_tick = 0;

static inline bool is_full_picture_complete(const sniffer_result_t *result) {
    return (result != NULL &&
            result->has_basic_id &&
            result->has_self_id &&
            result->has_pilot_loc &&
            result->has_operator_id);
}

static void finalize_lock(sniffer_result_t *result) {
    if (result == NULL || result->locked) return;

    // Defaults for any missing static messages
    if (result->static_messages[2][0] == 0) { // Self ID
        result->static_messages[2][0] = 0x32;
        result->static_messages[2][1] = 0x00;
        const char *def_self = "Cloned Drone";
        memcpy(&result->static_messages[2][2], def_self, strlen(def_self));
    }
    if (result->static_messages[3][0] == 0) { // System
        result->static_messages[3][0] = 0x42;
        result->static_messages[3][1] = 0x05;
    }
    if (result->static_messages[4][0] == 0) { // Operator ID
        result->static_messages[4][0] = 0x52;
        result->static_messages[4][1] = 0x01;
        const char *def_op = "OP-CLONED-001";
        memcpy(&result->static_messages[4][2], def_op, strlen(def_op));
    }

    result->locked = true;

    ESP_LOGI(TAG, "****************************************************************");
    ESP_LOGI(TAG, "[!] VICTIM DRONE INTERCEPTED & LOCKED!");
    ESP_LOGI(TAG, "    MAC:    %02X:%02X:%02X:%02X:%02X:%02X",
             result->mac[0], result->mac[1], result->mac[2],
             result->mac[3], result->mac[4], result->mac[5]);
    ESP_LOGI(TAG, "    Serial: %s", result->serial);
    if (result->has_pilot_loc) {
        ESP_LOGI(TAG, "    Pilot:  Lat=%ld, Lon=%ld", (long)result->pilot_lat, (long)result->pilot_lon);
    } else {
        ESP_LOGI(TAG, "    Pilot:  (None broadcast by victim)");
    }
    ESP_LOGI(TAG, "****************************************************************");
}

static void process_astm_chunk(sniffer_result_t *result, const uint8_t *mac, const uint8_t *chunk) {
    if (result == NULL || chunk == NULL) return;
    uint8_t header = chunk[0];
    uint8_t msg_type = (header >> 4) & 0x0F;

    // In multi-drone environments: if we have anchored onto a candidate MAC,
    // only accept packets matching that exact MAC.
    if (s_target_identified_tick > 0 && mac != NULL) {
        if (memcmp(result->mac, mac, 6) != 0) {
            return;
        }
    }

    // If a filter is configured and we don't have Basic ID yet,
    // we must reject non-Basic ID packets because we can't verify if they belong to the target.
    if (s_target_filter != NULL && strlen(s_target_filter) > 0) {
        if (!result->has_basic_id && msg_type != 0x00) {
            return;
        }
    }

    if (msg_type == 0x00) { // Basic ID (Type 0)
        char serial[21] = {0};
        int s_idx = 0;
        for (int i = 0; i < 20; i++) {
            char c = (char)chunk[2 + i];
            if (c >= 0x20 && c <= 0x7E) {
                serial[s_idx++] = c;
            } else if (c == '\0') {
                break;
            }
        }
        serial[s_idx] = '\0';

        if (s_target_filter != NULL && strlen(s_target_filter) > 0) {
            if (strstr(serial, s_target_filter) == NULL) {
                ESP_LOGD(TAG, "Ingested Basic ID '%s' does not match filter '%s'", serial, s_target_filter);
                return;
            }
        }

        memcpy(result->static_messages[0], chunk, 25);
        if (s_idx > 0) {
            strlcpy(result->serial, serial, sizeof(result->serial));
        }
        if (mac != NULL) {
            memcpy(result->mac, mac, 6);
        }
        result->has_basic_id = true;
        if (s_target_identified_tick == 0) {
            s_target_identified_tick = xTaskGetTickCount();
        }

        ESP_LOGI(TAG, "Captured Basic ID: Serial='%s', MAC=%02X:%02X:%02X:%02X:%02X:%02X [Picture: BasicID=OK, SelfID=%s, System=%s, OpID=%s]",
                 result->serial, result->mac[0], result->mac[1], result->mac[2],
                 result->mac[3], result->mac[4], result->mac[5],
                 result->has_self_id ? "OK" : "MISSING",
                 result->has_pilot_loc ? "OK" : "MISSING",
                 result->has_operator_id ? "OK" : "MISSING");

    } else if (msg_type == 0x03) { // Self-ID (Type 3)
        memcpy(result->static_messages[2], chunk, 25);
        if (mac != NULL && s_target_identified_tick == 0) {
            memcpy(result->mac, mac, 6);
        }
        result->has_self_id = true;
        if (s_target_identified_tick == 0) {
            s_target_identified_tick = xTaskGetTickCount();
        }
        char desc[24] = {0};
        int d_idx = 0;
        for (int i = 0; i < 23; i++) {
            char c = (char)chunk[2 + i];
            if (c >= 0x20 && c <= 0x7E) {
                desc[d_idx++] = c;
            } else if (c == '\0') {
                break;
            }
        }
        desc[d_idx] = '\0';
        ESP_LOGI(TAG, "Captured Self-ID: '%s' [Picture: BasicID=%s, SelfID=OK, System=%s, OpID=%s]",
                 desc,
                 result->has_basic_id ? "OK" : "MISSING",
                 result->has_pilot_loc ? "OK" : "MISSING",
                 result->has_operator_id ? "OK" : "MISSING");

    } else if (msg_type == 0x04) { // System (Type 4)
        memcpy(result->static_messages[3], chunk, 25);
        if (mac != NULL && s_target_identified_tick == 0) {
            memcpy(result->mac, mac, 6);
        }
        int32_t p_lat = 0;
        int32_t p_lon = 0;
        memcpy(&p_lat, &chunk[2], 4);
        memcpy(&p_lon, &chunk[6], 4);
        result->pilot_lat = p_lat;
        result->pilot_lon = p_lon;
        result->has_pilot_loc = true;
        if (s_target_identified_tick == 0) {
            s_target_identified_tick = xTaskGetTickCount();
        }
        ESP_LOGI(TAG, "Captured Pilot Location: Lat=%ld, Lon=%ld [Picture: BasicID=%s, SelfID=%s, System=OK, OpID=%s]",
                 (long)p_lat, (long)p_lon,
                 result->has_basic_id ? "OK" : "MISSING",
                 result->has_self_id ? "OK" : "MISSING",
                 result->has_operator_id ? "OK" : "MISSING");

    } else if (msg_type == 0x05) { // Operator ID (Type 5)
        memcpy(result->static_messages[4], chunk, 25);
        if (mac != NULL && s_target_identified_tick == 0) {
            memcpy(result->mac, mac, 6);
        }
        result->has_operator_id = true;
        if (s_target_identified_tick == 0) {
            s_target_identified_tick = xTaskGetTickCount();
        }
        char op_id[21] = {0};
        int o_idx = 0;
        for (int i = 0; i < 20; i++) {
            char c = (char)chunk[2 + i];
            if (c >= 0x20 && c <= 0x7E) {
                op_id[o_idx++] = c;
            } else if (c == '\0') {
                break;
            }
        }
        op_id[o_idx] = '\0';
        ESP_LOGI(TAG, "Captured Operator ID: '%s' [Picture: BasicID=%s, SelfID=%s, System=%s, OpID=OK]",
                 op_id,
                 result->has_basic_id ? "OK" : "MISSING",
                 result->has_self_id ? "OK" : "MISSING",
                 result->has_pilot_loc ? "OK" : "MISSING");
    }
}

bool sniffer_ingest_astm_payload(sniffer_result_t *result,
                                 const uint8_t *mac,
                                 const uint8_t *payload,
                                 size_t len,
                                 const char *target_serial_filter) {
    if (result == NULL || payload == NULL || len < 25) {
        return false;
    }
    if (result->locked) {
        return true;
    }

    s_target_filter = target_serial_filter;

    size_t i = 0;
    while (i < len) {
        uint8_t header = payload[i];
        uint8_t msg_type = (header >> 4) & 0x0F;

        if (msg_type == 0x0F) { // Message Pack
            if (i + 3 > len) break;
            uint8_t msg_size = payload[i + 1];
            uint8_t msg_count = payload[i + 2];

            if (msg_size != 25 || msg_count == 0 || msg_count > 9) {
                break;
            }
            if (i + 3 + (msg_count * 25) > len) {
                break;
            }

            i += 3;
            for (uint8_t c = 0; c < msg_count; c++) {
                const uint8_t *chunk = &payload[i + (c * 25)];
                uint8_t sub_type = (chunk[0] >> 4) & 0x0F;
                if (sub_type != 0x0F) {
                    process_astm_chunk(result, mac, chunk);
                }
            }
            i += (msg_count * 25);
            break;
        } else if (msg_type <= 0x05) { // Single message
            if (i + 25 <= len) {
                process_astm_chunk(result, mac, &payload[i]);
                i += 25;
            } else {
                break;
            }
        } else {
            i++;
        }
    }

    // Only lock immediately when the full picture (Types 0, 3, 4, 5) has been acquired
    if (is_full_picture_complete(result)) {
        finalize_lock(result);
        return true;
    }

    return false;
}

/* =========================================================================
 * Wi-Fi Promiscuous Sniffer Subsystem
 * ========================================================================= */
static void wifi_promiscuous_rx_cb(void *buf, wifi_promiscuous_pkt_type_t type) {
    if (type != WIFI_PKT_MGMT || s_active_result == NULL || s_active_result->locked) {
        return;
    }

    const wifi_promiscuous_pkt_t *pkt = (const wifi_promiscuous_pkt_t *)buf;
    const uint8_t *payload = pkt->payload;
    uint16_t len = pkt->rx_ctrl.sig_len;

    if (len < 24) return;

    uint8_t fc0 = payload[0];
    uint8_t subtype = (fc0 >> 4) & 0x0F;
    const uint8_t *src_mac = &payload[10];

    // 1. Management Beacon (8) or Probe Response (5)
    if (subtype == 8 || subtype == 5) {
        size_t offset = 36;
        while (offset + 2 <= len) {
            uint8_t eid = payload[offset];
            uint8_t elen = payload[offset + 1];
            if (offset + 2 + elen > len) break;

            if (eid == 0xDD && elen >= 5) {
                // ASTM OUI 0xFA0BBC and Type 0x0D
                if (payload[offset + 2] == 0xFA &&
                    payload[offset + 3] == 0x0B &&
                    payload[offset + 4] == 0xBC &&
                    payload[offset + 5] == 0x0D) {
                    if (elen > 5) {
                        const uint8_t *astm_payload = &payload[offset + 7];
                        size_t astm_len = elen - 5;
                        sniffer_ingest_astm_payload(s_active_result, src_mac, astm_payload, astm_len, s_target_filter);
                        if (s_active_result->locked) return;
                    }
                }
            }
            offset += 2 + elen;
        }
    }
    // 2. Action Frame (13): Wi-Fi Aware NAN Service Discovery Frame
    else if (subtype == 13 && len >= 47) {
        if (payload[24] == 0x04 && payload[25] == 0x09) {
            for (size_t offset = 26; offset + 17 <= len; offset++) {
                if (payload[offset] == 0x03) { // Service Descriptor Attribute
                    uint8_t s_info_len = payload[offset + 12];
                    if (s_info_len >= 25 && offset + 14 + s_info_len <= len) {
                        const uint8_t *astm_payload = &payload[offset + 14];
                        size_t astm_len = s_info_len - 1;
                        sniffer_ingest_astm_payload(s_active_result, src_mac, astm_payload, astm_len, s_target_filter);
                        if (s_active_result->locked) return;
                    }
                }
            }
        }
    }
}

static bool run_wifi_sniffer(sniffer_result_t *result, uint32_t timeout_sec) {
    ESP_LOGI(TAG, "Starting Wi-Fi Sniffer on Channel %d...", CONFIG_WIFI_CHANNEL);

    esp_err_t ret = nvs_flash_init();
    if (ret == ESP_ERR_NVS_NO_FREE_PAGES || ret == ESP_ERR_NVS_NEW_VERSION_FOUND) {
        nvs_flash_erase();
        nvs_flash_init();
    }

    ESP_ERROR_CHECK(esp_netif_init());
    ESP_ERROR_CHECK(esp_event_loop_create_default());

    esp_netif_t *sta_netif = esp_netif_create_default_wifi_sta();
    wifi_init_config_t cfg = WIFI_INIT_CONFIG_DEFAULT();
    ESP_ERROR_CHECK(esp_wifi_init(&cfg));
    ESP_ERROR_CHECK(esp_wifi_set_storage(WIFI_STORAGE_RAM));
    ESP_ERROR_CHECK(esp_wifi_set_mode(WIFI_MODE_STA));
    ESP_ERROR_CHECK(esp_wifi_start());
    ESP_ERROR_CHECK(esp_wifi_set_channel(CONFIG_WIFI_CHANNEL, WIFI_SECOND_CHAN_NONE));

    esp_wifi_set_promiscuous_rx_cb(wifi_promiscuous_rx_cb);
    esp_wifi_set_promiscuous(true);

    ESP_LOGI(TAG, "Wi-Fi Promiscuous RX Active. Listening for Drone Remote ID Beacons / Action frames...");

    TickType_t start_tick = xTaskGetTickCount();
    TickType_t last_status_tick = start_tick;

    while (!result->locked) {
        vTaskDelay(pdMS_TO_TICKS(100));

        if (is_full_picture_complete(result)) {
            finalize_lock(result);
            break;
        }

        // If candidate drone was identified, wait up to 30 seconds for full picture;
        // if incomplete, discard partial messages and restart search
        if (s_target_identified_tick > 0) {
            if ((xTaskGetTickCount() - s_target_identified_tick) > pdMS_TO_TICKS(30000)) {
                ESP_LOGW(TAG, "****************************************************************");
                ESP_LOGW(TAG, "[!] Candidate timeout (30s): Incomplete picture for MAC %02X:%02X:%02X:%02X:%02X:%02X!",
                         result->mac[0], result->mac[1], result->mac[2],
                         result->mac[3], result->mac[4], result->mac[5]);
                ESP_LOGW(TAG, "    Basic ID (Type 0):    %s", result->has_basic_id ? "CAPTURED" : "MISSING");
                ESP_LOGW(TAG, "    Self-ID (Type 3):     %s", result->has_self_id ? "CAPTURED" : "MISSING");
                ESP_LOGW(TAG, "    System/Pilot (Type 4):%s", result->has_pilot_loc ? "CAPTURED" : "MISSING");
                ESP_LOGW(TAG, "    Operator ID (Type 5): %s", result->has_operator_id ? "CAPTURED" : "MISSING");
                ESP_LOGW(TAG, "    Discarding partial data and restarting scan...");
                ESP_LOGW(TAG, "****************************************************************");
                memset(result, 0, sizeof(*result));
                s_target_identified_tick = 0;
            }
        }

        if ((xTaskGetTickCount() - last_status_tick) > pdMS_TO_TICKS(2000)) {
            last_status_tick = xTaskGetTickCount();
            if (s_target_identified_tick > 0) {
                int secs_left = 30 - (int)((xTaskGetTickCount() - s_target_identified_tick) / pdMS_TO_TICKS(1000));
                if (secs_left < 0) secs_left = 0;
                ESP_LOGI(TAG, "Assembling Full Picture (%d s left)... [BasicID=%s, SelfID=%s, System=%s, OpID=%s]",
                         secs_left,
                         result->has_basic_id ? "OK" : "WAIT",
                         result->has_self_id ? "OK" : "WAIT",
                         result->has_pilot_loc ? "OK" : "WAIT",
                         result->has_operator_id ? "OK" : "WAIT");
            }
        }

        if (timeout_sec > 0) {
            if ((xTaskGetTickCount() - start_tick) > pdMS_TO_TICKS(timeout_sec * 1000)) {
                ESP_LOGW(TAG, "Wi-Fi Sniffing timed out after %ld seconds.", (long)timeout_sec);
                break;
            }
        }
    }

    // Clean teardown so subsequent Wi-Fi transports can re-initialize cleanly
    esp_wifi_set_promiscuous(false);
    esp_wifi_stop();
    esp_wifi_deinit();
    if (sta_netif) {
        esp_netif_destroy_default_wifi(sta_netif);
    }
    ESP_ERROR_CHECK(esp_event_loop_delete_default());

    ESP_LOGI(TAG, "Wi-Fi Sniffer stopped and deinitialized.");
    return result->locked;
}

/* =========================================================================
 * BLE Sniffer Subsystem
 * ========================================================================= */
static SemaphoreHandle_t s_ble_cmd_sem = NULL;
static uint32_t s_ble_raw_packets_seen = 0;

static void parse_ble_adv_data(const uint8_t *mac, const uint8_t *adv_data, uint8_t adv_len) {
    if (adv_data == NULL || adv_len < 4 || s_active_result == NULL || s_active_result->locked) return;
    size_t offset = 0;
    while (offset < adv_len) {
        uint8_t ad_len = adv_data[offset];
        if (ad_len == 0 || offset + 1 + ad_len > adv_len) break;
        uint8_t ad_type = adv_data[offset + 1];
        const uint8_t *ad_val = &adv_data[offset + 2];
        uint8_t val_len = ad_len - 1;

        if (ad_type == 0x16 && val_len >= 3) { // Service Data - 16-bit UUID
            if (ad_val[0] == 0xFA && ad_val[1] == 0xFF) { // OpenDroneID UUID (0xFFFA)
                if (val_len >= 5 && ad_val[2] == 0x0D) {
                    // Standard ASTM F3411: UUID (2) + AppCode 0x0D (1) + Counter (1) + Payload
                    sniffer_ingest_astm_payload(s_active_result, mac, &ad_val[4], val_len - 4, s_target_filter);
                } else if (val_len >= 4 && ad_val[2] == 0x0D) {
                    // ASTM F3411 with AppCode 0x0D but no counter
                    sniffer_ingest_astm_payload(s_active_result, mac, &ad_val[3], val_len - 3, s_target_filter);
                } else if (val_len >= 27) {
                    // Direct ASTM message following UUID
                    sniffer_ingest_astm_payload(s_active_result, mac, &ad_val[2], val_len - 2, s_target_filter);
                }
                if (s_active_result->locked) return;
            }
        }
        offset += 1 + ad_len;
    }
}

static void ble_notify_host_send_available(void) {}

static uint8_t s_last_cmd_status = 0;

static int ble_notify_host_recv(uint8_t *data, uint16_t len) {
    if (len >= 3 && data[0] == 0x04) {
        uint8_t event_code = data[1];
        if (event_code == 0x0E || event_code == 0x0F) {
            if (event_code == 0x0E && len >= 7) {
                s_last_cmd_status = data[6];
            } else {
                s_last_cmd_status = 0;
            }
            if (s_ble_cmd_sem) xSemaphoreGive(s_ble_cmd_sem);
        } else if (event_code == 0x3E && len >= 4) {
            uint8_t subevent = data[3];
            if (subevent == 0x02 && len >= 14) { // LE Advertising Report (Legacy 1M)
                s_ble_raw_packets_seen++;
                uint8_t adv_len = data[13];
                if (len >= 14 + adv_len) {
                    uint8_t mac[6] = { data[12], data[11], data[10], data[9], data[8], data[7] };
                    parse_ble_adv_data(mac, &data[14], adv_len);
                }
            } else if (subevent == 0x0D && len >= 29) { // LE Extended Advertising Report (1M Legacy or Coded Extended)
                s_ble_raw_packets_seen++;
                uint8_t adv_len = data[28];
                if (len >= 29 + adv_len) {
                    uint8_t mac[6] = { data[13], data[12], data[11], data[10], data[9], data[8] };
                    parse_ble_adv_data(mac, &data[29], adv_len);
                }
            }
        }
    }
    return 0;
}

static const esp_vhci_host_callback_t s_ble_vhci_cb = {
    .notify_host_send_available = ble_notify_host_send_available,
    .notify_host_recv = ble_notify_host_recv
};

static bool ble_send_hci_cmd(uint16_t opcode, const uint8_t *payload, uint8_t len) {
    uint8_t cmd[256];
    cmd[0] = 0x01;
    cmd[1] = opcode & 0xFF;
    cmd[2] = (opcode >> 8) & 0xFF;
    cmd[3] = len;
    if (len > 0) memcpy(&cmd[4], payload, len);

    while (!esp_vhci_host_check_send_available()) {
        vTaskDelay(pdMS_TO_TICKS(2));
    }
    s_last_cmd_status = 0xFF;
    esp_vhci_host_send_packet(cmd, len + 4);

    if (xSemaphoreTake(s_ble_cmd_sem, pdMS_TO_TICKS(1000)) != pdTRUE) {
        ESP_LOGW(TAG, "HCI Command 0x%04X timed out", opcode);
        return false;
    }
    if (s_last_cmd_status != 0x00) {
        ESP_LOGE(TAG, "HCI Command 0x%04X rejected, status: 0x%02X", opcode, s_last_cmd_status);
        return false;
    }
    return true;
}

static bool run_ble_sniffer(sniffer_result_t *result, uint32_t timeout_sec) {
    ESP_LOGI(TAG, "Starting BLE Sniffer...");
    s_ble_raw_packets_seen = 0;

    esp_err_t ret = nvs_flash_init();
    if (ret == ESP_ERR_NVS_NO_FREE_PAGES || ret == ESP_ERR_NVS_NEW_VERSION_FOUND) {
        nvs_flash_erase();
        nvs_flash_init();
    }
    s_ble_cmd_sem = xSemaphoreCreateBinary();

    esp_bt_controller_config_t bt_cfg = BT_CONTROLLER_INIT_CONFIG_DEFAULT();
    ESP_ERROR_CHECK(esp_bt_controller_init(&bt_cfg));
    ESP_ERROR_CHECK(esp_bt_controller_enable(ESP_BT_MODE_BLE));
    esp_vhci_host_register_callback(&s_ble_vhci_cb);

    // 1. Reset Controller
    ble_send_hci_cmd(0x0C03, NULL, 0);
    vTaskDelay(pdMS_TO_TICKS(100));

    // 2. Set Event Mask (0x0C01) - Unmask LE Meta Event (0x3E)
    uint8_t evt_mask[8] = { 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF };
    ble_send_hci_cmd(0x0C01, evt_mask, sizeof(evt_mask));

    // 3. Set LE Event Mask (0x2001) - Crucial for unmasking Extended Adv Reports (0x0D) & Legacy Reports (0x02)!
    uint8_t le_evt_mask[8] = { 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF };
    ble_send_hci_cmd(0x2001, le_evt_mask, sizeof(le_evt_mask));

    // 4. Set Random Address (0x2005) - Ensure controller has a valid static random address
    uint8_t rand_addr[6] = { 0x11, 0x22, 0x33, 0x44, 0x55, 0xC0 };
    ble_send_hci_cmd(0x2005, rand_addr, sizeof(rand_addr));

    // 5. Configure Extended Scanning for simultaneous 1M (Legacy) and Coded PHY (Extended) scanning
    // Scanning_PHYs = 0x05 (Bit 0 = 1M PHY, Bit 2 = LE Coded PHY)
    uint8_t ext_scan_params[] = {
        0x00,                   // Own address type: 0x00 = Public Device Address
        0x00,                   // Scanning filter policy: Accept all (0x00)
        0x05,                   // Scanning PHYs: bit 0 (1M) | bit 2 (Coded)
        // 1M PHY (Primary Channels 37, 38, 39):
        0x00,                   // Passive scanning
        0x50, 0x00,             // Interval: 0x0050 (50ms)
        0x50, 0x00,             // Window: 0x0050 (50ms)
        // LE Coded PHY (Long Range):
        0x00,                   // Passive scanning
        0x50, 0x00,             // Interval: 0x0050 (50ms)
        0x50, 0x00              // Window: 0x0050 (50ms)
    };

    bool ext_scan_supported = ble_send_hci_cmd(0x2041, ext_scan_params, sizeof(ext_scan_params));
    if (ext_scan_supported) {
        // Enable Extended Scan: simultaneously listens for Legacy 1M and Extended Coded packets!
        uint8_t ext_scan_enable[] = { 0x01, 0x00, 0x00, 0x00, 0x00, 0x00 };
        ble_send_hci_cmd(0x2042, ext_scan_enable, sizeof(ext_scan_enable));
        ESP_LOGI(TAG, "BLE Dual-PHY Scanning Active: Listening simultaneously for Legacy (1M) and Extended (Coded PHY) packets!");
    } else {
        // Fallback for BLE 4.2-only hardware
        ESP_LOGW(TAG, "Extended Scan rejected by controller. Falling back to BLE 4 Legacy Scanning (1M PHY)...");
        uint8_t leg_scan_params[] = { 0x00, 0x50, 0x00, 0x50, 0x00, 0x00, 0x00 };
        ble_send_hci_cmd(0x200B, leg_scan_params, sizeof(leg_scan_params));
        uint8_t leg_scan_enable[] = { 0x01, 0x00 };
        ble_send_hci_cmd(0x200C, leg_scan_enable, sizeof(leg_scan_enable));
        ESP_LOGI(TAG, "BLE Legacy Scanning Active (1M PHY).");
    }

    TickType_t start_tick = xTaskGetTickCount();
    TickType_t last_status_tick = start_tick;

    while (!result->locked) {
        vTaskDelay(pdMS_TO_TICKS(100));

        if (is_full_picture_complete(result)) {
            finalize_lock(result);
            break;
        }

        // If candidate drone was identified, wait up to 30 seconds for full picture;
        // if incomplete, discard partial messages and restart search
        if (s_target_identified_tick > 0) {
            if ((xTaskGetTickCount() - s_target_identified_tick) > pdMS_TO_TICKS(30000)) {
                ESP_LOGW(TAG, "****************************************************************");
                ESP_LOGW(TAG, "[!] Candidate timeout (30s): Incomplete picture for MAC %02X:%02X:%02X:%02X:%02X:%02X!",
                         result->mac[0], result->mac[1], result->mac[2],
                         result->mac[3], result->mac[4], result->mac[5]);
                ESP_LOGW(TAG, "    Basic ID (Type 0):    %s", result->has_basic_id ? "CAPTURED" : "MISSING");
                ESP_LOGW(TAG, "    Self-ID (Type 3):     %s", result->has_self_id ? "CAPTURED" : "MISSING");
                ESP_LOGW(TAG, "    System/Pilot (Type 4):%s", result->has_pilot_loc ? "CAPTURED" : "MISSING");
                ESP_LOGW(TAG, "    Operator ID (Type 5): %s", result->has_operator_id ? "CAPTURED" : "MISSING");
                ESP_LOGW(TAG, "    Discarding partial data and restarting scan...");
                ESP_LOGW(TAG, "****************************************************************");
                memset(result, 0, sizeof(*result));
                s_target_identified_tick = 0;
            }
        }

        if ((xTaskGetTickCount() - last_status_tick) > pdMS_TO_TICKS(2000)) {
            last_status_tick = xTaskGetTickCount();
            if (s_target_identified_tick > 0) {
                int secs_left = 30 - (int)((xTaskGetTickCount() - s_target_identified_tick) / pdMS_TO_TICKS(1000));
                if (secs_left < 0) secs_left = 0;
                ESP_LOGI(TAG, "Assembling Full Picture (%d s left)... [BasicID=%s, SelfID=%s, System=%s, OpID=%s]",
                         secs_left,
                         result->has_basic_id ? "OK" : "WAIT",
                         result->has_self_id ? "OK" : "WAIT",
                         result->has_pilot_loc ? "OK" : "WAIT",
                         result->has_operator_id ? "OK" : "WAIT");
            } else {
                ESP_LOGI(TAG, "BLE Sniffing Active (Dual-PHY: 1M + Coded). Raw packets observed: %ld", (long)s_ble_raw_packets_seen);
            }
        }

        if (timeout_sec > 0) {
            if ((xTaskGetTickCount() - start_tick) > pdMS_TO_TICKS(timeout_sec * 1000)) {
                ESP_LOGW(TAG, "BLE Sniffing timed out after %ld seconds. Total raw packets observed: %ld",
                         (long)timeout_sec, (long)s_ble_raw_packets_seen);
                break;
            }
        }
    }

    // Disable Scanning
    if (ext_scan_supported) {
        uint8_t ext_scan_disable[] = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
        ble_send_hci_cmd(0x2042, ext_scan_disable, sizeof(ext_scan_disable));
    } else {
        uint8_t leg_scan_disable[] = { 0x00, 0x00 };
        ble_send_hci_cmd(0x200C, leg_scan_disable, sizeof(leg_scan_disable));
    }

    // Clean teardown of BT controller
    esp_bt_controller_disable();
    esp_bt_controller_deinit();
    vSemaphoreDelete(s_ble_cmd_sem);
    s_ble_cmd_sem = NULL;

    ESP_LOGI(TAG, "BLE Sniffer stopped and deinitialized.");
    return result->locked;
}

/* =========================================================================
 * Dummy Sniffer Subsystem (Offline Simulation)
 * ========================================================================= */
static bool run_dummy_sniffer(sniffer_result_t *result) {
    ESP_LOGI(TAG, "Simulating Drone Remote ID Sniffer (2-second simulated delay)...");
    vTaskDelay(pdMS_TO_TICKS(2000));

    uint8_t sim_pack[3 + 5 * 25] = {0};
    sim_pack[0] = 0xF2;
    sim_pack[1] = 0x19;
    sim_pack[2] = 0x05;

    // Type 0 (Basic ID)
    sim_pack[3 + 0] = 0x02;
    sim_pack[3 + 1] = 0x12;
    const char *sim_serial = "TARGET_DRONE_7777";
    memcpy(&sim_pack[3 + 2], sim_serial, strlen(sim_serial));

    // Type 1 (Location)
    sim_pack[3 + 25 + 0] = 0x12;

    // Type 3 (Self ID)
    sim_pack[3 + 50 + 0] = 0x32;
    sim_pack[3 + 50 + 1] = 0x00;
    const char *sim_desc = "Simulated Victim Drone";
    memcpy(&sim_pack[3 + 50 + 2], sim_desc, strlen(sim_desc));

    // Type 4 (System)
    sim_pack[3 + 75 + 0] = 0x42;
    sim_pack[3 + 75 + 1] = 0x05;
    int32_t sim_p_lat = 473769000;
    int32_t sim_p_lon = 85417000;
    memcpy(&sim_pack[3 + 75 + 2], &sim_p_lat, 4);
    memcpy(&sim_pack[3 + 75 + 6], &sim_p_lon, 4);

    // Type 5 (Operator ID)
    sim_pack[3 + 100 + 0] = 0x52;
    sim_pack[3 + 100 + 1] = 0x01;
    const char *sim_op = "CHE-OP-998877";
    memcpy(&sim_pack[3 + 100 + 2], sim_op, strlen(sim_op));

    uint8_t sim_mac[6] = {0x02, 0x55, 0x44, 0x33, 0x22, 0x11};
    sniffer_ingest_astm_payload(result, sim_mac, sim_pack, sizeof(sim_pack), s_target_filter);
    return result->locked;
}

/* =========================================================================
 * Main Sniffer Dispatcher
 * ========================================================================= */
bool sniffer_run_until_locked(sniffer_result_t *out_result, uint32_t timeout_sec) {
    if (out_result == NULL) return false;
    memset(out_result, 0, sizeof(sniffer_result_t));

    s_active_result = out_result;
    s_target_filter = CONFIG_CLONE_TARGET_SERIAL;
    s_target_identified_tick = 0;

    sniffer_medium_t medium = SNIFFER_MEDIUM_AUTO;

#if defined(CONFIG_CLONE_SNIFFER_WIFI)
    medium = SNIFFER_MEDIUM_WIFI;
#elif defined(CONFIG_CLONE_SNIFFER_BLE)
    medium = SNIFFER_MEDIUM_BLE;
#else // AUTO
#if defined(CONFIG_TRANSPORT_BLE) || defined(CONFIG_TRANSPORT_BLE4)
    medium = SNIFFER_MEDIUM_BLE;
#elif defined(CONFIG_TRANSPORT_WIFI_BEACON) || defined(CONFIG_TRANSPORT_NAN)
    medium = SNIFFER_MEDIUM_WIFI;
#elif defined(CONFIG_TRANSPORT_DUMMY)
    medium = SNIFFER_MEDIUM_DUMMY;
#endif
#endif

    bool success = false;
    switch (medium) {
        case SNIFFER_MEDIUM_WIFI:
            success = run_wifi_sniffer(out_result, timeout_sec);
            break;
        case SNIFFER_MEDIUM_BLE:
            success = run_ble_sniffer(out_result, timeout_sec);
            break;
        case SNIFFER_MEDIUM_DUMMY:
        default:
            success = run_dummy_sniffer(out_result);
            break;
    }

    s_active_result = NULL;
    return success;
}
