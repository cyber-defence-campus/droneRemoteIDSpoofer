#include "transport_dummy.h"
#include "mode_manager.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "esp_log.h"
#include "esp_timer.h"

static const char *TAG = "TRANSPORT_DUMMY";

static void transport_dummy_task(void *arg) {
    // 102.4ms interval for Wi-Fi beacons is roughly 102 ticks if 1 tick = 1ms
    // We use vTaskDelayUntil for precise execution frequency
    TickType_t xLastWakeTime = xTaskGetTickCount();
    const TickType_t xFrequency = pdMS_TO_TICKS(102);

    uint64_t last_tick_us = 0; // Monotonic timestamp of the previous kinematic tick

    ESP_LOGI(TAG, "Dummy Transport Started (Priority %d). Transmitting every 102ms.", TRANSPORT_TASK_PRIORITY);

    while (1) {
        // Wait for the exact interval (CPU sleeps here)
        vTaskDelayUntil(&xLastWakeTime, xFrequency);

        // Advance kinematic simulation by REAL elapsed time (nominal 0.102 s on first tick)
        uint64_t now_us = esp_timer_get_time();
        float dt = (last_tick_us == 0) ? 0.102f : (float)(now_us - last_tick_us) / 1e6f;
        last_tick_us = now_us;
        mode_manager_tick(dt);

        // Refresh the cached GPS fix (single read of the producer/consumer buffer)
        if (mode_manager_update()) {
            uint8_t count = mode_manager_get_drone_count();
            for (uint8_t i = 0; i < count; i++) {
                drone_telemetry_t drone;
                if (mode_manager_get_drone_telemetry(i, &drone)) {
                    ESP_LOGI(TAG, "[102ms TICK | Drone %d/%d | %s] MAC: %02X:%02X:%02X:%02X:%02X:%02X | Lat: %ld, Lon: %ld, Alt: %d, Spd: %d, Dir: %d",
                             i + 1, count, drone.serial,
                             drone.mac[0], drone.mac[1], drone.mac[2], drone.mac[3], drone.mac[4], drone.mac[5],
                             (long)drone.location.latitude, (long)drone.location.longitude,
                             drone.location.geodetic_alt, drone.location.speed, drone.location.direction);
                }
            }
        } else {
            // No fix yet
            ESP_LOGW(TAG, "[102ms TICK] Waiting for GPS Fix to transmit...");
        }
    }
}

void transport_dummy_init(void) {
    xTaskCreate(transport_dummy_task, "transport_dummy", 4096, NULL, TRANSPORT_TASK_PRIORITY, NULL);
}
