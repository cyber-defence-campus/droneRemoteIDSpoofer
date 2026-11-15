#include "esp_log.h"
#include "gps_reader.h"
#include "mode_manager.h"

// Conditionally include transport based on menuconfig
#ifdef CONFIG_TRANSPORT_DUMMY
#include "transport_dummy.h"
#endif
#ifdef CONFIG_TRANSPORT_BLE
#include "transport_ble.h"
#endif
#ifdef CONFIG_TRANSPORT_BLE4
#include "transport_ble4.h"
#endif
#ifdef CONFIG_TRANSPORT_NAN
#include "transport_nan.h"
#endif
#ifdef CONFIG_TRANSPORT_WIFI_BEACON
#include "transport_wifi_beacon.h"
#endif

void app_main(void)
{
    ESP_LOGI("APP_MAIN", "Initializing Modular Remote ID Spoofer");

    // 1. Initialize the GPS Reader (Producer Task)
    gps_reader_init();

    // 2. Initialize the Operation Mode Manager (Single Drone or Swarm)
    mode_manager_init();

    // 3. Initialize the Transport Layer (Consumer Task)
#ifdef CONFIG_TRANSPORT_DUMMY
    transport_dummy_init();
#elif defined(CONFIG_TRANSPORT_BLE)
    transport_ble_init();
#elif defined(CONFIG_TRANSPORT_BLE4)
    transport_ble4_init();
#elif defined(CONFIG_TRANSPORT_NAN)
    transport_nan_init();
#elif defined(CONFIG_TRANSPORT_WIFI_BEACON)
    transport_wifi_beacon_init();
#endif

    ESP_LOGI("APP_MAIN", "Initialization Complete.");
}
