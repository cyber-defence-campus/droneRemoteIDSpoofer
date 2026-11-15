idf_component_register(SRCS "transport_ble.c"
                    INCLUDE_DIRS "include"
                    REQUIRES "gps_reader" "esp_timer" "nvs_flash" "bt" "mode_manager")
