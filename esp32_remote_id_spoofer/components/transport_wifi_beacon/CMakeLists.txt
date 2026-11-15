idf_component_register(SRCS "transport_wifi_beacon.c"
                    INCLUDE_DIRS "include"
                    REQUIRES "esp_wifi" "esp_timer" "nvs_flash" "gps_reader" "mode_manager")
