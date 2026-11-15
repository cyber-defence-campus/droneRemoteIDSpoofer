idf_component_register(SRCS "transport_nan.c"
                    INCLUDE_DIRS "include"
                    REQUIRES "esp_wifi" "nvs_flash" "gps_reader" "esp_timer" "mode_manager")
