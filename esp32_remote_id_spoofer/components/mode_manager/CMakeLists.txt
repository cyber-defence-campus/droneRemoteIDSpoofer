idf_component_register(SRCS "mode_manager.c"
                    INCLUDE_DIRS "include"
                    REQUIRES "gps_reader" "esp_timer" "esp_hw_support" "sniffer")
