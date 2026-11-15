idf_component_register(SRCS "transport_dummy.c"
                    INCLUDE_DIRS "include"
                    REQUIRES "gps_reader" "esp_timer" "mode_manager")
