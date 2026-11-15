idf_component_register(SRCS "gps_reader.c"
                    INCLUDE_DIRS "include"
                    REQUIRES esp_driver_uart esp_driver_gpio esp_timer)
