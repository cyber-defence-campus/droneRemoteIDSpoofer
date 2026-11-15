idf_component_register(SRCS "sniffer.c"
                       INCLUDE_DIRS "include"
                       REQUIRES "esp_wifi" "esp_event" "nvs_flash" "bt" "esp_timer")
