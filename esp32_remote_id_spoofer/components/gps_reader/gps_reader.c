#include "gps_reader.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <math.h>
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "freertos/semphr.h"
#include "driver/uart.h"
#include "driver/gpio.h"
#include "esp_log.h"
#include "esp_timer.h"

#ifndef M_PI
#define M_PI 3.14159265358979323846
#endif

static const char *TAG = "GPS_READER";

// Enable simulated dummy location when real GPS hardware/fix is unavailable
#ifdef CONFIG_GPS_DUMMY_TEST_MODE
#define USE_DUMMY_GPS_MODE 1
#else
#define USE_DUMMY_GPS_MODE 0 // Disabled by default unless enabled in menuconfig
#endif

#define GPS_UART_PORT_NUM      UART_NUM_1
#define GPS_UART_BAUD_RATE     9600
#define GPS_UART_TXD           (11) 
#define GPS_UART_RXD           (12) 
#define GPS_UART_RX_BUF_SIZE   (1024)

static SemaphoreHandle_t gps_mutex = NULL;
static opendroneid_location_msg_t global_location_msg = {0};
static bool has_valid_fix = false;

typedef struct {
    float latitude;
    float longitude;
    float altitude;
    float speed; 
    float cog;   
    int fix;
} my_gps_t;

static my_gps_t current_gps = {0};

static float parse_nmea_coord(const char *coord_str, const char *dir_str) {
    if (!coord_str || !dir_str || strlen(coord_str) < 4) return 0.0;
    float ll = atof(coord_str);
    int deg = (int)(ll / 100.0f);
    float min = ll - (deg * 100.0f);
    float result = deg + (min / 60.0f);
    if (dir_str[0] == 'S' || dir_str[0] == 'W') {
        result = -result;
    }
    return result;
}

static void pack_opendroneid() {
    opendroneid_location_msg_t out_msg = {0};
    out_msg.header = 0x12;

    float cog = current_gps.cog;
    if (cog < 0) cog = 0;
    if (cog >= 360) cog = 359;
    if (cog < 180) {
        out_msg.direction = (uint8_t)cog;
        out_msg.ew_dir = 32;
    } else {
        out_msg.direction = (uint8_t)(cog - 180);
        out_msg.ew_dir = 34;
    }

    int speed_encoded = (int)roundf(current_gps.speed / 0.25f);
    if (speed_encoded < 0) speed_encoded = 0;
    if (speed_encoded > 255) speed_encoded = 255;
    out_msg.speed = (uint8_t)speed_encoded;

    out_msg.latitude = (int32_t)roundf(current_gps.latitude * 10000000.0f);
    out_msg.longitude = (int32_t)roundf(current_gps.longitude * 10000000.0f);

    int alt_encoded = (int)roundf((current_gps.altitude + 1000.0f) * 2.0f);
    if (alt_encoded < 0) alt_encoded = 0;
    if (alt_encoded > 0xFFFF) alt_encoded = 0xFFFF;
    out_msg.geodetic_alt = (uint16_t)alt_encoded;
    out_msg.pressure_alt = (uint16_t)alt_encoded; // No barometer: mirror geodetic altitude
    out_msg.height = (uint16_t)alt_encoded;
    out_msg.timestamp = 0; 

    // Safely write to global struct
    if (xSemaphoreTake(gps_mutex, portMAX_DELAY) == pdTRUE) {
        memcpy(&global_location_msg, &out_msg, sizeof(opendroneid_location_msg_t));
        has_valid_fix = true;
        xSemaphoreGive(gps_mutex);
    }
}

static void parse_nmea_line(char *line) {
    char line_copy[256];
    strlcpy(line_copy, line, sizeof(line_copy));
    
    if (strncmp(line_copy, "$GPRMC", 6) == 0 || strncmp(line_copy, "$GNRMC", 6) == 0) {
        char *token;
        char *rest = line_copy;
        int field = 0;
        char *lat_s = NULL, *lat_dir = NULL, *lon_s = NULL, *lon_dir = NULL;
        
        while ((token = strsep(&rest, ","))) {
            if (field == 2 && token[0]) current_gps.fix = (token[0] == 'A') ? 1 : 0;
            else if (field == 3 && token[0]) lat_s = token;
            else if (field == 4 && token[0]) lat_dir = token;
            else if (field == 5 && token[0]) lon_s = token;
            else if (field == 6 && token[0]) lon_dir = token;
            else if (field == 7 && token[0]) current_gps.speed = atof(token) * 0.514444f;
            else if (field == 8 && token[0]) current_gps.cog = atof(token);
            field++;
        }
        if (current_gps.fix && lat_s && lat_dir && lon_s && lon_dir) {
            current_gps.latitude = parse_nmea_coord(lat_s, lat_dir);
            current_gps.longitude = parse_nmea_coord(lon_s, lon_dir);
        }
    } 
    else if (strncmp(line_copy, "$GPGGA", 6) == 0 || strncmp(line_copy, "$GNGGA", 6) == 0) {
        char *token;
        char *rest = line_copy;
        int field = 0;
        while ((token = strsep(&rest, ","))) {
            if (field == 9 && token[0]) current_gps.altitude = atof(token);
            field++;
        }
    }
}

static void gps_task(void *arg)
{
    uart_config_t uart_config = {
        .baud_rate = GPS_UART_BAUD_RATE,
        .data_bits = UART_DATA_8_BITS,
        .parity    = UART_PARITY_DISABLE,
        .stop_bits = UART_STOP_BITS_1,
        .flow_ctrl = UART_HW_FLOWCTRL_DISABLE,
        .source_clk = UART_SCLK_DEFAULT,
    };

    ESP_LOGI(TAG, "Configuring UART...");
    ESP_ERROR_CHECK(uart_driver_install(GPS_UART_PORT_NUM, GPS_UART_RX_BUF_SIZE * 2, 0, 0, NULL, 0));
    ESP_ERROR_CHECK(uart_param_config(GPS_UART_PORT_NUM, &uart_config));
    ESP_ERROR_CHECK(uart_set_pin(GPS_UART_PORT_NUM, GPS_UART_TXD, GPS_UART_RXD, UART_PIN_NO_CHANGE, UART_PIN_NO_CHANGE));
    
    uint8_t *data = (uint8_t *) malloc(GPS_UART_RX_BUF_SIZE);
    char line_buf[256];
    int line_len = 0;
    
    while (1) {
        int len = uart_read_bytes(GPS_UART_PORT_NUM, data, GPS_UART_RX_BUF_SIZE - 1, 100 / portTICK_PERIOD_MS);
        if (len > 0) {
            for (int i = 0; i < len; i++) {
                char c = (char)data[i];
                if (c == '\n' || c == '\r') {
                    if (line_len > 0) {
                        line_buf[line_len] = '\0';
                        parse_nmea_line(line_buf);
                        if (current_gps.fix) {
                            pack_opendroneid();
                        }
                        line_len = 0;
                    }
                } else if (line_len < sizeof(line_buf) - 1) {
                    line_buf[line_len++] = c;
                }
            }
        }
    }
}

void gps_reader_init(void) {
    gps_mutex = xSemaphoreCreateMutex();
    if (gps_mutex == NULL) {
        ESP_LOGE(TAG, "Failed to create mutex!");
        return;
    }
    xTaskCreate(gps_task, "gps_task", 4096, NULL, GPS_TASK_PRIORITY, NULL);
    ESP_LOGI(TAG, "GPS Reader Task started with priority %d", GPS_TASK_PRIORITY);
}

bool gps_reader_get_latest_location(opendroneid_location_msg_t *out_msg) {
    if (out_msg == NULL) {
        return false;
    }
    if (xSemaphoreTake(gps_mutex, portMAX_DELAY) == pdTRUE) {
        if (!has_valid_fix) {
#if USE_DUMMY_GPS_MODE
            static bool logged_dummy = false;
            static uint64_t last_dummy_time_us = 0;
            static float dummy_phase_rad = 0.0f;
            static float dummy_dist_east_m = 0.0f;
            static float dummy_dist_north_m = 0.0f;

            uint64_t now_us = esp_timer_get_time();
            float dt = 0.0f;
            if (last_dummy_time_us == 0) {
                last_dummy_time_us = now_us;
            } else {
                dt = (float)(now_us - last_dummy_time_us) / 1000000.0f;
                last_dummy_time_us = now_us;
            }

            // Base origin point in Zurich (47.3777344 N, 8.5526392 E)
            const int32_t BASE_LAT = 473777344;
            const int32_t BASE_LON = 85526392;

            float cur_speed_mps = 0.0f;
            float cur_heading_deg = 0.0f;
            float offset_east_m = 0.0f;
            float offset_north_m = 0.0f;

#if defined(CONFIG_GPS_DUMMY_TRAJECTORY_CIRCLE)
            const float circle_radius_m = (float)CONFIG_GPS_DUMMY_CIRCLE_RADIUS_M;
            cur_speed_mps = (float)CONFIG_GPS_DUMMY_SPEED_MPS;
            float omega = cur_speed_mps / (circle_radius_m > 1.0f ? circle_radius_m : 1.0f);
            dummy_phase_rad += omega * dt;
            if (dummy_phase_rad >= 2.0f * (float)M_PI) {
                dummy_phase_rad -= 2.0f * (float)M_PI;
            }

            offset_east_m = circle_radius_m * cosf(dummy_phase_rad);
            offset_north_m = circle_radius_m * sinf(dummy_phase_rad);

            // Clockwise / navigation tangential bearing:
            // vx = -radius * omega * sin(phase), vy = radius * omega * cos(phase)
            float vx = -circle_radius_m * omega * sinf(dummy_phase_rad);
            float vy = circle_radius_m * omega * cosf(dummy_phase_rad);
            cur_heading_deg = atan2f(vx, vy) * (180.0f / (float)M_PI);
            if (cur_heading_deg < 0.0f) cur_heading_deg += 360.0f;

            if (!logged_dummy) {
                ESP_LOGI(TAG, "Simulated Dummy GPS CIRCULAR Trajectory: Speed=%d m/s, Radius=%d m",
                         CONFIG_GPS_DUMMY_SPEED_MPS, CONFIG_GPS_DUMMY_CIRCLE_RADIUS_M);
                logged_dummy = true;
            }

#elif defined(CONFIG_GPS_DUMMY_TRAJECTORY_STRAIGHT)
            cur_speed_mps = (float)CONFIG_GPS_DUMMY_SPEED_MPS;
            cur_heading_deg = (float)CONFIG_GPS_DUMMY_STRAIGHT_HEADING_DEG;
            float heading_rad = cur_heading_deg * ((float)M_PI / 180.0f);

            // East = speed * sin(heading), North = speed * cos(heading)
            float vx = cur_speed_mps * sinf(heading_rad);
            float vy = cur_speed_mps * cosf(heading_rad);

            dummy_dist_east_m += vx * dt;
            dummy_dist_north_m += vy * dt;

            offset_east_m = dummy_dist_east_m;
            offset_north_m = dummy_dist_north_m;

            if (!logged_dummy) {
                ESP_LOGI(TAG, "Simulated Dummy GPS STRAIGHT LINE Trajectory: Speed=%d m/s, Heading=%d deg",
                         CONFIG_GPS_DUMMY_SPEED_MPS, CONFIG_GPS_DUMMY_STRAIGHT_HEADING_DEG);
                logged_dummy = true;
            }

#else // STATIC
            cur_speed_mps = 5.0f;
            cur_heading_deg = 45.0f;
            offset_east_m = 0.0f;
            offset_north_m = 0.0f;

            if (!logged_dummy) {
                ESP_LOGI(TAG, "Simulated Dummy GPS STATIC Location (Lat=47.3777344, Lon=8.5526392)");
                logged_dummy = true;
            }
#endif

            // Convert meter offsets to 1e7 degrees
            const double METERS_PER_DEG_LAT = 111320.0;
            double lat_rad = ((double)BASE_LAT / 10000000.0) * (M_PI / 180.0);
            double meters_per_deg_lon = 111320.0 * cos(lat_rad);
            if (meters_per_deg_lon < 1.0) meters_per_deg_lon = 1.0;

            int32_t d_lat = (int32_t)round((double)offset_north_m * (10000000.0 / METERS_PER_DEG_LAT));
            int32_t d_lon = (int32_t)round((double)offset_east_m * (10000000.0 / meters_per_deg_lon));

            out_msg->header = 0x12;                           // Type 1 Location, Protocol 2
            out_msg->latitude = BASE_LAT + d_lat;
            out_msg->longitude = BASE_LON + d_lon;
            out_msg->geodetic_alt = (1000 + 450) * 2;         // 450 meters Geodetic Altitude encoded
            out_msg->pressure_alt = (1000 + 450) * 2;         // 450 meters Pressure Altitude encoded
            out_msg->height = (1000 + 50) * 2;                // 50 meters Above Ground Layer (AGL) height encoded

            // Encode heading / direction
            if (cur_heading_deg < 0.0f) cur_heading_deg = 0.0f;
            if (cur_heading_deg >= 360.0f) cur_heading_deg = 359.0f;
            if (cur_heading_deg < 180.0f) {
                out_msg->direction = (uint8_t)cur_heading_deg;
                out_msg->ew_dir = 32;
            } else {
                out_msg->direction = (uint8_t)(cur_heading_deg - 180.0f);
                out_msg->ew_dir = 34;
            }

            out_msg->speed = (uint8_t)roundf(cur_speed_mps / 0.25f);
            out_msg->timestamp = 0;
            xSemaphoreGive(gps_mutex);
            return true;
#else
            xSemaphoreGive(gps_mutex);
            return false;
#endif

        }
        memcpy(out_msg, &global_location_msg, sizeof(opendroneid_location_msg_t));
        xSemaphoreGive(gps_mutex);
        return true;
    }
    return false;
}
