#pragma once

#include <stdint.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

// FreeRTOS Task priority for the GPS reader (lower than transmission)
#define GPS_TASK_PRIORITY 5

#pragma pack(push, 1)
typedef struct {
    uint8_t  header;         
    uint8_t  ew_dir;
    uint8_t  direction;
    uint8_t  speed;
    int8_t   vertical_speed;
    int32_t  latitude;       
    int32_t  longitude;      
    uint16_t pressure_alt;   
    uint16_t geodetic_alt;   
    uint16_t height;         
    uint16_t h_v_accuracy;   
    uint16_t timestamp;      
    uint16_t t_baro_accuracy;
} opendroneid_location_msg_t;
#pragma pack(pop)

/**
 * @brief Initialize the GPS reading task and mutex.
 */
void gps_reader_init(void);

/**
 * @brief Safely retrieve the latest OpenDroneID location message.
 *        This locks the FreeRTOS Mutex, copies the data, and unlocks it.
 * 
 * @param out_msg Pointer to the struct where data will be copied.
 * @return true if a valid fix has been received at least once, false otherwise.
 */
bool gps_reader_get_latest_location(opendroneid_location_msg_t *out_msg);

#ifdef __cplusplus
}
#endif
