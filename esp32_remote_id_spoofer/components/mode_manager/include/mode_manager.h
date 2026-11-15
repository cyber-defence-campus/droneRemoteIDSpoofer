#pragma once

#include <stdint.h>
#include <stdbool.h>
#include "gps_reader.h"
#include "sniffer.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Structure representing the generated telemetry state of a single drone instance.
 */
typedef struct {
    uint8_t mac[6];                       /**< Locally administered RF MAC address */
    char serial[21];                      /**< Drone serial identifier for ASTM Basic ID */
    uint8_t nan_instance_id;              /**< Wi-Fi Aware Publish Instance ID */
    opendroneid_location_msg_t location; /**< Encoded OpenDroneID location telemetry */
} drone_telemetry_t;

/**
 * @brief Initialize the active operation mode (Single Drone or Swarm).
 */
void mode_manager_init(void);

/**
 * @brief Advance kinematic simulation time.
 * 
 * @param dt_seconds Elapsed time in seconds since previous tick.
 */
void mode_manager_tick(float dt_seconds);

/**
 * @brief Refresh the cached base GPS fix from gps_reader and latch the pilot/takeoff
 *        location on the first valid fix. Call once per transmit cycle before reading
 *        telemetry; this is the single point where the producer/consumer buffer is read.
 *
 * @return true if a valid fix is now cached, false if no fix has been received yet.
 */
bool mode_manager_update(void);

/**
 * @brief Get the number of active drones in current mode.
 * 
 * @return 1 for Single Drone Mode, or CONFIG_SWARM_DRONE_COUNT for Swarm Mode.
 */
uint8_t mode_manager_get_drone_count(void);

/**
 * @brief Retrieve computed telemetry for a specific drone index.
 * 
 * @param index Drone index (0 .. count-1)
 * @param out_drone Pointer to output telemetry structure
 * @return true on success, false if no fix is cached, index is out of bounds, or out_drone is NULL
 *
 * @note Uses the base fix cached by the most recent mode_manager_update() call.
 */
bool mode_manager_get_drone_telemetry(uint8_t index,
                                      drone_telemetry_t *out_drone);

/**
 * @brief Get the NAN Anchor Master MAC for the active mode: the drone with the highest
 *        Wi-Fi Aware Master Rank. All drones advertise the same Master Preference (0xFE)
 *        and Random Factor (0xEA), so rank reduces to the numerically greatest MAC under
 *        the spec weighting (MAC[5] most significant .. MAC[0] least). The single shared
 *        NAN sync/anchor beacon should originate from this MAC so the cluster anchor is a
 *        genuine Remote ID publisher rather than a phantom device. Single and Clone modes
 *        return their one drone's MAC.
 *
 * @param out_mac 6-byte output buffer for the anchor MAC.
 */
void mode_manager_get_anchor_mac(uint8_t out_mac[6]);

/**
 * @brief Build the static ASTM F3411 message template shared by all transports.
 *        Fills Basic ID (0), Location header (1), Self ID (3), System header (4),
 *        and Operator ID (5) from the active identity. In Clone/Relay mode, once a
 *        victim is locked the synthetic identity is replaced by the sniffed pack.
 *        Call once per transport before the transmit loop.
 *
 * @param out_messages 5x25 byte array populated with the static template.
 */
void mode_manager_build_static_messages(uint8_t out_messages[5][25]);

/**
 * @brief Overlay the live per-frame fields onto a prebuilt message template:
 *        Basic ID serial (0), encoded Location telemetry (1), and the System
 *        message pilot/takeoff location (3). Call once per drone per transmit cycle.
 *
 * @param messages 5x25 byte array previously seeded by mode_manager_build_static_messages().
 * @param drone Telemetry for the drone being transmitted.
 * @param pilot_lat Pilot/takeoff latitude in 1e7 degrees.
 * @param pilot_lon Pilot/takeoff longitude in 1e7 degrees.
 */
void mode_manager_apply_dynamic_fields(uint8_t messages[5][25],
                                       const drone_telemetry_t *drone,
                                       int32_t pilot_lat, int32_t pilot_lon);

/**
 * @brief Calculate optimal inter-frame delay during Wi-Fi NAN Discovery Window burst.
 *        Distributes frame airtime smoothly across the 16.384 ms DW depending on drone count.
 * 
 * @param drone_count Number of drones being burst transmitted
 * @return Delay in microseconds to wait between each frame
 */
uint32_t mode_manager_calculate_nan_burst_delay_us(uint8_t drone_count);

/**
 * @brief Store a cloned target identity discovered by the sniffer.
 * 
 * @param target Pointer to sniffer result structure
 */
void mode_manager_set_cloned_target(const sniffer_result_t *target);

/**
 * @brief Ingest a raw ASTM F3411 payload captured over the air.
 *        Used by Clone / Relay mode to parse and lock onto a victim drone.
 * 
 * @param mac Transmitter MAC address (6 bytes)
 * @param payload Raw ASTM payload buffer (message pack or single message)
 * @param len Length of payload in bytes
 * @return true if a valid drone was detected, false otherwise.
 */
bool mode_manager_ingest_astm_payload(const uint8_t *mac, const uint8_t *payload, size_t len);

/**
 * @brief Check whether Clone Mode has successfully locked onto a victim drone.
 * 
 * @return true if locked, false if still listening.
 */
bool mode_manager_is_clone_locked(void);

/**
 * @brief Retrieve cloned static ASTM F3411 messages (Types 0, 2, 3, 4, 5).
 * 
 * @param out_messages 5x25 byte array where cloned messages will be written.
 * @return true if Clone Mode is active and locked, false otherwise.
 */
bool mode_manager_get_cloned_static_pack(uint8_t out_messages[5][25]);

/**
 * @brief Retrieve the pilot/takeoff location for the active mode.
 *        Clone mode returns the cloned System Message (Type 4) coordinates when available;
 *        single/swarm return the location latched from the first valid GPS fix.
 *
 * @param out_lat Output latitude in 1e7 degrees
 * @param out_lon Output longitude in 1e7 degrees
 * @return true if a pilot location is available, false otherwise.
 */
bool mode_manager_get_pilot_location(int32_t *out_lat, int32_t *out_lon);

#ifdef __cplusplus
}
#endif

