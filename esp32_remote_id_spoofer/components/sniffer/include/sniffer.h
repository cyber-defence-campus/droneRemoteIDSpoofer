#pragma once

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef enum {
    SNIFFER_MEDIUM_AUTO = 0,
    SNIFFER_MEDIUM_WIFI,
    SNIFFER_MEDIUM_BLE,
    SNIFFER_MEDIUM_DUMMY
} sniffer_medium_t;

typedef struct {
    bool locked;
    uint8_t mac[6];
    char serial[21];
    uint8_t static_messages[5][25]; // Type 0, 1 (unused), 2 (Self ID), 3 (System), 4 (Operator ID)
    int32_t pilot_lat;              // In 1e7 degrees from System Message
    int32_t pilot_lon;              // In 1e7 degrees from System Message
    bool has_pilot_loc;             // System Message (Type 4)
    bool has_basic_id;              // Basic ID Message (Type 0)
    bool has_self_id;               // Self-ID Message (Type 3)
    bool has_operator_id;           // Operator ID Message (Type 5)
} sniffer_result_t;

/**
 * @brief Run the Remote ID sniffer until a victim drone is locked or timeout expires.
 *        Automatically handles RF initialization, scanning, ASTM decoding, and radio cleanup.
 * 
 * @param out_result Output structure where victim drone metadata will be written.
 * @param timeout_sec Maximum seconds to sniff (0 = wait indefinitely).
 * @return true if a victim drone was locked, false on timeout.
 */
bool sniffer_run_until_locked(sniffer_result_t *out_result, uint32_t timeout_sec);

/**
 * @brief Parse and ingest a raw ASTM F3411 payload (single message or message pack).
 * 
 * @param result Target result structure to update
 * @param mac Source RF MAC address
 * @param payload Raw ASTM payload buffer
 * @param len Payload length in bytes
 * @param target_serial_filter Optional filter substring (NULL or "" to accept any)
 * @return true if lock was achieved, false otherwise.
 */
bool sniffer_ingest_astm_payload(sniffer_result_t *result,
                                 const uint8_t *mac,
                                 const uint8_t *payload,
                                 size_t len,
                                 const char *target_serial_filter);

#ifdef __cplusplus
}
#endif
