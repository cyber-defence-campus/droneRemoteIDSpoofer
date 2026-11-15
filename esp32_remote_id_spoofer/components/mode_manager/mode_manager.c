#include "mode_manager.h"
#include <stdio.h>
#include <string.h>
#include <math.h>
#include <stdlib.h>
#include "esp_log.h"
#include "esp_random.h"

static const char *TAG = "MODE_MANAGER";

#ifndef M_PI
#define M_PI 3.14159265358979323846
#endif

#ifndef MIN
#define MIN(a, b) (((a) < (b)) ? (a) : (b))
#endif

#ifndef MAX
#define MAX(a, b) (((a) > (b)) ? (a) : (b))
#endif

#ifndef CONFIG_DRONE_NAME
#define CONFIG_DRONE_NAME "VHCI_SPOOFER12345678"
#endif

#ifndef CONFIG_SELF_ID
#define CONFIG_SELF_ID "Spoofing Test"
#endif

#ifndef CONFIG_OPERATOR_ID
#define CONFIG_OPERATOR_ID "OP-DEFAULT-0001"
#endif

#define DEFAULT_BASE_NAN_INSTANCE_ID 0x01

// Latest GPS fix snapshot, refreshed by mode_manager_update() and shared by all modes.
static opendroneid_location_msg_t s_base_loc = {0};
static bool s_has_fix = false;
// Pilot/takeoff location latched from the first valid fix (single & swarm modes).
static int32_t s_pilot_lat = 0;
static int32_t s_pilot_lon = 0;
static bool s_has_pilot = false;

#ifdef CONFIG_MODE_CLONE
static bool s_clone_locked = false;
static uint8_t s_cloned_mac[6] = {0x02, 0x11, 0x22, 0x33, 0x44, 0x55};
static char s_cloned_serial[21] = "CLONED_DRONE_001";
static uint8_t s_cloned_static_messages[5][25] = {0};
static int32_t s_cloned_pilot_lat = 0;
static int32_t s_cloned_pilot_lon = 0;
static bool s_has_cloned_pilot = false;
static bool s_has_basic_id = false;
#endif

#ifdef CONFIG_MODE_SWARM

#ifndef CONFIG_SWARM_DRONE_COUNT
#define CONFIG_SWARM_DRONE_COUNT 5
#endif

#ifndef CONFIG_SWARM_RADIUS_DM
#define CONFIG_SWARM_RADIUS_DM 10
#endif

#ifndef CONFIG_SWARM_ALTITUDE_SPREAD_METERS
#define CONFIG_SWARM_ALTITUDE_SPREAD_METERS 0
#endif

#ifndef CONFIG_SWARM_KINEMATICS_SPEED_MPS
#define CONFIG_SWARM_KINEMATICS_SPEED_MPS 10
#endif

typedef struct {
    uint8_t mac[6];
    char serial[21];
    uint8_t nan_instance_id;
    float offset_x_m;        // East-West relative offset in meters
    float offset_y_m;        // North-South relative offset in meters
    float offset_z_m;        // Altitude offset in meters
    float speed_mps;         // Kinematic speed in m/s
    float heading_deg;       // Heading in degrees (0..359)
    float orbit_angle_rad;   // Current phase angle in radians
    float orbit_radius_m;    // Distance from center in meters
    float vx_mps;            // Velocity X for random walk
    float vy_mps;            // Velocity Y for random walk
} swarm_drone_state_t;

static swarm_drone_state_t s_swarm_drones[CONFIG_SWARM_DRONE_COUNT];
static uint8_t s_swarm_count = CONFIG_SWARM_DRONE_COUNT;
static float s_swarm_radius_m = 1.0f;
static float s_swarm_alt_spread_m = 0.0f;
static float s_swarm_speed_mps = 1.0f;

#endif // CONFIG_MODE_SWARM

void mode_manager_init(void) {
#if defined(CONFIG_MODE_CLONE)
    ESP_LOGI(TAG, "Initializing Clone / Relay Spoofing Mode...");
    s_clone_locked = false;
    s_has_basic_id = false;
    s_has_cloned_pilot = false;
    memset(s_cloned_static_messages, 0, sizeof(s_cloned_static_messages));

    uint32_t timeout_sec = 0;
#ifdef CONFIG_CLONE_TIMEOUT_SEC
    timeout_sec = CONFIG_CLONE_TIMEOUT_SEC;
#endif

    sniffer_result_t sniff_res;
    bool locked = sniffer_run_until_locked(&sniff_res, timeout_sec);
    if (locked) {
        mode_manager_set_cloned_target(&sniff_res);
    } else {
        ESP_LOGW(TAG, "Sniffer did not lock onto a drone before timeout; using fallback identity.");
    }
#elif defined(CONFIG_MODE_SWARM)
    ESP_LOGI(TAG, "Initializing Swarm Spoofing Mode with %d drones...", CONFIG_SWARM_DRONE_COUNT);

    s_swarm_count = CONFIG_SWARM_DRONE_COUNT;
    if (s_swarm_count < 2) s_swarm_count = 2;
    if (s_swarm_count > 20) s_swarm_count = 20;

    s_swarm_radius_m = (float)CONFIG_SWARM_RADIUS_DM * 0.1f;
    if (s_swarm_radius_m < 0.5f) s_swarm_radius_m = 0.5f;

    s_swarm_alt_spread_m = (float)CONFIG_SWARM_ALTITUDE_SPREAD_METERS;
    s_swarm_speed_mps = (float)CONFIG_SWARM_KINEMATICS_SPEED_MPS * 0.1f;
    if (s_swarm_speed_mps < 0.1f) s_swarm_speed_mps = 0.1f;

    for (uint8_t i = 0; i < s_swarm_count; i++) {
        swarm_drone_state_t *d = &s_swarm_drones[i];

        // 1. MAC address: Locally Administered (0x02 prefix), unique lower octet
        d->mac[0] = 0x02;
        d->mac[1] = 0x11;
        d->mac[2] = 0x22;
        d->mac[3] = 0x33;
        d->mac[4] = 0x44;
        d->mac[5] = (uint8_t)(0x50 + i);

        // 2. Drone Serial Number: Base name + suffix index
        snprintf(d->serial, sizeof(d->serial), "%s_%02d", CONFIG_DRONE_NAME, i + 1);

        // 3. Wi-Fi Aware Publish Instance ID
        d->nan_instance_id = (uint8_t)(DEFAULT_BASE_NAN_INSTANCE_ID + i);

        // 4. Polar geometry distribution
        float angle = ((2.0f * (float)M_PI) / (float)s_swarm_count) * (float)i;
        d->orbit_angle_rad = angle;
        d->orbit_radius_m = s_swarm_radius_m;

        d->offset_x_m = s_swarm_radius_m * cosf(angle);
        d->offset_y_m = s_swarm_radius_m * sinf(angle);

        // Altitude spread across drones
        if (s_swarm_alt_spread_m > 0.0f && s_swarm_count > 1) {
            d->offset_z_m = (-s_swarm_alt_spread_m / 2.0f) + (s_swarm_alt_spread_m * (float)i / (float)(s_swarm_count - 1));
        } else {
            d->offset_z_m = 0.0f;
        }

        d->speed_mps = s_swarm_speed_mps;

        // Kinematics-specific setup
#ifdef CONFIG_SWARM_KINEMATICS_ORBIT
        // Tangential heading (perpendicular to radial angle)
        float heading = (angle + ((float)M_PI / 2.0f)) * (180.0f / (float)M_PI);
        while (heading < 0.0f) heading += 360.0f;
        while (heading >= 360.0f) heading -= 360.0f;
        d->heading_deg = heading;
#elif defined(CONFIG_SWARM_KINEMATICS_RANDOM_WALK)
        // Random initial heading
        float rand_angle = ((float)(esp_random() % 3600) / 10.0f) * ((float)M_PI / 180.0f);
        d->vx_mps = s_swarm_speed_mps * cosf(rand_angle);
        d->vy_mps = s_swarm_speed_mps * sinf(rand_angle);
        d->heading_deg = rand_angle * (180.0f / (float)M_PI);
#else
        // Static offset: zero internal velocity
        d->speed_mps = 0.0f;
        d->heading_deg = 0.0f;
#endif

        ESP_LOGI(TAG, "Drone [%d]: Serial='%s', MAC=%02X:%02X:%02X:%02X:%02X:%02X, Offset=(%.2fm, %.2fm, %.2fm)",
                 i, d->serial, d->mac[0], d->mac[1], d->mac[2], d->mac[3], d->mac[4], d->mac[5],
                 d->offset_x_m, d->offset_y_m, d->offset_z_m);
    }
#else
    ESP_LOGI(TAG, "Initialized Single Drone Mode (Serial: %s)", CONFIG_DRONE_NAME);
#endif
}

bool mode_manager_update(void) {
    opendroneid_location_msg_t loc;
    if (!gps_reader_get_latest_location(&loc)) {
        return false;
    }
    s_base_loc = loc;
    s_has_fix = true;

    // Latch the takeoff/pilot location on the first valid fix. Clone mode may override this
    // with the sniffed System Message location in mode_manager_get_pilot_location().
    if (!s_has_pilot) {
        s_pilot_lat = loc.latitude;
        s_pilot_lon = loc.longitude;
        s_has_pilot = true;
        ESP_LOGI(TAG, "Takeoff Location Snapshot: Lat=%ld, Lon=%ld",
                 (long)s_pilot_lat, (long)s_pilot_lon);
    }
    return true;
}

void mode_manager_tick(float dt_seconds) {
#ifdef CONFIG_MODE_SWARM
    if (dt_seconds <= 0.0f) return;

#if defined(CONFIG_SWARM_KINEMATICS_ORBIT)
    for (uint8_t i = 0; i < s_swarm_count; i++) {
        swarm_drone_state_t *d = &s_swarm_drones[i];
        if (d->orbit_radius_m > 0.05f) {
            float angular_vel = d->speed_mps / d->orbit_radius_m;
            d->orbit_angle_rad += angular_vel * dt_seconds;
            if (d->orbit_angle_rad >= 2.0f * (float)M_PI) {
                d->orbit_angle_rad -= 2.0f * (float)M_PI;
            }

            d->offset_x_m = d->orbit_radius_m * cosf(d->orbit_angle_rad);
            d->offset_y_m = d->orbit_radius_m * sinf(d->orbit_angle_rad);

            float heading = (d->orbit_angle_rad + ((float)M_PI / 2.0f)) * (180.0f / (float)M_PI);
            while (heading < 0.0f) heading += 360.0f;
            while (heading >= 360.0f) heading -= 360.0f;
            d->heading_deg = heading;
        }
    }
#elif defined(CONFIG_SWARM_KINEMATICS_RANDOM_WALK)
    for (uint8_t i = 0; i < s_swarm_count; i++) {
        swarm_drone_state_t *d = &s_swarm_drones[i];

        // Slight perturbation to velocity angle (-15 deg to +15 deg scaled by dt)
        float steer_delta = (((float)(esp_random() % 31) - 15.0f) * ((float)M_PI / 180.0f)) * dt_seconds;
        float cur_v_angle = atan2f(d->vy_mps, d->vx_mps) + steer_delta;
        d->vx_mps = d->speed_mps * cosf(cur_v_angle);
        d->vy_mps = d->speed_mps * sinf(cur_v_angle);

        // Advance displacement
        d->offset_x_m += d->vx_mps * dt_seconds;
        d->offset_y_m += d->vy_mps * dt_seconds;

        // Bounding reflection if drone reaches outer radius
        float dist = sqrtf((d->offset_x_m * d->offset_x_m) + (d->offset_y_m * d->offset_y_m));
        if (dist > s_swarm_radius_m) {
            // Reflect inward towards origin
            float inward_angle = atan2f(-d->offset_y_m, -d->offset_x_m);
            d->vx_mps = d->speed_mps * cosf(inward_angle);
            d->vy_mps = d->speed_mps * sinf(inward_angle);
            d->offset_x_m = (d->offset_x_m / dist) * s_swarm_radius_m;
            d->offset_y_m = (d->offset_y_m / dist) * s_swarm_radius_m;
        }

        float heading = atan2f(d->vy_mps, d->vx_mps) * (180.0f / (float)M_PI);
        if (heading < 0.0f) heading += 360.0f;
        d->heading_deg = heading;
    }
#endif // KINEMATICS

#endif // CONFIG_MODE_SWARM
}

uint8_t mode_manager_get_drone_count(void) {
#ifdef CONFIG_MODE_SWARM
    return s_swarm_count;
#else
    return 1;
#endif
}

void mode_manager_get_anchor_mac(uint8_t out_mac[6]) {
    if (out_mac == NULL) {
        return;
    }
#ifdef CONFIG_MODE_SWARM
    // Anchor Master = swarm member with the highest Wi-Fi Aware Master Rank. All drones share
    // the same Master Preference (0xFE) and Random Factor (0xEA), so rank reduces to the MAC
    // weighted MAC[5] (most significant) .. MAC[0]. Select the numerically greatest under that
    // byte order so the advertised anchor is the drone that would actually win the election.
    const uint8_t *best = s_swarm_drones[0].mac;
    for (uint8_t i = 1; i < s_swarm_count; i++) {
        const uint8_t *cand = s_swarm_drones[i].mac;
        for (int b = 5; b >= 0; b--) {
            if (cand[b] != best[b]) {
                if (cand[b] > best[b]) {
                    best = cand;
                }
                break;
            }
        }
    }
    memcpy(out_mac, best, 6);
#elif defined(CONFIG_MODE_CLONE)
    memcpy(out_mac, s_cloned_mac, 6);
#else
    const uint8_t default_mac[6] = {0x02, 0x11, 0x22, 0x33, 0x44, 0x55};
    memcpy(out_mac, default_mac, 6);
#endif
}

bool mode_manager_get_drone_telemetry(uint8_t index,
                                      drone_telemetry_t *out_drone) {
    if (out_drone == NULL || !s_has_fix) {
        return false;
    }
    static const opendroneid_location_msg_t *const base_loc = &s_base_loc;

#ifdef CONFIG_MODE_SWARM
    if (index >= s_swarm_count) {
        return false;
    }

    const swarm_drone_state_t *d = &s_swarm_drones[index];

    // Copy identity
    memcpy(out_drone->mac, d->mac, 6);
    strlcpy(out_drone->serial, d->serial, sizeof(out_drone->serial));
    out_drone->nan_instance_id = d->nan_instance_id;

    // Start with base location packet
    out_drone->location = *base_loc;

    // Convert local meter offsets (dx, dy) to OpenDroneID 1e7 integer degrees
    double lat_deg = (double)base_loc->latitude / 10000000.0;
    double lat_rad = lat_deg * (M_PI / 180.0);

    const double METERS_PER_DEG_LAT = 111320.0;
    double meters_per_deg_lon = 111320.0 * cos(lat_rad);
    if (meters_per_deg_lon < 1.0) {
        meters_per_deg_lon = 1.0;
    }

    // 1 meter = (1e7 / METERS_PER_DEG) units
    int32_t d_lat_units = (int32_t)round((double)d->offset_y_m * (10000000.0 / METERS_PER_DEG_LAT));
    int32_t d_lon_units = (int32_t)round((double)d->offset_x_m * (10000000.0 / meters_per_deg_lon));

    out_drone->location.latitude += d_lat_units;
    out_drone->location.longitude += d_lon_units;

    // Altitude offset (encoded in 0.5m steps: 1 meter = +2 units)
    int32_t d_alt_units = (int32_t)roundf(d->offset_z_m * 2.0f);
    int32_t geo_alt = (int32_t)out_drone->location.geodetic_alt + d_alt_units;
    int32_t hgt = (int32_t)out_drone->location.height + d_alt_units;
    out_drone->location.geodetic_alt = (uint16_t)MAX(0, MIN(0xFFFF, geo_alt));
    out_drone->location.height = (uint16_t)MAX(0, MIN(0xFFFF, hgt));

#if defined(CONFIG_SWARM_KINEMATICS_ORBIT) || defined(CONFIG_SWARM_KINEMATICS_RANDOM_WALK)
    // Encode dynamic speed (0.25 m/s per unit)
    int speed_enc = (int)roundf(d->speed_mps / 0.25f);
    out_drone->location.speed = (uint8_t)MAX(0, MIN(255, speed_enc));

    // Encode dynamic direction
    float cog = d->heading_deg;
    if (cog < 0.0f) cog = 0.0f;
    if (cog >= 360.0f) cog = 359.0f;
    if (cog < 180.0f) {
        out_drone->location.direction = (uint8_t)cog;
        out_drone->location.ew_dir = 32;
    } else {
        out_drone->location.direction = (uint8_t)(cog - 180.0f);
        out_drone->location.ew_dir = 34;
    }
#endif

    return true;

#elif defined(CONFIG_MODE_CLONE)

    if (index > 0) {
        return false;
    }

    // Use cloned MAC & Serial, live GPS for location
    memcpy(out_drone->mac, s_cloned_mac, 6);
    strlcpy(out_drone->serial, s_cloned_serial, sizeof(out_drone->serial));
    out_drone->nan_instance_id = DEFAULT_BASE_NAN_INSTANCE_ID;
    out_drone->location = *base_loc;

    return true;

#else // SINGLE DRONE MODE

    if (index > 0) {
        return false;
    }

    // Default static Single Drone MAC & Serial
    uint8_t default_mac[6] = {0x02, 0x11, 0x22, 0x33, 0x44, 0x55};
    memcpy(out_drone->mac, default_mac, 6);
    strlcpy(out_drone->serial, CONFIG_DRONE_NAME, sizeof(out_drone->serial));
    out_drone->nan_instance_id = DEFAULT_BASE_NAN_INSTANCE_ID;
    out_drone->location = *base_loc;

    return true;

#endif
}

uint32_t mode_manager_calculate_nan_burst_delay_us(uint8_t drone_count) {
    if (drone_count <= 1) {
        return 0;
    }
    // Discovery Window is 16,384 us. Reserved budget ~2,000 us for initial contention + Sync Beacon.
    // Frame transmission takes ~400 us.
    int32_t available_budget_us = 14000 - ((int32_t)drone_count * 400);
    if (available_budget_us < 1000) {
        available_budget_us = 1000;
    }
    uint32_t delay_us = (uint32_t)(available_budget_us / drone_count);

    if (delay_us < 600) delay_us = 600;
    if (delay_us > 2500) delay_us = 2500;

    return delay_us;
}

void mode_manager_set_cloned_target(const sniffer_result_t *target) {
#ifdef CONFIG_MODE_CLONE
    if (target == NULL) return;
    memcpy(s_cloned_mac, target->mac, 6);
    strlcpy(s_cloned_serial, target->serial, sizeof(s_cloned_serial));
    memcpy(s_cloned_static_messages, target->static_messages, sizeof(s_cloned_static_messages));
    s_cloned_pilot_lat = target->pilot_lat;
    s_cloned_pilot_lon = target->pilot_lon;
    s_has_cloned_pilot = target->has_pilot_loc;
    s_clone_locked = target->locked;
    s_has_basic_id = target->locked;
    if (s_has_cloned_pilot) {
        ESP_LOGI(TAG, "Loaded Cloned Pilot / Takeoff Location: Lat=%ld, Lon=%ld",
                 (long)s_cloned_pilot_lat, (long)s_cloned_pilot_lon);
    }
#endif
}

bool mode_manager_ingest_astm_payload(const uint8_t *mac, const uint8_t *payload, size_t len) {
#ifdef CONFIG_MODE_CLONE
    if (s_clone_locked) return true;
    sniffer_result_t res;
    memset(&res, 0, sizeof(res));
    const char *filter = NULL;
#ifdef CONFIG_CLONE_TARGET_SERIAL
    if (strlen(CONFIG_CLONE_TARGET_SERIAL) > 0) {
        filter = CONFIG_CLONE_TARGET_SERIAL;
    }
#endif
    bool locked = sniffer_ingest_astm_payload(&res, mac, payload, len, filter);
    if (locked) {
        mode_manager_set_cloned_target(&res);
    }
    return locked;
#else
    return false;
#endif
}

bool mode_manager_is_clone_locked(void) {
#ifdef CONFIG_MODE_CLONE
    return s_clone_locked;
#else
    return false;
#endif
}

bool mode_manager_get_cloned_static_pack(uint8_t out_messages[5][25]) {
#ifdef CONFIG_MODE_CLONE
    if (out_messages == NULL || !s_clone_locked) {
        return false;
    }
    memcpy(out_messages, s_cloned_static_messages, sizeof(s_cloned_static_messages));
    return true;
#else
    return false;
#endif
}

void mode_manager_build_static_messages(uint8_t out_messages[5][25]) {
    if (out_messages == NULL) {
        return;
    }
    memset(out_messages, 0, 5 * 25);

    // 1. Basic ID (Type 0, Protocol 2)
    out_messages[0][0] = 0x02;
    out_messages[0][1] = 0x12; // ID Type 1 (Serial), UA Type 2
    memcpy(&out_messages[0][2], CONFIG_DRONE_NAME, MIN(sizeof(CONFIG_DRONE_NAME) - 1, 20));

    // 2. Location (Type 1, Protocol 2) - overwritten per-frame by live telemetry
    out_messages[1][0] = 0x12;

    // 3. Self ID (Type 3, Protocol 2)
    out_messages[2][0] = 0x32;
    out_messages[2][1] = 0x00; // Description Type 0
    memcpy(&out_messages[2][2], CONFIG_SELF_ID, MIN(sizeof(CONFIG_SELF_ID) - 1, 23));

    // 4. System (Type 4, Protocol 2) - pilot/takeoff location filled per-frame
    out_messages[3][0] = 0x42;
    out_messages[3][1] = 0x05; // Operator Location Type 1 (Takeoff) + Classification Type

    // 5. Operator ID (Type 5, Protocol 2)
    out_messages[4][0] = 0x52;
    out_messages[4][1] = 0x00; // OperatorIdType: 0x00 = ODID_OPERATOR_ID (only spec-defined value; 0x01+ reserved)
    memcpy(&out_messages[4][2], CONFIG_OPERATOR_ID, MIN(sizeof(CONFIG_OPERATOR_ID) - 1, 20));

#ifdef CONFIG_MODE_CLONE
    // Clone/Relay mode: once locked, broadcast the sniffed victim's static pack verbatim.
    if (s_clone_locked) {
        memcpy(out_messages, s_cloned_static_messages, sizeof(s_cloned_static_messages));
    }
#endif
}

void mode_manager_apply_dynamic_fields(uint8_t messages[5][25],
                                       const drone_telemetry_t *drone,
                                       int32_t pilot_lat, int32_t pilot_lon) {
    if (messages == NULL || drone == NULL) {
        return;
    }
    // Basic ID (Index 0): live serial
    memcpy(&messages[0][2], drone->serial, MIN(sizeof(drone->serial) - 1, 20));
    // Location (Index 1): exactly 25 bytes of encoded telemetry
    memcpy(&messages[1][0], &drone->location, 25);
    // System (Index 3): pilot/takeoff location
    memcpy(&messages[3][2], &pilot_lat, 4);
    memcpy(&messages[3][6], &pilot_lon, 4);
}

bool mode_manager_get_pilot_location(int32_t *out_lat, int32_t *out_lon) {
    if (out_lat == NULL || out_lon == NULL) {
        return false;
    }
#ifdef CONFIG_MODE_CLONE
    // Prefer the cloned victim's System Message (Type 4) pilot location when available.
    if (s_has_cloned_pilot) {
        *out_lat = s_cloned_pilot_lat;
        *out_lon = s_cloned_pilot_lon;
        return true;
    }
#endif
    if (s_has_pilot) {
        *out_lat = s_pilot_lat;
        *out_lon = s_pilot_lon;
        return true;
    }
    return false;
}
