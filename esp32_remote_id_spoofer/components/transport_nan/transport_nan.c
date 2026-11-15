#include "transport_nan.h"
#include "mode_manager.h"
#include <string.h>
#include <stdio.h>
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "freertos/semphr.h"
#include "esp_system.h"
#include "esp_wifi.h"
#include "esp_nan.h"
#include "esp_mac.h"
#include "esp_event.h"
#include "esp_log.h"
#include "esp_timer.h"
#include "esp_rom_sys.h"
#include "esp_random.h"
#include "nvs_flash.h"

static const char *TAG = "TRANSPORT_NAN";
#define NAN_SERVICE_NAME "org.opendroneid.remoteid"

// Compile-time default NAN Service Instance ID. This only seeds the static SDF
// template below; the actual transmitted value is written per-drone at runtime
// from drone.nan_instance_id (see mode_manager DEFAULT_BASE_NAN_INSTANCE_ID).
// Not a Kconfig option despite the historical CONFIG_ name.
#define NAN_DEFAULT_INSTANCE_ID 0x01

#ifndef MIN
#define MIN(a, b) (((a) < (b)) ? (a) : (b))
#endif

// Helper function to read the hardware Wi-Fi MAC TSF register directly from ESP-IDF baseband.
// This prevents TSF phase collisions against CPU timers and ensures action frames land
// precisely inside Android's synchronized Discovery Window (DW).
static inline uint64_t get_wifi_hw_tsf(void) {
    // In standalone STA mode without an AP connection, esp_wifi_get_tsf_time(WIFI_IF_STA) returns 0.
    // By activating APSTA mode and querying WIFI_IF_AP, we directly read the active hardware TSF master clock!
    int64_t tsf = esp_wifi_get_tsf_time(WIFI_IF_AP);
    if (tsf <= 0) {
        tsf = esp_wifi_get_tsf_time(WIFI_IF_STA);
    }
    if (tsf <= 0) {
        // Fallback to CPU OS timer only during initial radio power-up
        return esp_timer_get_time();
    }
    return (uint64_t)tsf;
}

// Pilot Location (Snapshot of first valid GPS fix)
static int32_t pilot_lat = 0;
static int32_t pilot_lon = 0;

// Strict 25-byte message size per ASTM F3411 specification
static uint8_t f3411_messages[5][25] = {0};

// Standalone minimal SHA-256 algorithm to compute the 6-byte NAN Service ID without external libraries
#define ROR(x, n) (((x) >> (n)) | ((x) << (32 - (n))))
#define CH(x, y, z) (((x) & (y)) ^ (~(x) & (z)))
#define MAJ(x, y, z) (((x) & (y)) ^ ((x) & (z)) ^ ((y) & (z)))
#define EP0(x) (ROR(x, 2) ^ ROR(x, 13) ^ ROR(x, 22))
#define EP1(x) (ROR(x, 6) ^ ROR(x, 11) ^ ROR(x, 25))
#define SIG0(x) (ROR(x, 7) ^ ROR(x, 18) ^ ((x) >> 3))
#define SIG1(x) (ROR(x, 17) ^ ROR(x, 19) ^ ((x) >> 10))

static void compute_nan_service_id(const char *str, uint8_t *service_id) {
    static const uint32_t k[64] = {
        0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
        0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
        0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
        0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
        0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
        0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
        0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
        0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2
    };

    size_t len = strlen(str);
    uint8_t msg[64] = {0};
    memcpy(msg, str, len);
    msg[len] = 0x80;

    // Append bit length at end of 64-byte block in big-endian
    uint32_t bit_len = (uint32_t)(len * 8);
    msg[60] = (bit_len >> 24) & 0xFF;
    msg[61] = (bit_len >> 16) & 0xFF;
    msg[62] = (bit_len >> 8) & 0xFF;
    msg[63] = (bit_len) & 0xFF;

    uint32_t w[64];
    for (int i = 0; i < 16; i++) {
        w[i] = ((uint32_t)msg[i*4] << 24) | ((uint32_t)msg[i*4+1] << 16) |
               ((uint32_t)msg[i*4+2] << 8) | ((uint32_t)msg[i*4+3]);
    }
    for (int i = 16; i < 64; i++) {
        w[i] = SIG1(w[i-2]) + w[i-7] + SIG0(w[i-15]) + w[i-16];
    }

    uint32_t h0 = 0x6a09e667, h1 = 0xbb67ae85, h2 = 0x3c6ef372, h3 = 0xa54ff53a;
    uint32_t h4 = 0x510e527f, h5 = 0x9b05688c, h6 = 0x1f83d9ab, h7 = 0x5be0cd19;

    uint32_t a = h0, b = h1, c = h2, d = h3, e = h4, f = h5, g = h6, h = h7;

    for (int i = 0; i < 64; i++) {
        uint32_t t1 = h + EP1(e) + CH(e, f, g) + k[i] + w[i];
        uint32_t t2 = EP0(a) + MAJ(a, b, c);
        h = g; g = f; f = e; e = d + t1;
        d = c; c = b; b = a; a = t1 + t2;
    }

    h0 += a; h1 += b;

    // Service ID is the first 6 bytes of the SHA-256 hash (in big-endian order)
    service_id[0] = (h0 >> 24) & 0xFF;
    service_id[1] = (h0 >> 16) & 0xFF;
    service_id[2] = (h0 >> 8) & 0xFF;
    service_id[3] = (h0) & 0xFF;
    service_id[4] = (h1 >> 24) & 0xFF;
    service_id[5] = (h1 >> 16) & 0xFF;
}

// Helper to parse MAC/Cluster ID strings formatted as "XX:XX:XX:XX:XX:XX"
static void parse_mac_string(const char *str, uint8_t *mac) {
    unsigned int bytes[6];
    if (sscanf(str, "%x:%x:%x:%x:%x:%x", &bytes[0], &bytes[1], &bytes[2], &bytes[3], &bytes[4], &bytes[5]) == 6) {
        for (int i = 0; i < 6; i++) {
            mac[i] = (uint8_t)bytes[i];
        }
    } else {
        // Fallback to standard WFA NAN Cluster BSSID for 2.4 GHz (50:6F:9A:01:00:FF)
        uint8_t default_cluster[6] = {0x50, 0x6F, 0x9A, 0x01, 0x00, 0xFF};
        memcpy(mac, default_cluster, 6);
    }
}

static void transport_nan_task(void *arg) {
    uint8_t counter = 0;
    uint8_t mac[6];
    uint8_t cluster_bssid[6];

    parse_mac_string(CONFIG_NAN_CLUSTER_ID, cluster_bssid);
    // NAN Anchor Master MAC = highest Master-Rank drone (equal preference/random factor across
    // drones means the numerically highest MAC wins election). The single shared anchor/sync
    // beacon therefore originates from a real publisher instead of a phantom device, and its
    // Anchor Master Attribute is self-consistent with the Master Rank tie-break.
    mode_manager_get_anchor_mac(mac);
    mode_manager_build_static_messages(f3411_messages);

    // Compute first 6 bytes of SHA-256("org.opendroneid.remoteid") for the NAN Service ID
    uint8_t sha256_hash[6];
    compute_nan_service_id(NAN_SERVICE_NAME, sha256_hash);

    // 1. Construct RAW NAN Cluster Beacon (106 bytes) matching known working Sync and Discovery beacon structures
    uint8_t raw_nan_beacon[106] = {
        // --- 802.11 MAC HEADER (24 bytes: indices 0..23) ---
        0x80, 0x00,                         // 0..1: Frame Control (Management Beacon: Type 0, Subtype 8)
        0x00, 0x00,                         // 2..3: Duration
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, // 4..9: Destination MAC (Broadcast)
        mac[0], mac[1], mac[2], mac[3], mac[4], mac[5], // 10..15: Source MAC (Drone MAC)
        cluster_bssid[0], cluster_bssid[1], cluster_bssid[2], 
        cluster_bssid[3], cluster_bssid[4], cluster_bssid[5], // 16..21: BSSID (NAN Cluster ID)
        0x00, 0x00,                         // 22..23: Sequence Control (updated dynamically prior to each TX)

        // --- FIXED PARAMETERS (12 bytes: indices 24..35) ---
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // 24..31: Timestamp (8 bytes, updated dynamically in loop)
        0x00, 0x02,                         // 32..33: Beacon Interval in TU (Dynamically switched: 512 TU for Sync vs 100 TU for Discovery)
        0x20, 0x06,                         // 34..35: Capability Information (0x0620 matching standard NAN anchor capabilities)

        // --- TAGGED PARAMETERS (IEs - 70 bytes: indices 36..105) ---
        // Wi-Fi Aware (NAN) Parameter Vendor Specific IE (70 bytes total envelope: indices 36..105)
        0xdd, 0x44,                         // 36..37: Element ID 221 (Vendor Specific), Length (68 / 0x44 bytes payload)
        0x50, 0x6f, 0x9a,                   // 38..40: WFA OUI
        0x13,                               // 41: OUI Type (0x13 = WFA NAN / Wi-Fi Aware standard)
        // --- MASTER INDICATION ATTRIBUTE (5 bytes: indices 42..46) ---
        0x00,                               // 42: Attribute ID 0 (Master Indication Attribute)
        0x02, 0x00,                         // 43..44: Attribute Length (16-bit little-endian: 2 bytes payload)
        0xfe,                               // 45: Master Preference (254)
        0xea,                               // 46: Random Factor (0xea matching working capture)
        // --- NAN CLUSTER ATTRIBUTE (16 bytes: indices 47..62) ---
        0x01,                               // 47: Attribute ID 1 (NAN Cluster Attribute)
        0x0d, 0x00,                         // 48..49: Attribute Length (16-bit little-endian: 13 bytes payload)
        mac[0], mac[1], mac[2], mac[3], mac[4], mac[5], // 50..55: Anchor Master MAC Address (Lower 6 octets of AMR)
        0xea,                               // 56: Anchor Master Random Factor (Byte 6 of AMR)
        0xfe,                               // 57: Anchor Master Preference (254 - Byte 7 / MSB of AMR)
        0x00,                               // 58: Hop Count to Anchor Master (0)
        0x00, 0x00, 0x00, 0x00,             // 59..62: AMBTT (Lower 4 bytes of TSF in us at most recent TBTT, initialized to 0)
        // --- COUNTRY CODE ATTRIBUTE (5 bytes: indices 63..67) ---
        0x0b,                               // 63: Attribute ID 11 (Country Code Attribute)
        0x02, 0x00,                         // 64..65: Attribute Length (2 bytes payload)
        0x43, 0x48,                         // 66..67: ASCII Country Code ("CH" for Switzerland)
        // --- DEVICE CAPABILITY ATTRIBUTE (12 bytes: indices 68..79) ---
        0x0f,                               // 68: Attribute ID 15 (Device Capability Attribute)
        0x09, 0x00,                         // 69..70: Attribute Length (9 bytes payload)
        0x00,                               // 71: Map ID (0)
        0x49, 0x08,                         // 72..73: Committed DW Info / Supported Channels
        0x14,                               // 74: Supported Bands
        0x01,                               // 75: Operation Mode
        0x22,                               // 76: Number of Antennas (2 TX, 2 RX)
        0x58, 0x1b,                         // 77..78: Max Channel Switch Time
        0x08,                               // 79: Capabilities (0x08 matching working capture)
        // --- SERVICE ID LIST ATTRIBUTE (9 bytes: indices 80..88) ---
        0x02,                               // 80: Attribute ID 2 (Service ID List Attribute)
        0x06, 0x00,                         // 81..82: Attribute Length (6 bytes payload)
        sha256_hash[0], sha256_hash[1], sha256_hash[2], 
        sha256_hash[3], sha256_hash[4], sha256_hash[5], // 83..88: Service ID Hash (SHA-256 first 6 bytes)
        // --- VENDOR SPECIFIC IE & ENVELOPE TAIL (17 bytes: indices 89..105) ---
        0xdd, 0x0e,                         // 89..90: Element ID 221, Length (14 bytes payload)
        0x00, 0x00, 0x00, 0xf0,             // 91..94: OUI and Type
        0x33, 0x08, 0x00, 0x01, 0x00, 0x00, 
        0x00, 0x00, 0x00, 0x00,             // 95..104: Vendor specific data
        0x00                                // 105: Trailing envelope alignment byte
    };

    // 2. Construct RAW Wi-Fi Aware Service Discovery Frame (SDF) - 273 bytes total
    uint8_t raw_sdf[273] = {
        // --- 802.11 MAC HEADER (24 bytes) ---
        0xd0, 0x00,                         // 0..1: Frame Control (Action Frame: Type 0, Subtype 13)
        0x00, 0x00,                         // 2..3: Duration
        0x51, 0x6f, 0x9a, 0x01, 0x00, 0x00, // 4..9: Destination MAC (NAN Network ID per NAN spec v3.0 Sec 2.8.1)
        mac[0], mac[1], mac[2], mac[3], mac[4], mac[5], // 10..15: Source MAC
        cluster_bssid[0], cluster_bssid[1], cluster_bssid[2], 
        cluster_bssid[3], cluster_bssid[4], cluster_bssid[5], // 16..21: BSSID (NAN Cluster ID)
        0x00, 0x00,                         // 22..23: Sequence Control (updated dynamically prior to each TX)

        // --- PUBLIC ACTION FRAME HEADER (6 bytes) ---
        0x04,                               // 24: Category (Public Action)
        0x09,                               // 25: Action (Vendor Specific Public Action)
        0x50, 0x6f, 0x9a,                   // 26..28: WFA OUI
        0x13,                               // 29: OUI Type (0x13 = WFA NAN / Wi-Fi Aware standard)

        // --- SERVICE DESCRIPTOR ATTRIBUTE (SDA) HEADER (13 bytes) ---
        0x03,                               // 30: Attribute ID (Service Descriptor Attribute 0x03)
        139, 0x00,                          // 31..32: Attribute Length (139 bytes little-endian: 6+1+1+1+1+129)
        sha256_hash[0], sha256_hash[1], sha256_hash[2], 
        sha256_hash[3], sha256_hash[4], sha256_hash[5], // 33..38: Service ID (SHA-256 first 6 bytes)
        NAN_DEFAULT_INSTANCE_ID,            // 39: Instance ID (template default; overwritten per-drone at runtime)
        0x00,                               // 40: Requestor Instance ID (0 = N/A)
        0x10,                               // 41: Service Control (0x10 = Bit 4: Service Info Present, Bits 0-1: Unsolicited Publish)
        129,                                // 42: Service Info Length (4-byte header + 125-byte message pack)

        // --- ASTM F3411-22 SERVICE INFO PAYLOAD (129 bytes) ---
        0x00,                               // 43: Message Pack Counter
        0xf2,                               // 44: Message Pack Type (0xF) & Protocol Version (0x2)
        0x19,                               // 45: Message Size (strictly 25 bytes)
        0x05,                               // 46: Message Count (5 messages in pack)
        
        // 47..171: 125 bytes of dynamic ASTM messages appended in loop (automatically zero-initialized here)

        // --- SERVICE DESCRIPTOR EXTENSION ATTRIBUTE (7 bytes: indices 172..178) ---
        [172] = 0x0e,                       // 172: Attribute ID 14 (Service Descriptor Extension Attribute)
        0x04, 0x00,                         // 173..174: Attribute Length (4 bytes payload)
        NAN_DEFAULT_INSTANCE_ID,            // 175: Instance ID (template default; overwritten per-drone at runtime)
        0x00,                               // 176: Requestor Instance ID (0 = N/A)
        0x02,                               // 177: Service Extension Control Flags (Bit 1: Service Update Indicator Present)
        0x00,                               // 178: Service Update Indicator (Originally static 0x27; dynamically updated in loop!)

        // --- COUNTRY CODE ATTRIBUTE (5 bytes: indices 179..183) ---
        0x0b,                               // 179: Attribute ID 11 (Country Code Attribute)
        0x02, 0x00,                         // 180..181: Attribute Length (2 bytes payload)
        0x43, 0x48,                         // 182..183: ASCII Country Code ("CH" for Switzerland)

        // --- DEVICE CAPABILITY ATTRIBUTE (12 bytes: indices 184..195) ---
        0x0f,                               // 184: Attribute ID 15 (Device Capability Attribute)
        0x09, 0x00,                         // 185..186: Attribute Length (9 bytes payload)
        0x00,                               // 187: Map ID (0)
        0x49, 0x08,                         // 188..189: Committed DW Info / Supported Channels
        0x14,                               // 190: Supported Bands (2.4 GHz + 5 GHz)
        0x01,                               // 191: Operation Mode
        0x22,                               // 192: Number of Antennas (2 TX, 2 RX)
        0x58, 0x1b,                         // 193..194: Max Channel Switch Time
        0x08,                               // 195: Capabilities

        // --- NAN AVAILABILITY ATTRIBUTE - ENTRY 1 (22 bytes: indices 196..217) ---
        0x12,                               // 196: Attribute ID 18 (NAN Availability Attribute)
        0x13, 0x00,                         // 197..198: Attribute Length (19 bytes payload)
        0x00, 0x31, 0x00, 0x0e, 0x00, 0xea, 
        0x12, 0x18, 0x00, 0x04, 0xfe, 0xfe, 
        0xff, 0xff, 0x11, 0x51, 0xff, 0x1f, 
        0x00,                               // 199..217: Availability Map & Schedule Parameters

        // --- NAN AVAILABILITY ATTRIBUTE - ENTRY 2 (38 bytes: indices 218..255) ---
        0x12,                               // 218: Attribute ID 18 (NAN Availability Attribute)
        0x23, 0x00,                         // 219..220: Attribute Length (35 bytes payload)
        0x00, 0x32, 0x00, 0x0e, 0x00, 0xf2, 
        0x12, 0x18, 0x00, 0x04, 0x00, 0xfe, 
        0x00, 0xff, 0x11, 0x80, 0x21, 0x00, 
        0x0f, 0x0e, 0x00, 0xf2, 0x12, 0x18, 
        0x00, 0x04, 0xff, 0x00, 0xff, 0x00, 
        0x11, 0x80, 0x01, 0x00, 0x01,       // 221..255: Availability Schedule Sub-entries

        // --- VENDOR SPECIFIC NAN ATTRIBUTE (17 bytes: indices 256..272) ---
        0xdd,                               // 256: Attribute ID 221 (Vendor Specific NAN Attribute)
        0x0e, 0x00,                         // 257..258: Attribute Length (14 bytes payload, little-endian)
        0x00, 0x00, 0x00, 0xf0,             // 259..262: OUI and Type
        0x33, 0x08, 0x00, 0x01, 0x00, 0x00, 
        0x00, 0x00, 0x00, 0x00              // 263..272: Vendor specific data
    };

    // NAN Discovery Windows (DWs) occur strictly every 512 TU (1 TU = 1024 us -> 512 TU = 524,288 us)
    const uint64_t TSF_EPOCH_US = 524288ULL;
    // Define 5 target timestamps within each 524,288 us epoch for zero-drift scheduling:
    // Target 0: 0 us (Zero-Offset TBTT right at the start of the 16.384 ms active Discovery Window) -> Sync Beacon + SDF
    // Targets 1..4: 105,000 us, 210,000 us, 315,000 us, 420,000 us -> Inter-DW Discovery Beacons
    const uint64_t target_offsets[5] = { 0ULL, 105000ULL, 210000ULL, 315000ULL, 420000ULL };
    int target_idx = 0;
    int loop_counter = 0;
    uint16_t seq_num = 0;
    uint64_t last_tick_tsf = 0; // Hardware TSF (us) at the previous kinematic tick

    ESP_LOGI(TAG, "Starting Hardware TSF Phase-Locked NAN Spoofer | Base Instance ID: 0x%02X | Cluster: %s | Anchor Master: %02X:%02X:%02X:%02X:%02X:%02X",
             NAN_DEFAULT_INSTANCE_ID, CONFIG_NAN_CLUSTER_ID, mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);

    while (1) {
        // Compute exact microsecond target time directly against physical antenna Hardware TSF clock
        uint64_t now = get_wifi_hw_tsf();
        uint64_t current_epoch = now / TSF_EPOCH_US;
        uint64_t target_time = (current_epoch * TSF_EPOCH_US) + target_offsets[target_idx];

        // If we already bypassed this offset in the current epoch, advance target appropriately
        if (now >= target_time) {
            if (target_idx == 0) {
                target_time = ((current_epoch + 1) * TSF_EPOCH_US) + target_offsets[target_idx];
            } else {
                target_idx = (target_idx + 1) % 5;
                continue;
            }
        }

        // Sleep via FreeRTOS for the majority of the waiting time
        uint64_t diff_us = target_time - get_wifi_hw_tsf();
        if (diff_us > 2000 && diff_us < TSF_EPOCH_US) {
            vTaskDelay(pdMS_TO_TICKS((diff_us - 1000) / 1000));
        }
        // Precision microsecond spin-wait against live Wi-Fi MAC TSF register for perfect radio synchronization
        while (get_wifi_hw_tsf() < target_time) {
            // Spin silently for microsecond synchronization
        }

        if (mode_manager_update()) {
            // Pilot/takeoff location for the System message (clone: sniffed; else first fix)
            mode_manager_get_pilot_location(&pilot_lat, &pilot_lon);

            // Ensure radio synthesizer remains locked to configured Wi-Fi channel (Channel 6)
            esp_wifi_set_channel(CONFIG_WIFI_CHANNEL, WIFI_SECOND_CHAN_NONE);

            // 1. Configure beacon frame type and early-DW contention offset based on target in TSF epoch
            if (target_idx == 0) {
                raw_nan_beacon[32] = 0x00;
                raw_nan_beacon[33] = 0x02; // 0x0200 = 512 TU (Synchronization Beacon inside DW)

                // Early-DW CSMA/CA contention delay (200 us to 600 us) for Synchronization Beacons.
                // Transmitting at literally 0 us hits receiver radios while they are still waking up or hopping to Ch 6.
                // A brief offset ensures receivers are listening and suppresses their internal Sync Beacon backoff timers.
                uint32_t sync_beacon_jitter_us = 200 + (esp_random() % 401);
                esp_rom_delay_us(sync_beacon_jitter_us);
            } else {
                raw_nan_beacon[32] = 0x64;
                raw_nan_beacon[33] = 0x00; // 0x0064 = 100 TU (Discovery Beacon outside DW)
            }

            // Update 802.11 Sequence Control field (bits 4-15 = sequence number, bits 0-3 = fragment number 0)
            raw_nan_beacon[22] = (seq_num & 0x0F) << 4;
            raw_nan_beacon[23] = (seq_num >> 4) & 0xFF;
            seq_num = (seq_num + 1) % 4096;

            // Update AMBTT in NAN Cluster Attribute: Lower 4 octets of TSF (in microseconds) at the time
            // of the most recent TBTT of a Synchronization Beacon (the start of the current Discovery Window epoch).
            uint32_t ambtt_us = (uint32_t)(current_epoch * TSF_EPOCH_US);
            memcpy(&raw_nan_beacon[59], &ambtt_us, 4);

            // Update live TSF Timestamp right before TX and inject the configured NAN Beacon
            uint64_t tsf = get_wifi_hw_tsf();
            memcpy(&raw_nan_beacon[24], &tsf, 8);
            esp_wifi_80211_tx(WIFI_IF_STA, raw_nan_beacon, sizeof(raw_nan_beacon), true);

            // 2. When target_idx == 0, we are precisely inside the 16.384 ms active Discovery Window: Inject SDF Burst!
            if (target_idx == 0) {
                // Advance kinematic simulation by REAL elapsed TSF time, not a fixed guess.
                // Nominal is one epoch (TSF_EPOCH_US); a skipped Discovery Window yields a
                // proportionally larger dt so the swarm never lags real time.
                uint64_t tick_tsf = get_wifi_hw_tsf();
                float dt = (last_tick_tsf == 0)
                             ? ((float)TSF_EPOCH_US / 1e6f)
                             : (float)(tick_tsf - last_tick_tsf) / 1e6f;
                last_tick_tsf = tick_tsf;
                mode_manager_tick(dt);

                uint8_t count = mode_manager_get_drone_count();
                uint32_t burst_delay_us = mode_manager_calculate_nan_burst_delay_us(count);

                // Initial CSMA/CA DW contention slot jitter
                if (count <= 1) {
                    uint32_t dw_jitter_us = 500 + (esp_random() % 9501);
                    esp_rom_delay_us(dw_jitter_us);
                } else {
                    uint32_t dw_jitter_us = 200 + (esp_random() % 601);
                    esp_rom_delay_us(dw_jitter_us);
                }

                // Burst transmit all drones within the 16.384ms Discovery Window
                for (uint8_t i = 0; i < count; i++) {
                    drone_telemetry_t drone;
                    if (mode_manager_get_drone_telemetry(i, &drone)) {
                        // Patch unique Source MAC for this drone
                        memcpy(&raw_sdf[10], drone.mac, 6);

                        // Patch unique NAN Service Instance ID
                        raw_sdf[39] = drone.nan_instance_id;
                        raw_sdf[175] = drone.nan_instance_id;

                        // Overlay live telemetry (Basic ID serial, Location, System pilot location)
                        mode_manager_apply_dynamic_fields(f3411_messages, &drone, pilot_lat, pilot_lon);

                        // Pack all 5 ASTM messages into raw SDF starting at index 47
                        for (int m = 0; m < 5; m++) {
                            memcpy(&raw_sdf[47 + (m * 25)], f3411_messages[m], 25);
                        }

                        // Update ASTM pack counter in Service Info payload
                        raw_sdf[43] = counter;

                        // Update Service Update Indicator in SDEA (Index 178)
                        raw_sdf[178] = counter;

                        // Update 802.11 Sequence Control field to prevent duplicate dropping
                        raw_sdf[22] = (seq_num & 0x0F) << 4;
                        raw_sdf[23] = (seq_num >> 4) & 0xFF;
                        seq_num = (seq_num + 1) % 4096;

                        // Inject the crafted RAW NAN Service Discovery Frame directly into the synchronized DW
                        esp_err_t err = esp_wifi_80211_tx(WIFI_IF_STA, raw_sdf, sizeof(raw_sdf), true);
                        if (err != ESP_OK) {
                            ESP_LOGD(TAG, "Raw NAN SDF TX failed: %s (err 0x%x)", esp_err_to_name(err), err);
                        }

                        // Inter-frame burst spacing
                        if (i < count - 1 && burst_delay_us > 0) {
                            esp_rom_delay_us(burst_delay_us);
                        }
                    }
                }

                // Increment loop counter (2 DW loops = ~1.05s for 1Hz ASTM counter cadence)
                loop_counter++;
                if (loop_counter >= 2) {
                    counter++;
                    loop_counter = 0;
                    ESP_LOGI(TAG, "Injected NAN SDF Burst (%d drone%s) inside DW | Counter: %d",
                             count, (count > 1 ? "s" : ""), counter);
                }
            }

        } else {
            if (target_idx == 0) {
                ESP_LOGW(TAG, "NAN Transport Waiting for GPS Fix...");
            }
        }

        // Advance target state (0 = Discovery Window, 1..4 = Inter-DW Discovery Beacons)
        target_idx = (target_idx + 1) % 5;
    }
}

void transport_nan_init(void) {
    esp_err_t ret = nvs_flash_init();
    if (ret == ESP_ERR_NVS_NO_FREE_PAGES || ret == ESP_ERR_NVS_NEW_VERSION_FOUND) {
        ESP_ERROR_CHECK(nvs_flash_erase());
        ret = nvs_flash_init();
    }
    ESP_ERROR_CHECK(ret);

    ESP_ERROR_CHECK(esp_netif_init());
    ESP_ERROR_CHECK(esp_event_loop_create_default());

    // Initialize AP+Station mode (WIFI_MODE_APSTA) so internal Hardware TSF Clock runs freely and can be queried via WIFI_IF_AP
    esp_netif_create_default_wifi_sta();
    esp_netif_create_default_wifi_ap();
    wifi_init_config_t cfg = WIFI_INIT_CONFIG_DEFAULT();
    ESP_ERROR_CHECK(esp_wifi_init(&cfg));
    ESP_ERROR_CHECK(esp_wifi_set_storage(WIFI_STORAGE_RAM));
    ESP_ERROR_CHECK(esp_wifi_set_mode(WIFI_MODE_APSTA));

    // Configure SoftAP with a hidden/dummy SSID and 60-second beacon interval (60,000 TU) to minimize airtime usage
    wifi_config_t ap_config = {
        .ap = {
            .ssid = "nan_anchor_ap",
            .ssid_len = 13,
            .channel = CONFIG_WIFI_CHANNEL,
            .max_connection = 1,
            .ssid_hidden = 1,
            .beacon_interval = 60000 // Max interval (60,000 TU = 60s) to reduce beacon congestion
        },
    };
    ESP_ERROR_CHECK(esp_wifi_set_config(WIFI_IF_AP, &ap_config));
    ESP_ERROR_CHECK(esp_wifi_start());

    // Set STA interface MAC to the NAN Anchor Master (highest Master-Rank drone) so the
    // hardware source identity matches the drone that anchors the cluster.
    uint8_t mac[6];
    mode_manager_get_anchor_mac(mac);
    esp_wifi_set_mac(WIFI_IF_STA, mac);

    // Disable Wi-Fi power saving so radio PHY stays active for raw TX injection
    ESP_ERROR_CHECK(esp_wifi_set_ps(WIFI_PS_NONE));

    // Set Wi-Fi radio frequency to the configured channel
    ESP_ERROR_CHECK(esp_wifi_set_channel(CONFIG_WIFI_CHANNEL, WIFI_SECOND_CHAN_NONE));

    ESP_LOGI(TAG, "Initialized Raw NAN Anchor & SDF Injection on Channel %d", CONFIG_WIFI_CHANNEL);

    xTaskCreate(transport_nan_task, "nan_task", 4096, NULL, TRANSPORT_NAN_PRIORITY, NULL);
}
