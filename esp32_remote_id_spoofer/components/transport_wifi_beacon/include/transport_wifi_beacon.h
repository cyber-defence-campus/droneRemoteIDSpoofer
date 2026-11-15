#pragma once

#ifdef __cplusplus
extern "C" {
#endif

// Priority 10 to ensure strict timing for beacon intervals
#define TRANSPORT_WIFI_BEACON_PRIORITY 10

void transport_wifi_beacon_init(void);

#ifdef __cplusplus
}
#endif
