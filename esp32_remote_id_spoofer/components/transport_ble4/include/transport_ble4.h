#pragma once

#ifdef __cplusplus
extern "C" {
#endif

// High priority for strict timing
#define TRANSPORT_TASK_PRIORITY 10

void transport_ble4_init(void);

#ifdef __cplusplus
}
#endif
