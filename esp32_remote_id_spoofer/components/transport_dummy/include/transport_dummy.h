#pragma once

#ifdef __cplusplus
extern "C" {
#endif

// High priority for strict timing (e.g. 102.4ms intervals)
#define TRANSPORT_TASK_PRIORITY 10

void transport_dummy_init(void);

#ifdef __cplusplus
}
#endif
