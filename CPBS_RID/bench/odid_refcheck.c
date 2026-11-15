/* Decode a message pack (hex in argv[1]) with the opendroneid-core-c reference
 * decoder and print the fields CPBS relies on, one "key value" per line.
 * Build: see tests/test_odid_reference.py */
#include <stdio.h>
#include <string.h>
#include "opendroneid.h"

static int hex2bin(const char *h, uint8_t *out, size_t max) {
    size_t n = strlen(h) / 2;
    if (n > max) return -1;
    for (size_t i = 0; i < n; i++) sscanf(h + 2 * i, "%2hhx", &out[i]);
    return (int)n;
}

int main(int argc, char **argv) {
    uint8_t buf[sizeof(ODID_MessagePack_encoded)] = {0};
    if (argc != 2 || hex2bin(argv[1], buf, sizeof(buf)) < 0) return 2;
    ODID_UAS_Data uas;
    odid_initUasData(&uas);
    printf("rc %d\n", decodeMessagePack(&uas, (ODID_MessagePack_encoded *)buf));
    for (int i = 0; i < ODID_BASIC_ID_MAX_MESSAGES; i++) {
        if (!uas.BasicIDValid[i]) continue;
        printf("basic_id_type %d\nbasic_id ", uas.BasicID[i].IDType);
        for (int j = 0; j < ODID_ID_SIZE; j++) printf("%02X", (uint8_t)uas.BasicID[i].UASID[j]);
        printf("\n");
    }
    if (uas.LocationValid)
        printf("lat %.7f\nlon %.7f\nspeed %.2f\nheight %.1f\nloc_ts %.1f\n",
               uas.Location.Latitude, uas.Location.Longitude, uas.Location.SpeedHorizontal,
               uas.Location.Height, uas.Location.TimeStamp);
    if (uas.SystemValid)
        printf("op_lat %.7f\nop_lon %.7f\n", uas.System.OperatorLatitude, uas.System.OperatorLongitude);
    for (int p = 0; p < ODID_AUTH_MAX_PAGES; p++) {
        if (!uas.AuthValid[p]) continue;
        ODID_Auth_data *a = &uas.Auth[p];
        printf("auth_page %d type %d", a->DataPage, a->AuthType);
        if (p == 0) printf(" last %d length %d ts %u", a->LastPageIndex, a->Length, a->Timestamp);
        printf(" data ");
        int n = p == 0 ? ODID_AUTH_PAGE_ZERO_DATA_SIZE : ODID_AUTH_PAGE_NONZERO_DATA_SIZE;
        for (int j = 0; j < n; j++) printf("%02X", a->AuthData[j]);
        printf("\n");
    }
    return 0;
}
