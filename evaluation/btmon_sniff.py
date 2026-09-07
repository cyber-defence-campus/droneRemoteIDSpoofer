import subprocess
import re

# ANSI escape codes
RED = "\033[31m"
YELLOW = "\033[33m"
CYAN = "\033[36m"
RESET = "\033[0m"

def monitor_btmon():
    # Force line-buffered output to ensure real-time processing
    process = subprocess.Popen(['btmon'], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)

    print(f"{YELLOW}Monitoring btmon: Tracking timestamps from event headers...{RESET}")
    
    # Matches the header line: > HCI Event: LE Meta Event (0x3e) ... #78 [hci1] 1.841773
    # We capture the float at the very end of the line.
    re_header_timestamp = re.compile(r"#\d+ \[hci\d+\] (\d+\.\d+)\s*$")
    
    re_event_start = re.compile(r"LE Advertising Set Terminated", re.IGNORECASE)
    re_status = re.compile(r"Status:\s*(.*?)\s*\(0x", re.IGNORECASE)
    re_count = re.compile(r"Number of completed extended advertising events:\s*(\d+)", re.IGNORECASE)

    last_alert_timestamp = None
    current_packet_timestamp = None
    in_term_event = False
    status = None

    try:
        for line in process.stdout:
            clean_line = line.strip()

            # 1. Check every line for the HCI Header timestamp
            # Even if it's not our event yet, we track the 'current' time of the log
            header_match = re_header_timestamp.search(clean_line)
            if header_match:
                current_packet_timestamp = float(header_match.group(1))

            # 2. Look for the start of the Termination event
            if re_event_start.search(clean_line):
                in_term_event = True
                # This is the timestamp associated with the ACTUAL event we care about
                active_event_time = current_packet_timestamp
                status = None
                continue

            if in_term_event:
                # 3. Capture the Status
                status_match = re_status.search(clean_line)
                if status_match:
                    status = status_match.group(1).strip()

                # 4. Capture the Completion Count (The "End" of the block)
                count_match = re_count.search(clean_line)
                if count_match:
                    count = int(count_match.group(1))

                    # Logic: Alert on errors, ignore "Cancelled" if events > 0
                    is_error = status and status.lower() != "success"
                    is_ignorable_cancel = (status and "cancelled" in status.lower() and count > 0)

                    if is_error and not is_ignorable_cancel:
                        gap_str = "N/A (First Event)"
                        
                        if last_alert_timestamp is not None and active_event_time is not None:
                            gap = active_event_time - last_alert_timestamp
                            gap_str = f"{gap:.6f} seconds"
                        
                        print(f"{RED}--- WARNING: UNEXPECTED TERMINATION ---{RESET}")
                        print(f"{RED}Status:{RESET} {status}")
                        print(f"{RED}Events Completed:{RESET} {count}")
                        print(f"{CYAN}Time Gap (since last fail):{RESET} {gap_str}")
                        print(f"{CYAN}Event Timestamp:{RESET} {active_event_time}")
                        print("-" * 45)
                        
                        # Update the alert clock
                        last_alert_timestamp = active_event_time
                    
                    # Exit the block
                    in_term_event = False

    except KeyboardInterrupt:
        process.terminate()
        print("\nMonitor stopped.")

if __name__ == "__main__":
    try:
        monitor_btmon()
    except PermissionError:
        print("Error: Run with sudo.")