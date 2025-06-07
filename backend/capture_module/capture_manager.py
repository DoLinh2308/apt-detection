# capture_module/capture_manager.py
import time
import csv
import os
import sys
from collections import defaultdict

# Scapy needs root/admin privileges
try:
    from scapy.all import sniff, IP, TCP, UDP, Ether
except ImportError:
    print("ERROR: Scapy library not found.", file=sys.stderr)
    print("Please run: pip install scapy", file=sys.stderr)
    sys.exit(1)
except OSError as e:
     print(f"ERROR: OSError importing Scapy: {e}", file=sys.stderr)
     print("Ensure Npcap (Windows) or libpcap (Linux/macOS) is installed.", file=sys.stderr)
     print("Scapy might require root/administrator privileges to run.", file=sys.stderr)
     sys.exit(1)

from . import config
from .packet_processor import process_packet
from .feature_calculator import calculate_final_features

# Global dictionary to store active flows (managed within this module)
active_flows = {}
# Global packet counter (managed within this module)
packet_count = 0

def check_flow_timeouts(writer, current_time):
    """
    Checks for timed-out flows, calculates their features, writes them to CSV,
    and removes them from active_flows.

    Args:
        writer: csv.DictWriter instance for the output file.
        current_time: The current timestamp.

    Returns:
        True if any flows timed out and were written, False otherwise.
    """
    global active_flows
    timed_out_keys = []
    flows_written = False

    for key, flow_state in list(active_flows.items()): # Iterate over a copy of keys
        if current_time - flow_state['last_seen'] > config.IDLE_TIMEOUT:
            timed_out_keys.append(key)

    if timed_out_keys:
        print(f"\n--- Processing {len(timed_out_keys)} timed-out flows ---")
        for key in timed_out_keys:
            if key in active_flows: # Check again in case of race conditions (unlikely here)
                flow_state = active_flows.pop(key)
                final_features = calculate_final_features(flow_state, key)
                try:
                    writer.writerow(final_features)
                    # print(f"Saved flow {final_features.get('Flow ID', key)} to {config.OUTPUT_CSV_FILE}")
                    flows_written = True
                except Exception as e:
                    print(f"ERROR: Failed to write flow {key} to CSV: {e}", file=sys.stderr)
        print("-----------------------------------------------\n") 
    return flows_written

def process_remaining_flows(writer):
    """
    Processes all flows remaining in active_flows at the end of capture.

    Args:
        writer: csv.DictWriter instance for the output file.
    """
    global active_flows
    remaining_keys = list(active_flows.keys())
    if remaining_keys:
        print(f"\n--- Processing {len(remaining_keys)} remaining flows ---")
        while active_flows: # Process until empty
            key, flow_state = active_flows.popitem() # Efficiently get and remove
            final_features = calculate_final_features(flow_state, key)
            try:
                writer.writerow(final_features)
            except Exception as e:
                print(f"ERROR: Failed to write remaining flow {key} to CSV: {e}", file=sys.stderr)
        print(f"Finished writing remaining flows to {config.OUTPUT_CSV_FILE}")
    else:
        print("\nNo remaining flows in memory to process.")


def start_capture():
    """
    Main function to start the packet capture process.
    """
    global active_flows, packet_count
    active_flows = {} # Reset state if called multiple times
    packet_count = 0

    print(f"Starting packet capture on interface: {config.INTERFACE if config.INTERFACE else 'default'}...")
    print(f"Capture duration: {config.CAPTURE_DURATION} seconds")
    print(f"Idle timeout: {config.IDLE_TIMEOUT} seconds")
    print(f"Output CSV: {config.OUTPUT_CSV_FILE}")
    print("Press Ctrl+C to stop early.")

    # Ensure the output directory exists (if OUTPUT_CSV_FILE includes a path)
    output_dir = os.path.dirname(config.OUTPUT_CSV_FILE)
    if output_dir and not os.path.exists(output_dir):
        try:
            os.makedirs(output_dir)
            print(f"Created output directory: {output_dir}")
        except OSError as e:
            print(f"ERROR: Could not create output directory '{output_dir}': {e}", file=sys.stderr)
            return 

    csvfile = None 
    writer = None

    try:
        with open(config.OUTPUT_CSV_FILE, 'w', newline='', encoding='utf-8') as csvfile:
            writer = csv.DictWriter(csvfile, fieldnames=config.CSV_HEADER)
            writer.writeheader()
            print("CSV header written.")
            csvfile.flush()
            last_timeout_check = time.time()
            start_sniff_time = time.time()
            def packet_callback_wrapper(packet):
                nonlocal last_timeout_check, writer, csvfile, start_sniff_time
                global packet_count
                process_packet(packet, active_flows)
                packet_count += 1
                current_time = time.time()
                elapsed = current_time - start_sniff_time
                remaining = max(0, config.CAPTURE_DURATION - elapsed)
                print(f"\rProcessed: {packet_count} packets. Active flows: {len(active_flows)}. Time left: {remaining:.0f}s", end="")
                if packet_count % 1000 == 0 or current_time - last_timeout_check > 5.0:
                    if check_flow_timeouts(writer, current_time):
                        csvfile.flush() 
                    last_timeout_check = current_time
            print(f"\nSniffing for {config.CAPTURE_DURATION} seconds...")
            sniff(prn=packet_callback_wrapper, store=False, iface=config.INTERFACE, timeout=config.CAPTURE_DURATION)

            print(f"\n\nCapture finished after {config.CAPTURE_DURATION} seconds or timeout.")
            print(f"Total packets processed: {packet_count}")

            if writer and csvfile and not csvfile.closed:
                process_remaining_flows(writer)
                csvfile.flush()

    except PermissionError:
        print("\nERROR: Permission denied.", file=sys.stderr)
        print("Try running the script with administrator/root privileges.", file=sys.stderr)
        print("Also check write permissions for the output file/directory.", file=sys.stderr)
    except OSError as e:
         if "No such device" in str(e) or "Interface not found" in str(e) :
              print(f"\nERROR: Network interface '{config.INTERFACE}' not found. Check available interfaces.", file=sys.stderr)
         elif "Permission denied" in str(e): # Could be file write permission
              print(f"\nERROR: Permission denied writing to '{config.OUTPUT_CSV_FILE}'. Check permissions.", file=sys.stderr)
         else:
              print(f"\nERROR: OSError during capture: {e}", file=sys.stderr)
    except KeyboardInterrupt:
        print("\nCapture stopped by user (Ctrl+C).")
        # Process remaining flows even if stopped early
        if writer and csvfile and not csvfile.closed:
            print("Processing remaining flows before exit...")
            process_remaining_flows(writer)
            csvfile.flush()
    except Exception as e:
        print(f"\nERROR: An unexpected error occurred during capture: {e}", file=sys.stderr)
        import traceback
        traceback.print_exc()
    finally:
        print("Capture process cleanup complete.")

