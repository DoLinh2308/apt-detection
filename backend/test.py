#!/usr/bin/env python
import re
import time
import statistics
from collections import defaultdict, deque
import csv
import os
import logging
import pandas as pd
import numpy as np
import joblib
from datetime import datetime, timedelta
import collections # Already imported via defaultdict, deque

# Scapy import with error handling
try:
    from scapy.all import sniff, IP, TCP, UDP, Ether
except ImportError:
    print("FATAL ERROR: Scapy library not found.")
    print("Please install it using: pip install scapy")
    exit(1)
except OSError as e:
    print(f"FATAL ERROR: OSError importing Scapy: {e}")
    print("Ensure Npcap (Windows) or libpcap (Linux/macOS) is installed and Scapy has permissions.")
    print("Try running the script with administrator/root privileges.")
    exit(1)
except Exception as e:
    print(f"FATAL ERROR: An unexpected error occurred while importing Scapy: {e}")
    exit(1)


# --- Unified Configuration ---

# Part 1: Capture Configuration
INTERFACE = None  # None for default, or specify e.g., "eth0", "Wi-Fi"
IDLE_TIMEOUT = 60 # Seconds before a flow is considered inactive and processed
CAPTURE_DURATION = 120 # Seconds to capture packets (adjust as needed)

# Shared File Path (Output for Capture, Input for Prediction)
# Define the base directory where the script is running or a specific output directory
# Using the directory of the script file itself
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__)) if '__file__' in locals() else '.'
FLOW_DATA_CSV_PATH = os.path.join(SCRIPT_DIR, 'network_flows.csv') # Unified path

# Part 2: Prediction Configuration
MODEL_PATH = r'D:/Do_an_tot_nghiep/apt-detection/ai_model/dataset/working2/random_forest_model.pkl'
SCALER_PATH = r'D:/Do_an_tot_nghiep/apt-detection/ai_model/dataset/working2/scaler.pkl'

# Tùy chọn: Đặt tên tệp đầu ra cho kết quả dự đoán
PREDICTIONS_OUTPUT_CSV_PATH = FLOW_DATA_CSV_PATH.replace('.csv', '_Predictions.csv')
SUSPICIOUS_FLOWS_OUTPUT_CSV_PATH = FLOW_DATA_CSV_PATH.replace('.csv', '_Suspicious_Flows.csv')


# --- Logging Configuration ---
LOG_LEVEL = logging.INFO # Hoặc logging.DEBUG để xem chi tiết hơn
LOG_FORMAT = '%(asctime)s - %(levelname)s - [%(filename)s:%(lineno)d] - %(message)s' # Thêm tên file và dòng cho dễ debug
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__)) if '__file__' in locals() else '.'
LOG_FILE_PATH = os.path.join(SCRIPT_DIR, 'network_analysis.log') # Tên file log (sẽ lưu trong cùng thư mục script)

# --- Logging Setup ---
logger = logging.getLogger() # Lấy logger gốc
logger.setLevel(LOG_LEVEL) # Đặt mức log tổng thể

# Xóa các handler cũ nếu có (để tránh log bị lặp lại nếu script chạy lại trong cùng môi trường)
if logger.hasHandlers():
    logger.handlers.clear()

# Tạo formatter chung
formatter = logging.Formatter(LOG_FORMAT)

# 1. Cấu hình Console Handler (để vẫn thấy log trên màn hình)
console_handler = logging.StreamHandler()
console_handler.setLevel(LOG_LEVEL) # Mức log cho console
console_handler.setFormatter(formatter)
logger.addHandler(console_handler)

# 2. Cấu hình File Handler (để lưu log vào file)
try:
    # mode='a' để ghi nối tiếp vào file, không xóa log cũ mỗi lần chạy
    # encoding='utf-8' để hỗ trợ ký tự đặc biệt
    file_handler = logging.FileHandler(LOG_FILE_PATH, mode='a', encoding='utf-8')
    file_handler.setLevel(LOG_LEVEL) # Mức log cho file
    file_handler.setFormatter(formatter)
    logger.addHandler(file_handler)
    # Ghi log đầu tiên để xác nhận file handler hoạt động
    logging.info(f"Logging initialized. Output will be sent to console and file: {LOG_FILE_PATH}")
except PermissionError:
    logging.error(f"Permission denied: Cannot write to log file {LOG_FILE_PATH}. Check permissions.")
    # Log sẽ chỉ xuất hiện trên console nếu không ghi được file
except Exception as e:
    logging.error(f"Failed to configure file logging to {LOG_FILE_PATH}: {e}", exc_info=True)
    # Log sẽ chỉ xuất hiện trên console nếu có lỗi khác

# --- Part 1: Packet Capture and Flow Generation Code ---

active_flows = {} # Global dictionary to store active flows

# QUAN TRỌNG: This header list MUST match the keys returned by calculate_final_features
CSV_HEADER = [
    'Flow ID', 'Src IP', 'Src Port', 'Dst IP', 'Dst Port', 'Protocol',
    'Timestamp', # Flow end/processing time
    'Flow Duration', 'Tot Fwd Pkts', 'Tot Bwd Pkts', 'TotLen Fwd Pkts', 'TotLen Bwd Pkts',
    'Fwd Pkt Len Max', 'Fwd Pkt Len Min', 'Fwd Pkt Len Mean', 'Fwd Pkt Len Std',
    'Bwd Pkt Len Max', 'Bwd Pkt Len Min', 'Bwd Pkt Len Mean', 'Bwd Pkt Len Std',
    'Flow Byts/s', 'Flow Pkts/s',
    'Flow IAT Mean', 'Flow IAT Std', 'Flow IAT Max', 'Flow IAT Min',
    'Fwd IAT Tot', 'Fwd IAT Mean', 'Fwd IAT Std', 'Fwd IAT Max', 'Fwd IAT Min',
    'Bwd IAT Tot', 'Bwd IAT Mean', 'Bwd IAT Std', 'Bwd IAT Max', 'Bwd IAT Min',
    'Fwd PSH Flags', 'Fwd URG Flags', 'Bwd PSH Flags', 'Bwd URG Flags', # Added Bwd flags
    'Fwd Header Len', 'Bwd Header Len', 'Fwd Pkts/s', 'Bwd Pkts/s',
    'Pkt Len Min', 'Pkt Len Max', 'Pkt Len Mean', 'Pkt Len Std', 'Pkt Len Var',
    'FIN Flag Cnt', 'SYN Flag Cnt', 'RST Flag Cnt', 'PSH Flag Cnt', 'ACK Flag Cnt',
    'URG Flag Cnt', 'CWE Flag Count', 'ECE Flag Cnt', 'Down/Up Ratio', 'Pkt Size Avg',
    'Fwd Seg Size Avg', 'Bwd Seg Size Avg',
    'Fwd Byts/b Avg', 'Fwd Pkts/b Avg', 'Fwd Blk Rate Avg', # Placeholders
    'Bwd Byts/b Avg', 'Bwd Pkts/b Avg', 'Bwd Blk Rate Avg', # Placeholders
    'Subflow Fwd Pkts', 'Subflow Fwd Byts', 'Subflow Bwd Pkts', 'Subflow Bwd Byts',
    'Init Fwd Win Byts', 'Init Bwd Win Byts', 'Fwd Act Data Pkts', 'Fwd Seg Size Min',
    'Active Mean', 'Active Std', 'Active Max', 'Active Min',
    'Idle Mean', 'Idle Std', 'Idle Max', 'Idle Min',
    'Protocol_0', 'Protocol_6', 'Protocol_17' # One-hot encoded protocol
]

def initialize_flow_state():
    """Initializes a dictionary to store flow state."""
    current_time = time.time()
    return {
        'start_time': current_time, 'last_seen': current_time,
        'src_ip': None, 'dst_ip': None, 'src_port': None, 'dst_port': None, 'protocol': None,
        'fwd_packet_count': 0, 'fwd_total_bytes': 0, 'fwd_timestamps': [], 'fwd_pkt_lengths': [],
        'fwd_header_bytes': 0, 'fwd_psh_flags': 0, 'fwd_urg_flags': 0,
        'bwd_packet_count': 0, 'bwd_total_bytes': 0, 'bwd_timestamps': [], 'bwd_pkt_lengths': [],
        'bwd_header_bytes': 0, 'bwd_psh_flags': 0, 'bwd_urg_flags': 0,
        'fin_flag_count': 0, 'syn_flag_count': 0, 'rst_flag_count': 0,
        'psh_flag_count': 0, 'ack_flag_count': 0, 'urg_flag_count': 0,
        'cwe_flag_count': 0, 'ece_flag_count': 0,
        'all_timestamps_ordered': [],
        # 'active_periods': [], 'idle_periods': [], 'last_active_transition': current_time, # Complex - omit for now
        'flow_id': None, 'src_init_win_bytes': -1, 'dst_init_win_bytes': -1,
        'fwd_data_pkt_count': 0, 'fwd_min_seg_size': float('inf'),
    }

def process_packet(packet):
    """Processes a single packet and updates the corresponding flow state."""
    global active_flows
    current_time = time.time()

    if not packet.haslayer(IP): return
    ip_layer = packet.getlayer(IP)
    proto = ip_layer.proto
    src_ip = ip_layer.src
    dst_ip = ip_layer.dst
    src_port, dst_port, tcp_flags = None, None, None
    packet_len = len(packet) # Use the total packet length as often expected
    ip_header_len = ip_layer.ihl * 4
    header_len = ip_header_len
    init_win = -1

    # Handle TCP and UDP layers
    if packet.haslayer(TCP):
        tcp_layer = packet.getlayer(TCP)
        src_port, dst_port = tcp_layer.sport, tcp_layer.dport
        tcp_flags = tcp_layer.flags
        header_len += tcp_layer.dataofs * 4
        init_win = tcp_layer.window
    elif packet.haslayer(UDP):
        udp_layer = packet.getlayer(UDP)
        src_port, dst_port = udp_layer.sport, udp_layer.dport
        header_len += 8 # UDP header is 8 bytes
    else:
        return # Ignore non-TCP/UDP packets for flow analysis

    actual_payload_len = packet_len - header_len
    if actual_payload_len < 0: actual_payload_len = 0

    # Create a canonical flow key (lowest IP/Port first)
    flow_key_part1 = (src_ip, src_port)
    flow_key_part2 = (dst_ip, dst_port)
    # Ensure consistent ordering for the key
    if flow_key_part1 > flow_key_part2:
        flow_key_part1, flow_key_part2 = flow_key_part2, flow_key_part1
    flow_key = flow_key_part1 + flow_key_part2 + (proto,)

    # Initialize flow if it's new
    if flow_key not in active_flows:
        active_flows[flow_key] = initialize_flow_state()
        flow = active_flows[flow_key]
        # Store the actual first packet's direction info
        flow['flow_id'] = f"{src_ip}:{src_port}-{dst_ip}:{dst_port}-{proto}"
        flow['src_ip'] = src_ip
        flow['dst_ip'] = dst_ip
        flow['src_port'] = src_port
        flow['dst_port'] = dst_port
        flow['protocol'] = proto
        # Capture initial window size based on the first packet's direction
        if proto == 6: # TCP
             flow['src_init_win_bytes'] = init_win # Assume first packet defines 'src' for this flow context
    else:
        flow = active_flows[flow_key]


    # Update general flow state
    flow['last_seen'] = current_time
    flow['all_timestamps_ordered'].append(current_time)

    # Determine packet direction based on the *initial* direction stored in the flow state
    is_forward = (src_ip == flow['src_ip'] and src_port == flow['src_port'] and
                  dst_ip == flow['dst_ip'] and dst_port == flow['dst_port'])

    # Update direction-specific counters
    if is_forward:
        flow['fwd_packet_count'] += 1
        flow['fwd_total_bytes'] += packet_len
        flow['fwd_timestamps'].append(current_time)
        flow['fwd_pkt_lengths'].append(packet_len)
        flow['fwd_header_bytes'] += header_len
        if actual_payload_len > 0: flow['fwd_data_pkt_count'] += 1
        if tcp_flags is not None:
            if 'P' in tcp_flags: flow['fwd_psh_flags'] += 1
            if 'U' in tcp_flags: flow['fwd_urg_flags'] += 1
        # Capture initial window size if not already set (should be set on first packet)
        if proto == 6 and flow['src_init_win_bytes'] == -1:
             flow['src_init_win_bytes'] = init_win
        if proto == 6: # TCP Min segment size
            flow['fwd_min_seg_size'] = min(flow['fwd_min_seg_size'], header_len)

    else: # Backward direction
        flow['bwd_packet_count'] += 1
        flow['bwd_total_bytes'] += packet_len
        flow['bwd_timestamps'].append(current_time)
        flow['bwd_pkt_lengths'].append(packet_len)
        flow['bwd_header_bytes'] += header_len
        if tcp_flags is not None:
            if 'P' in tcp_flags: flow['bwd_psh_flags'] += 1
            if 'U' in tcp_flags: flow['bwd_urg_flags'] += 1
        # Capture initial window size for backward direction on its first packet
        if proto == 6 and flow['dst_init_win_bytes'] == -1:
             flow['dst_init_win_bytes'] = init_win

    # Update overall TCP flag counts
    if tcp_flags is not None:
        if 'F' in tcp_flags: flow['fin_flag_count'] += 1
        if 'S' in tcp_flags: flow['syn_flag_count'] += 1
        if 'R' in tcp_flags: flow['rst_flag_count'] += 1
        if 'P' in tcp_flags: flow['psh_flag_count'] += 1 # Overall PSH count
        if 'A' in tcp_flags: flow['ack_flag_count'] += 1
        if 'U' in tcp_flags: flow['urg_flag_count'] += 1 # Overall URG count
        if 'C' in tcp_flags: flow['cwe_flag_count'] += 1
        if 'E' in tcp_flags: flow['ece_flag_count'] += 1


def calculate_final_features(flow_state, flow_key_tuple):
    """Calculates derived features from the final flow state."""
    features = {}
    # Use microsecond precision for duration as often expected by CICFlowMeter features
    flow_duration_sec = flow_state['last_seen'] - flow_state['start_time']
    flow_duration_usec = flow_duration_sec * 1_000_000 # Microseconds

    # Basic flow identifiers (using the stored initial direction)
    features['Flow ID'] = flow_state.get('flow_id', '-'.join(map(str, flow_key_tuple)))
    features['Src IP'] = flow_state['src_ip']
    features['Src Port'] = flow_state['src_port']
    features['Dst IP'] = flow_state['dst_ip']
    features['Dst Port'] = flow_state['dst_port']
    features['Protocol'] = flow_state['protocol']
    # Timestamp of the *last* packet seen for the flow
    # CICFlowMeter format often like 'DD/MM/YYYY HH:MM:SS AM/PM' or ISO
    # Using ISO format YYYY-MM-DD HH:MM:SS for simplicity now, adjust if needed
    features['Timestamp'] = datetime.fromtimestamp(flow_state['last_seen']).strftime('%Y-%m-%d %H:%M:%S.%f')[:-3] # Millisecond precision

    # --- Feature Calculations ---
    features['Flow Duration'] = int(flow_duration_usec) # Integer microseconds
    features['Tot Fwd Pkts'] = flow_state['fwd_packet_count']
    features['Tot Bwd Pkts'] = flow_state['bwd_packet_count']
    features['TotLen Fwd Pkts'] = sum(flow_state['fwd_pkt_lengths']) # Recalculate sum for safety
    features['TotLen Bwd Pkts'] = sum(flow_state['bwd_pkt_lengths']) # Recalculate sum
    features['Fwd Header Len'] = flow_state['fwd_header_bytes'] # Total header bytes in fwd direction
    features['Bwd Header Len'] = flow_state['bwd_header_bytes'] # Total header bytes in bwd direction
    features['Init Fwd Win Byts'] = flow_state['src_init_win_bytes']
    features['Init Bwd Win Byts'] = flow_state['dst_init_win_bytes']
    features['Fwd Act Data Pkts'] = flow_state['fwd_data_pkt_count'] # Packets with payload > 0
    features['Fwd Seg Size Min'] = flow_state['fwd_min_seg_size'] if flow_state['fwd_min_seg_size'] != float('inf') else 0 # Min header size observed

    # Packet Length statistics
    fwd_pkts = flow_state['fwd_pkt_lengths']
    bwd_pkts = flow_state['bwd_pkt_lengths']
    all_pkts = fwd_pkts + bwd_pkts
    features['Fwd Pkt Len Max'] = float(max(fwd_pkts)) if fwd_pkts else 0.0
    features['Fwd Pkt Len Min'] = float(min(fwd_pkts)) if fwd_pkts else 0.0
    features['Fwd Pkt Len Mean'] = float(statistics.mean(fwd_pkts)) if fwd_pkts else 0.0
    features['Fwd Pkt Len Std'] = float(statistics.stdev(fwd_pkts)) if len(fwd_pkts) > 1 else 0.0
    features['Bwd Pkt Len Max'] = float(max(bwd_pkts)) if bwd_pkts else 0.0
    features['Bwd Pkt Len Min'] = float(min(bwd_pkts)) if bwd_pkts else 0.0
    features['Bwd Pkt Len Mean'] = float(statistics.mean(bwd_pkts)) if bwd_pkts else 0.0
    features['Bwd Pkt Len Std'] = float(statistics.stdev(bwd_pkts)) if len(bwd_pkts) > 1 else 0.0
    features['Pkt Len Min'] = float(min(all_pkts)) if all_pkts else 0.0
    features['Pkt Len Max'] = float(max(all_pkts)) if all_pkts else 0.0
    features['Pkt Len Mean'] = float(statistics.mean(all_pkts)) if all_pkts else 0.0
    features['Pkt Len Std'] = float(statistics.stdev(all_pkts)) if len(all_pkts) > 1 else 0.0
    features['Pkt Len Var'] = float(statistics.variance(all_pkts)) if len(all_pkts) > 1 else 0.0
    features['Pkt Size Avg'] = features['Pkt Len Mean'] # Average packet size
    features['Fwd Seg Size Avg'] = features['Fwd Pkt Len Mean'] # Avg Fwd packet size
    features['Bwd Seg Size Avg'] = features['Bwd Pkt Len Mean'] # Avg Bwd packet size

    # Rate features (handle division by zero)
    if flow_duration_sec > 0:
        features['Flow Byts/s'] = (features['TotLen Fwd Pkts'] + features['TotLen Bwd Pkts']) / flow_duration_sec
        features['Flow Pkts/s'] = (features['Tot Fwd Pkts'] + features['Tot Bwd Pkts']) / flow_duration_sec
        features['Fwd Pkts/s'] = features['Tot Fwd Pkts'] / flow_duration_sec
        features['Bwd Pkts/s'] = features['Tot Bwd Pkts'] / flow_duration_sec
    else: # Avoid NaN/Inf, set to 0 or a very large number if that makes sense for the model
        features['Flow Byts/s'] = 0.0
        features['Flow Pkts/s'] = 0.0
        features['Fwd Pkts/s'] = 0.0
        features['Bwd Pkts/s'] = 0.0

    # TCP Flag features
    features['FIN Flag Cnt'] = flow_state['fin_flag_count']
    features['SYN Flag Cnt'] = flow_state['syn_flag_count']
    features['RST Flag Cnt'] = flow_state['rst_flag_count']
    features['PSH Flag Cnt'] = flow_state['psh_flag_count'] # Overall PSH
    features['ACK Flag Cnt'] = flow_state['ack_flag_count']
    features['URG Flag Cnt'] = flow_state['urg_flag_count'] # Overall URG
    features['CWE Flag Count'] = flow_state['cwe_flag_count'] # CWR flag count
    features['ECE Flag Cnt'] = flow_state['ece_flag_count']
    features['Fwd PSH Flags'] = flow_state['fwd_psh_flags'] # PSH in Fwd direction
    features['Fwd URG Flags'] = flow_state['fwd_urg_flags'] # URG in Fwd direction
    features['Bwd PSH Flags'] = flow_state['bwd_psh_flags'] # PSH in Bwd direction
    features['Bwd URG Flags'] = flow_state['bwd_urg_flags'] # URG in Bwd direction

    # Down/Up Ratio
    features['Down/Up Ratio'] = float(features['Tot Bwd Pkts'] / features['Tot Fwd Pkts']) if features['Tot Fwd Pkts'] > 0 else 0.0

    # Inter-Arrival Time (IAT) statistics (in microseconds)
    all_iats = [(t - s) * 1_000_000 for s, t in zip(flow_state['all_timestamps_ordered'], flow_state['all_timestamps_ordered'][1:])]
    fwd_iats = [(t - s) * 1_000_000 for s, t in zip(flow_state['fwd_timestamps'], flow_state['fwd_timestamps'][1:])]
    bwd_iats = [(t - s) * 1_000_000 for s, t in zip(flow_state['bwd_timestamps'], flow_state['bwd_timestamps'][1:])]

    features['Flow IAT Mean'] = float(statistics.mean(all_iats)) if all_iats else 0.0
    features['Flow IAT Std'] = float(statistics.stdev(all_iats)) if len(all_iats) > 1 else 0.0
    features['Flow IAT Max'] = float(max(all_iats)) if all_iats else 0.0
    features['Flow IAT Min'] = float(min(all_iats)) if all_iats else 0.0

    # Fwd IAT Total = Time between first and last Fwd packet
    fwd_iat_total_usec = (flow_state['fwd_timestamps'][-1] - flow_state['fwd_timestamps'][0]) * 1_000_000 if len(flow_state['fwd_timestamps']) > 1 else 0
    features['Fwd IAT Tot'] = float(fwd_iat_total_usec)
    features['Fwd IAT Mean'] = float(statistics.mean(fwd_iats)) if fwd_iats else 0.0
    features['Fwd IAT Std'] = float(statistics.stdev(fwd_iats)) if len(fwd_iats) > 1 else 0.0
    features['Fwd IAT Max'] = float(max(fwd_iats)) if fwd_iats else 0.0
    features['Fwd IAT Min'] = float(min(fwd_iats)) if fwd_iats else 0.0

    # Bwd IAT Total = Time between first and last Bwd packet
    bwd_iat_total_usec = (flow_state['bwd_timestamps'][-1] - flow_state['bwd_timestamps'][0]) * 1_000_000 if len(flow_state['bwd_timestamps']) > 1 else 0
    features['Bwd IAT Tot'] = float(bwd_iat_total_usec)
    features['Bwd IAT Mean'] = float(statistics.mean(bwd_iats)) if bwd_iats else 0.0
    features['Bwd IAT Std'] = float(statistics.stdev(bwd_iats)) if len(bwd_iats) > 1 else 0.0
    features['Bwd IAT Max'] = float(max(bwd_iats)) if bwd_iats else 0.0
    features['Bwd IAT Min'] = float(min(bwd_iats)) if bwd_iats else 0.0

    # Protocol One-Hot Encoding (Example: 0=HOPOPT, 6=TCP, 17=UDP)
    proto = flow_state['protocol']
    features['Protocol_0'] = 1 if proto == 0 else 0
    features['Protocol_6'] = 1 if proto == 6 else 0
    features['Protocol_17'] = 1 if proto == 17 else 0
    # Add more protocols if needed by the model

    # --- Placeholder Features (Not Implemented) ---
    # Ensure these keys exist, matching the CSV_HEADER, even if value is 0 or None
    # These likely require more complex state or analysis (e.g., subflows, bulk rates)
    placeholders = [
        'Fwd Byts/b Avg', 'Fwd Pkts/b Avg', 'Fwd Blk Rate Avg',
        'Bwd Byts/b Avg', 'Bwd Pkts/b Avg', 'Bwd Blk Rate Avg',
        'Subflow Fwd Pkts', 'Subflow Fwd Byts', 'Subflow Bwd Pkts', 'Subflow Bwd Byts',
        'Active Mean', 'Active Std', 'Active Max', 'Active Min', # Requires active/idle period detection
        'Idle Mean', 'Idle Std', 'Idle Max', 'Idle Min'      # Requires active/idle period detection
    ]
    for ph in placeholders:
        features[ph] = 0.0 # Use float 0.0 as a default

    # Ensure all expected columns are present before returning
    final_feature_dict = {col: features.get(col, 0.0) for col in CSV_HEADER} # Default to 0.0 if missing
    # Overwrite non-numeric defaults where necessary
    final_feature_dict['Flow ID'] = features.get('Flow ID', 'Unknown')
    final_feature_dict['Src IP'] = features.get('Src IP', '0.0.0.0')
    final_feature_dict['Src Port'] = features.get('Src Port', 0)
    final_feature_dict['Dst IP'] = features.get('Dst IP', '0.0.0.0')
    final_feature_dict['Dst Port'] = features.get('Dst Port', 0)
    final_feature_dict['Protocol'] = features.get('Protocol', -1)
    final_feature_dict['Timestamp'] = features.get('Timestamp', datetime.now().strftime('%Y-%m-%d %H:%M:%S.%f')[:-3])


    return final_feature_dict


def check_flow_timeouts(writer, csvfile_handle, current_time):
    """Checks for timed-out flows, calculates features, writes to CSV, and removes them."""
    global active_flows
    timed_out_keys = []
    flows_processed_count = 0

    for key, flow_state in list(active_flows.items()): # Iterate over a copy of keys
        if current_time - flow_state['last_seen'] > IDLE_TIMEOUT:
            timed_out_keys.append(key)

    if timed_out_keys:
        logging.debug(f"Processing {len(timed_out_keys)} timed-out flows...")
        for key in timed_out_keys:
            if key in active_flows: # Check again as it might have been processed concurrently
                flow_state = active_flows.pop(key) # Get and remove the flow
                final_features = calculate_final_features(flow_state, key)
                try:
                    writer.writerow(final_features)
                    flows_processed_count += 1
                except Exception as e:
                    logging.error(f"Error writing flow {final_features.get('Flow ID', key)} to CSV: {e}")
        if flows_processed_count > 0:
             logging.info(f"Processed and wrote {flows_processed_count} timed-out flows to {FLOW_DATA_CSV_PATH}")
             csvfile_handle.flush() # Ensure data is written to disk
             return True # Indicate that flows were processed
    return False # No flows processed


def capture_and_save_flows():
    """Main function for capturing packets and saving flow data."""
    global active_flows # Ensure we're using the global dict
    active_flows = {} # Reset active flows at the start
    logging.info(f"Starting packet capture on interface: {INTERFACE if INTERFACE else 'default'}")
    logging.info(f"Capture duration: {CAPTURE_DURATION} seconds")
    logging.info(f"Flow idle timeout: {IDLE_TIMEOUT} seconds")
    logging.info(f"Output CSV: {FLOW_DATA_CSV_PATH}")
    print("Press Ctrl+C to stop capturing early.")

    # Check write permissions for output file *before* starting capture
    try:
        with open(FLOW_DATA_CSV_PATH, 'w') as f:
            pass # Just test opening for writing
        os.remove(FLOW_DATA_CSV_PATH) # Remove the test file
    except PermissionError:
         logging.error(f"Permission denied: Cannot write to {FLOW_DATA_CSV_PATH}.")
         print(f"ERROR: Permission denied writing to {FLOW_DATA_CSV_PATH}. Check directory permissions.")
         return False # Indicate failure
    except Exception as e:
        logging.error(f"Error checking write permissions for {FLOW_DATA_CSV_PATH}: {e}")
        print(f"ERROR: Could not verify write permissions for {FLOW_DATA_CSV_PATH}: {e}")
        return False # Indicate failure


    # --- Scapy Sniffing Setup ---
    packet_count = 0
    last_timeout_check = time.time()
    start_sniff_time = time.time()
    writer = None
    csvfile = None

    def packet_callback(packet):
        nonlocal packet_count, last_timeout_check, writer, csvfile, start_sniff_time
        try:
            process_packet(packet)
            packet_count += 1
            current_time = time.time()

            # Periodic logging/status update
            if packet_count % 5000 == 0: # Log every 5000 packets
                 elapsed_time = current_time - start_sniff_time
                 rate = packet_count / elapsed_time if elapsed_time > 0 else 0
                 logging.info(f"Processed {packet_count} packets... ({rate:.2f} pkt/s). Active flows: {len(active_flows)}")

            # Periodic timeout check
            if current_time - last_timeout_check > 5.0: # Check every 5 seconds
                if writer and csvfile: # Ensure writer/file are ready
                    check_flow_timeouts(writer, csvfile, current_time)
                last_timeout_check = current_time

        except Exception as e:
            logging.error(f"Error processing packet #{packet_count}: {e}", exc_info=True)


    try:
        # Open CSV file and prepare writer *before* starting sniff
        with open(FLOW_DATA_CSV_PATH, 'w', newline='', encoding='utf-8') as csvfile_local:
            csvfile = csvfile_local # Assign to outer scope variable
            writer = csv.DictWriter(csvfile, fieldnames=CSV_HEADER, extrasaction='ignore') # Ignore extra fields if any
            writer.writeheader()
            csvfile.flush()
            logging.info("CSV header written.")

            # Start sniffing
            logging.info(f"Sniffing started for {CAPTURE_DURATION} seconds...")
            sniff(prn=packet_callback, store=False, iface=INTERFACE, timeout=CAPTURE_DURATION)
            logging.info(f"Sniffing completed after {CAPTURE_DURATION} seconds or timeout.")

    except PermissionError:
        logging.error("Permission denied: Cannot capture packets. Try running as root/administrator.")
        print("\nERROR: Permission denied. Please run this script with administrator/root privileges.")
        return False # Indicate failure
    except OSError as e:
        if "No such device" in str(e) or "Interface not found" in str(e) :
            logging.error(f"Network interface '{INTERFACE}' not found.")
            print(f"\nERROR: Network interface '{INTERFACE}' not found. Check available interfaces.")
        else:
            logging.error(f"OS error during capture: {e}", exc_info=True)
            print(f"\nERROR: An OS error occurred during capture: {e}")
        return False # Indicate failure
    except KeyboardInterrupt:
        logging.warning("Capture stopped by user (Ctrl+C).")
        print("\nCapture stopped by user.")
    except Exception as e:
        logging.error(f"An unexpected error occurred during capture: {e}", exc_info=True)
        print(f"\nERROR: An unexpected error occurred during capture: {e}")
        return False # Indicate failure
    finally:
        # --- Final processing of remaining flows ---
        logging.info("Processing remaining active flows...")
        final_time = time.time()
        if writer and csvfile and not csvfile.closed:
            # Force check for any flows that timed out exactly at the end
            check_flow_timeouts(writer, csvfile, final_time + IDLE_TIMEOUT + 1)

            # Process all remaining flows regardless of timeout
            remaining_keys = list(active_flows.keys())
            if remaining_keys:
                 logging.info(f"Writing {len(remaining_keys)} remaining flows to CSV...")
                 flows_processed_count = 0
                 for key in remaining_keys:
                     if key in active_flows: # Check again
                          flow_state = active_flows.pop(key)
                          final_features = calculate_final_features(flow_state, key)
                          try:
                              writer.writerow(final_features)
                              flows_processed_count += 1
                          except Exception as e:
                              logging.error(f"Error writing final flow {final_features.get('Flow ID', key)} to CSV: {e}")
                 if flows_processed_count > 0:
                     logging.info(f"Wrote {flows_processed_count} final flows.")
                     try:
                        csvfile.flush()
                     except Exception as e:
                        logging.warning(f"Could not flush CSV file at the very end: {e}")

        else:
            logging.warning("CSV writer/file was not available for final flow processing.")

        total_duration = time.time() - start_sniff_time
        logging.info(f"Capture phase finished. Total packets processed: {packet_count}. Duration: {total_duration:.2f}s")
        print(f"Capture phase finished. Total packets processed: {packet_count}.")
        if not os.path.exists(FLOW_DATA_CSV_PATH) or os.path.getsize(FLOW_DATA_CSV_PATH) < len(','.join(CSV_HEADER)):
             logging.error("CSV file seems empty or missing after capture phase.")
             return False # Indicate failure if file is bad

    return True # Indicate success


# --- Part 2: Prediction Code ---

EXPECTED_FEATURES = None # Will be loaded from scaler if possible

def load_predict_and_save():
    """Loads flow data, pre-trained model/scaler, predicts, and saves results."""
    global EXPECTED_FEATURES # Allow modification of global variable

    logging.info("--- Starting Prediction Phase ---")

    # --- Load Model and Scaler ---
    logging.info("Loading model and scaler...")
    if not os.path.exists(MODEL_PATH):
        logging.error(f"FATAL: Model file not found at '{MODEL_PATH}'. Please update the path.")
        return # Stop prediction phase
    if not os.path.exists(SCALER_PATH):
        logging.error(f"FATAL: Scaler file not found at '{SCALER_PATH}'. Please update the path.")
        return # Stop prediction phase

    try:
        model = joblib.load(MODEL_PATH)
        scaler = joblib.load(SCALER_PATH)
        logging.info(f"Successfully loaded model from: {MODEL_PATH}")
        logging.info(f"Successfully loaded scaler from: {SCALER_PATH}")

        # Attempt to get feature names from scaler
        if hasattr(scaler, 'feature_names_in_'):
            EXPECTED_FEATURES = list(scaler.feature_names_in_)
            logging.info(f"Got {len(EXPECTED_FEATURES)} expected features from scaler.") #{EXPECTED_FEATURES[:10]}...")
        elif hasattr(scaler, 'n_features_in_') and isinstance(scaler.n_features_in_, int):
             logging.warning(f"Scaler has 'n_features_in_' ({scaler.n_features_in_}), but not 'feature_names_in_'. Cannot automatically get feature names/order.")
             # MUST define EXPECTED_FEATURES manually here if needed, otherwise it will fail later
             # Example: EXPECTED_FEATURES = ['Flow_Duration', 'Tot_Fwd_Pkts', ...] # Must match training order *exactly*
             if EXPECTED_FEATURES is None: # Check if it wasn't set manually
                 logging.error("FATAL: Could not get feature names from scaler, and EXPECTED_FEATURES was not defined manually. Cannot proceed.")
                 return
        else:
            logging.warning(f"Could not get feature names or count from scaler object. Type: {type(scaler)}")
            # MUST define EXPECTED_FEATURES manually here
            if EXPECTED_FEATURES is None:
                logging.error("FATAL: Could not get feature names from scaler, and EXPECTED_FEATURES was not defined manually. Cannot proceed.")
                return

        if EXPECTED_FEATURES:
            logging.info(f"Using features (first 10): {EXPECTED_FEATURES[:10]}")
        else:
             logging.error("FATAL: EXPECTED_FEATURES list is empty or None after loading scaler. Cannot proceed.")
             return


    except FileNotFoundError: # Should be caught by os.path.exists, but good practice
        logging.error(f"Error: Model ('{MODEL_PATH}') or scaler ('{SCALER_PATH}') file not found during load.")
        return
    except Exception as e:
        logging.error(f"Error loading model/scaler: {e}", exc_info=True)
        return

    # --- Read and Preprocess CSV from Capture Phase ---
    logging.info(f"Reading captured flow data from: {FLOW_DATA_CSV_PATH}")
    if not os.path.exists(FLOW_DATA_CSV_PATH):
        logging.error(f"FATAL: Input CSV file '{FLOW_DATA_CSV_PATH}' not found. Capture phase might have failed.")
        return
    if os.path.getsize(FLOW_DATA_CSV_PATH) < len(','.join(CSV_HEADER)): # Basic check if file has more than just header
         logging.error(f"FATAL: Input CSV file '{FLOW_DATA_CSV_PATH}' seems empty or only contains header. No data to predict.")
         return

    try:
        # Specify low_memory=False if there are mixed types warnings
        df = pd.read_csv(FLOW_DATA_CSV_PATH, low_memory=False)
        logging.info(f"Successfully read {len(df)} rows from {FLOW_DATA_CSV_PATH}.")
        if df.empty:
            logging.warning("CSV file loaded successfully, but it contains no data rows.")
            return # Nothing to predict

        # --- Preprocessing Steps ---
        df_original_cols = df.columns.tolist()
        df_original = df.copy() # Keep a copy if needed later

        # 1. Clean column names (make them valid Python identifiers)
        # logging.debug("Cleaning column names...")
        # df.columns = df.columns.str.strip()
        # df.columns = df.columns.str.replace('[^A-Za-z0-9_]+', '_', regex=True)
        # df.columns = df.columns.str.replace('_+', '_', regex=True) # Replace multiple underscores
        # df.columns = df.columns.str.lower() # Optional: convert to lowercase for consistency
        # renamed_cols = dict(zip(df_original_cols, df.columns))
        # logging.debug(f"Renamed columns map (sample): {list(renamed_cols.items())[:5]}")

        # Adjust EXPECTED_FEATURES to match cleaned column names
        # Corrected version using re.sub:
        if EXPECTED_FEATURES:
            logging.info(f"Original EXPECTED_FEATURES (first 10): {EXPECTED_FEATURES[:10]}")
            cleaned_expected_features = []
            for col in EXPECTED_FEATURES:
                col_stripped = col.strip()
                col_lower = col_stripped.lower()
                # Apply first regex substitution: replace non-alphanumeric/_ with _
                col_sub1 = re.sub(r'[^a-z0-9_]+', '_', col_lower)
                # Apply second regex substitution: replace multiple underscores with one
                col_sub2 = re.sub(r'_+', '_', col_sub1)
                cleaned_expected_features.append(col_sub2)

            EXPECTED_FEATURES = cleaned_expected_features
            logging.info(f"Adjusted EXPECTED_FEATURES to cleaned names using regex (first 10): {EXPECTED_FEATURES[:10]}")
        else:
            # This error handling part was likely already there and correct
            logging.error("FATAL: EXPECTED_FEATURES list is empty or None after loading scaler. Cannot proceed.")
            return
        logging.info(f"Adjusted EXPECTED_FEATURES to cleaned names (first 10): {EXPECTED_FEATURES[:10]}")


        # 2. Handle Timestamp (Crucial!)
        # Find the timestamp column (handle potential renaming)
        timestamp_col_original = 'Timestamp'
        timestamp_col = None
        # Define potential original names
        possible_ts_names = [timestamp_col_original, 'timestamp'] # Add other common names if needed

        logging.debug(f"Searching for timestamp column using potential names: {possible_ts_names}")
        logging.debug(f"Available columns after initial cleaning: {df.columns.tolist()}")

        for potential_name in possible_ts_names:
            # Tìm trực tiếp trong các cột đã strip()
            if potential_name in df.columns:
                timestamp_col = potential_name
                logging.info(f"Found timestamp column: '{timestamp_col}'")
                break
                
        if not timestamp_col:
            # If still not found, maybe log the columns again for debugging
            logging.error(f"FATAL: Timestamp column could not be found in the DataFrame after cleaning potential names {possible_ts_names}.")
            logging.error(f"DataFrame columns checked: {df.columns.tolist()}")
            return

        logging.info(f"Converting timestamp column '{timestamp_col}'...")
        # Try specific formats known to be used or generated
        ts_formats_to_try = [
            '%Y-%m-%d %H:%M:%S.%f', # Format used in capture script
            '%d/%m/%Y %I:%M:%S %p', # Common CICFlowMeter format 1
            '%d/%m/%Y %H:%M:%S',    # Common CICFlowMeter format 2
            '%Y-%m-%d %H:%M:%S'     # ISO format without milliseconds
        ]
        converted = False
        for fmt in ts_formats_to_try:
            try:
                df[timestamp_col] = pd.to_datetime(df[timestamp_col], format=fmt, errors='raise')
                logging.info(f"Timestamp converted successfully using format: {fmt}")
                converted = True
                break
            except (ValueError, TypeError):
                logging.debug(f"Timestamp format '{fmt}' did not match. Trying next...")
                df[timestamp_col] = df_original[timestamp_col_original] # Reset before trying next format

        if not converted:
            logging.warning("Specific timestamp formats failed. Trying automatic inference (infer_datetime_format=True)...")
            try:
                # errors='coerce' turns unparseable values into NaT (Not a Time)
                df[timestamp_col] = pd.to_datetime(df[timestamp_col], infer_datetime_format=True, errors='coerce')
                if df[timestamp_col].isnull().any():
                    failed_count = df[timestamp_col].isnull().sum()
                    logging.error(f"Timestamp conversion failed for {failed_count} rows using automatic inference. These rows might be dropped or cause issues.")
                    # Optional: Log problematic rows
                    # logging.error("Problematic timestamp rows (original values):\n" + df_original[df[timestamp_col].isnull()][timestamp_col_original].head().to_string())
                    # Option 1: Drop rows with NaT timestamps
                    logging.warning(f"Dropping {failed_count} rows with invalid timestamps.")
                    df.dropna(subset=[timestamp_col], inplace=True)
                    if df.empty:
                         logging.error("DataFrame is empty after dropping rows with invalid timestamps.")
                         return
                    # Option 2: Fill NaT (less ideal for time-based features) - df[timestamp_col] = df[timestamp_col].fillna(pd.Timestamp('1970-01-01'))
                else:
                    logging.info("Timestamp converted successfully using automatic inference.")
                    converted = True
            except Exception as e_infer:
                 logging.error(f"Critical error during automatic timestamp inference for column '{timestamp_col}': {e_infer}", exc_info=True)
                 return # Cannot proceed without valid timestamps

        if not converted:
            logging.error("FATAL: Could not convert timestamp column after trying multiple formats and inference.")
            return

        # 3. Handle Infinity and NaN
        logging.info("Handling Infinity and NaN values...")
        numeric_cols = df.select_dtypes(include=np.number).columns.tolist()

        # Replace Inf with NaN first
        inf_replaced_count = 0
        for col in numeric_cols:
            if np.isinf(df[col]).any():
                count = np.isinf(df[col]).sum()
                df[col] = df[col].replace([np.inf, -np.inf], np.nan)
                logging.debug(f"Replaced {count} Inf values with NaN in column '{col}'.")
                inf_replaced_count += count
        if inf_replaced_count > 0:
             logging.info(f"Total Inf values replaced with NaN: {inf_replaced_count}")

        # Fill NaN (now includes those from Inf)
        nan_counts_before = df[numeric_cols].isnull().sum()
        cols_with_nan = nan_counts_before[nan_counts_before > 0]
        if not cols_with_nan.empty:
            logging.warning(f"Found NaN values in numeric columns. Filling with 0. Columns affected:\n{cols_with_nan}")
            df[numeric_cols] = df[numeric_cols].fillna(0)
            # Verify NaNs are gone
            nan_counts_after = df[numeric_cols].isnull().sum().sum()
            if nan_counts_after == 0:
                 logging.info("Successfully filled NaN values in numeric columns with 0.")
            else:
                 logging.error("Failed to fill all NaN values. Some might remain.")
        else:
            logging.info("No NaN values found in numeric columns.")


        # 4. Ensure Numeric Types for Features
        logging.info("Ensuring expected features have numeric types...")
        converted_types_count = 0
        for col in EXPECTED_FEATURES:
            if col in df.columns and not pd.api.types.is_numeric_dtype(df[col]):
                logging.warning(f"Column '{col}' is not numeric (type: {df[col].dtype}). Attempting conversion...")
                try:
                    # Keep track of NaNs before conversion
                    nan_before = df[col].isnull().sum()
                    df[col] = pd.to_numeric(df[col], errors='coerce')
                    # Check for new NaNs created by coercion
                    nan_after = df[col].isnull().sum()
                    new_nans = nan_after - nan_before
                    if new_nans > 0:
                        logging.warning(f"Conversion of '{col}' created {new_nans} new NaN values. Filling them with 0.")
                        df[col] = df[col].fillna(0)
                    logging.info(f"Successfully converted column '{col}' to numeric.")
                    converted_types_count += 1
                except Exception as e_convert:
                    logging.error(f"Failed to convert column '{col}' to numeric: {e_convert}. Filling with 0.")
                    df[col] = 0 # Fill with 0 if conversion fails entirely
        if converted_types_count > 0:
             logging.info(f"Completed type conversions for {converted_types_count} columns.")

        # --- Optional: Calculate Dynamic/Behavioral Features ---
        # Only if the model was trained with them and they aren't in the CSV
        # Example: Time Since Last Flow, Rolling Window features
        # Requires sorting by timestamp first!
        logging.info("Sorting data by timestamp for potential dynamic feature calculation...")
        df = df.sort_values(by=timestamp_col).reset_index(drop=True)

        # Add dynamic feature calculations here if needed, similar to the original script 2
        # Ensure feature names generated here match the cleaned EXPECTED_FEATURES
        # Example: feature_time_since = 'time_since_last_flow_src_sec'
        # if feature_time_since in EXPECTED_FEATURES: ... calculate ...
        # Example: rolling_window_features = [...]
        # if any(f in EXPECTED_FEATURES for f in rolling_window_features): ... calculate ...


        # --- Prepare Data for Model ---
        logging.info("Preparing data for the model (selecting/ordering features)...")

        current_columns = df.columns.tolist()
        expected_set = set(EXPECTED_FEATURES)
        current_set = set(current_columns)

        missing_features = list(expected_set - current_set)
        extra_features = list(current_set - expected_set)

        # Handle Missing Features
        if missing_features:
            logging.warning(f"Missing {len(missing_features)} features required by the model: {missing_features}")
            logging.warning("Adding missing columns and filling with 0.0. This might impact prediction accuracy.")
            for col in missing_features:
                df[col] = 0.0 # Add as float
        else:
            logging.info("All expected features are present in the DataFrame.")

        # Handle Extra Features (Informational)
        if extra_features:
            logging.info(f"Found {len(extra_features)} extra columns not used by the model (will be ignored): {extra_features[:10]}...")


        # Select and Reorder Features
        logging.info(f"Selecting and reordering {len(EXPECTED_FEATURES)} features...")
        try:
            # Ensure all expected columns exist *before* selection
            final_expected_cols = [col for col in EXPECTED_FEATURES if col in df.columns]
            if len(final_expected_cols) != len(EXPECTED_FEATURES):
                 logging.error(f"Mismatch after handling missing columns. Expected {len(EXPECTED_FEATURES)}, found {len(final_expected_cols)} available.")
                 # This should not happen if the missing column handling worked
                 return

            X_test = df[EXPECTED_FEATURES].astype(float) # Select in correct order and ensure float type
        except KeyError as e:
            logging.error(f"FATAL: KeyError selecting features. Missing column: {e}. This should not happen after checks.", exc_info=True)
            return
        except Exception as e_select:
            logging.error(f"FATAL: Error during feature selection/ordering or type conversion: {e_select}", exc_info=True)
            # Try to identify the problematic column
            for col in EXPECTED_FEATURES:
                 if col in df:
                     try: df[col].astype(float)
                     except Exception as col_err: logging.error(f"  -> Column '{col}' might be causing the error: {col_err}")
                 else: logging.error(f"  -> Expected column '{col}' is missing!")
            return

        logging.info(f"Data prepared for model. Shape: {X_test.shape}")

        # --- Scale Data ---
        logging.info("Applying scaler to the data...")
        try:
            # Sanity check feature count consistency
            n_features_in_scaler = getattr(scaler, 'n_features_in_', None)
            if n_features_in_scaler is not None and n_features_in_scaler != X_test.shape[1]:
                 logging.error(f"FATAL: Feature count mismatch! Scaler expects {n_features_in_scaler} features, but data has {X_test.shape[1]}.")
                 logging.error(f"Data columns: {X_test.columns.tolist()}")
                 logging.error(f"Expected features (from scaler/manual): {EXPECTED_FEATURES}")
                 return

            X_test_scaled = scaler.transform(X_test)
        except ValueError as e:
            if "Input contains NaN" in str(e):
                logging.error("FATAL: ValueError applying scaler - Input data contains NaN values.")
                nan_check = X_test.isnull().sum()
                logging.error(f"NaN counts in features before scaling:\n{nan_check[nan_check > 0]}")
                logging.error("Review preprocessing steps (NaN/Inf handling, type conversion).")
            elif "features, but" in str(e): # Mismatch error message
                 logging.error(f"FATAL: ValueError applying scaler - Feature count mismatch. {e}")
            else:
                logging.error(f"FATAL: ValueError applying scaler: {e}", exc_info=True)
            return
        except Exception as e:
            logging.error(f"FATAL: Unexpected error applying scaler: {e}", exc_info=True)
            return

        logging.info("Data scaled successfully.")

        # --- Predict ---
        logging.info("Making predictions using the model...")
        try:
            predictions = model.predict(X_test_scaled)
            probabilities = None
            if hasattr(model, "predict_proba"):
                try:
                    probabilities = model.predict_proba(X_test_scaled)
                    # Get probability of the predicted class
                    prediction_probabilities = np.max(probabilities, axis=1)
                    logging.info("Predictions and probabilities obtained.")
                except Exception as e_proba:
                    logging.warning(f"Could not get prediction probabilities: {e_proba}")
                    prediction_probabilities = np.nan # Assign NaN or default value
            else:
                logging.info("Model does not support 'predict_proba'. Only predictions obtained.")
                prediction_probabilities = np.nan # Assign NaN or default value

        except Exception as e:
            logging.error(f"FATAL: Error during model prediction: {e}", exc_info=True)
            return

        logging.info("Prediction complete.")

        # --- Analyze and Save Results ---
        # Add predictions (and optionally probabilities) back to the original DataFrame
        # Use df_original if you want all original columns, or df if preprocessed is fine
        output_df = df # Use the preprocessed dataframe 'df'
        output_df['Prediction'] = predictions
        output_df['Prediction_Probability'] = prediction_probabilities # Add probabilities if available

        # Analyze results
        prediction_counts = output_df['Prediction'].value_counts()
        logging.info("\n--- Prediction Results Summary ---")
        print("\n--- Prediction Results Summary ---")
        print(prediction_counts)

        # Identify suspicious flows (assuming 'Benign' or 0 is normal)
        # Adapt these labels based on your model's output
        benign_labels = ['benign', 0, 'normal'] # Use lowercase due to cleaning
        actual_benign_labels_in_preds = [label for label in benign_labels if label in output_df['Prediction'].unique()]

        if actual_benign_labels_in_preds:
             logging.info(f"Identifying suspicious flows (not labeled as: {actual_benign_labels_in_preds})...")
             suspicious_condition = ~output_df['Prediction'].isin(actual_benign_labels_in_preds)
        else:
             logging.warning(f"No known benign labels {benign_labels} found in predictions. Considering all non-majority predictions as potentially suspicious or classifying all as suspicious.")
             # Option 1: Consider everything not the majority class suspicious
             # majority_class = prediction_counts.idxmax()
             # suspicious_condition = output_df['Prediction'] != majority_class
             # Option 2: Consider all flows suspicious if no benign label found
             suspicious_condition = pd.Series([True] * len(output_df), index=output_df.index)
             logging.warning("Marking ALL flows as suspicious due to absence of known benign labels.")


        suspicious_flows = output_df[suspicious_condition]
        num_suspicious = len(suspicious_flows)
        num_total = len(output_df)
        logging.info(f"Found {num_suspicious} suspicious flows out of {num_total} total flows ({num_suspicious/num_total:.2%} suspicious).")
        print(f"Found {num_suspicious} suspicious flows out of {num_total} total flows.")

        # Display sample suspicious flows
        if not suspicious_flows.empty:
            print("\nSample Suspicious Flows:")
            # Select important columns for display (use cleaned names)
            display_cols = [
                 timestamp_col, 'flow_id', 'src_ip', 'src_port', 'dst_ip', 'dst_port', 'protocol',
                 'prediction', 'prediction_probability' # Use lowercase cleaned names
             ]
            # Filter display_cols to only those existing in output_df
            display_cols_existing = [col for col in display_cols if col in output_df.columns]
            print(suspicious_flows[display_cols_existing].head(10).to_string()) # Use to_string for better console format

        # Save results
        try:
            logging.info(f"Saving all flows with predictions to: {PREDICTIONS_OUTPUT_CSV_PATH}")
            output_df.to_csv(PREDICTIONS_OUTPUT_CSV_PATH, index=False, encoding='utf-8')
            logging.info("Successfully saved predictions.")

            if not suspicious_flows.empty:
                logging.info(f"Saving suspicious flows only to: {SUSPICIOUS_FLOWS_OUTPUT_CSV_PATH}")
                suspicious_flows.to_csv(SUSPICIOUS_FLOWS_OUTPUT_CSV_PATH, index=False, encoding='utf-8')
                logging.info("Successfully saved suspicious flows.")
            else:
                logging.info("No suspicious flows to save separately.")

        except Exception as e:
            logging.error(f"Error saving prediction results to CSV: {e}", exc_info=True)


    except FileNotFoundError: # Catch specific pd.read_csv error
        logging.error(f"FATAL: Input CSV file '{FLOW_DATA_CSV_PATH}' not found during read.")
    except pd.errors.EmptyDataError:
         logging.error(f"FATAL: Input CSV file '{FLOW_DATA_CSV_PATH}' is empty.")
    except Exception as e:
        logging.error(f"An unexpected error occurred during the prediction phase: {e}", exc_info=True)

    logging.info("--- Prediction Phase Finished ---")


# --- Main Execution Logic ---
def main():
    """Orchestrates the capture and prediction process."""
    logging.info("====== Starting Network Analysis Script ======")

    # --- Phase 1: Capture and Save ---
    print("\n--- Running Capture Phase ---")
    capture_successful = capture_and_save_flows()

    # --- Phase 2: Load, Predict, and Save ---
    if capture_successful:
        print("\n--- Running Prediction Phase ---")
        # Check if the output file from capture actually exists and has data
        if os.path.exists(FLOW_DATA_CSV_PATH) and os.path.getsize(FLOW_DATA_CSV_PATH) > len(','.join(CSV_HEADER)) + 10: # Check if file exists and is reasonably larger than just the header
            load_predict_and_save()
        elif not os.path.exists(FLOW_DATA_CSV_PATH):
             logging.error(f"Prediction skipped: Capture phase indicated success, but output file '{FLOW_DATA_CSV_PATH}' is missing.")
             print(f"ERROR: Prediction skipped - capture output file '{FLOW_DATA_CSV_PATH}' not found.")
        else:
             logging.error(f"Prediction skipped: Capture phase indicated success, but output file '{FLOW_DATA_CSV_PATH}' appears empty or contains only header.")
             print(f"ERROR: Prediction skipped - capture output file '{FLOW_DATA_CSV_PATH}' seems empty.")
    else:
        logging.error("Prediction phase skipped because the capture phase failed or was interrupted.")
        print("ERROR: Prediction phase skipped due to failure in capture phase.")

    logging.info("====== Network Analysis Script Finished ======")
    print("\n====== Script Finished ======")

if __name__ == "__main__":
    # Important: Check for root/admin privileges for Scapy capture
    if os.name == 'posix' and os.geteuid() != 0:
         print("WARNING: Scapy often requires root privileges on Linux/macOS for packet capture.")
         # Optionally exit if root is strictly required:
         # print("Please run this script using 'sudo python your_script_name.py'")
         # exit(1)
    elif os.name == 'nt':
         # Checking for admin privileges on Windows is more complex,
         # usually requires running the terminal as administrator.
         # We can just show a warning.
         print("WARNING: Scapy may require running this script from an Administrator command prompt on Windows.")

    main()