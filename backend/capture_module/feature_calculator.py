# capture_module/feature_calculator.py
import time
import statistics
from .config import CSV_HEADER, PLACEHOLDER_FEATURES, DEFAULT_PLACEHOLDER_VALUE

def _safe_stat(func, data, default=0):
    """Safely compute statistics, handling empty or single-element lists."""
    if not data:
        return default
    if len(data) < 2 and func in (statistics.stdev, statistics.variance):
        return default # Standard deviation/variance require at least 2 points
    try:
        return func(data)
    except statistics.StatisticsError:
        return default # Should not happen with checks above, but just in case
    except ZeroDivisionError:
         return default # e.g. for mean of empty list if check failed

def calculate_final_features(flow_state, flow_key_tuple):
    """
    Calculates derived network flow features from the flow state.

    Args:
        flow_state: Dictionary containing the aggregated state of the flow.
        flow_key_tuple: The tuple key used to identify the flow.

    Returns:
        A dictionary where keys match the CSV_HEADER.
    """
    features = {}
    flow_duration_sec = flow_state['last_seen'] - flow_state['start_time']
    # Avoid division by zero; use a small epsilon if duration is zero
    flow_duration_sec_safe = flow_duration_sec if flow_duration_sec > 0 else 1e-9

    # --- Basic Flow Identifiers ---
    features['Flow ID'] = flow_state.get('flow_id', '-'.join(map(str, flow_key_tuple)))
    features['Src IP'] = flow_state['src_ip']
    features['Src Port'] = flow_state['src_port']
    features['Dst IP'] = flow_state['dst_ip']
    features['Dst Port'] = flow_state['dst_port']
    features['Protocol'] = flow_state['protocol']
    features['Timestamp'] = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(flow_state['last_seen']))

    # --- Duration and Packet Counts ---
    features['Flow Duration'] = flow_duration_sec * 1_000_000 # Microseconds often expected
    features['Tot Fwd Pkts'] = flow_state['fwd_packet_count']
    features['Tot Bwd Pkts'] = flow_state['bwd_packet_count']
    features['TotLen Fwd Pkts'] = flow_state['fwd_total_bytes']
    features['TotLen Bwd Pkts'] = flow_state['bwd_total_bytes']

    # --- Packet Length Statistics ---
    fwd_pkts = flow_state['fwd_pkt_lengths']
    bwd_pkts = flow_state['bwd_pkt_lengths']
    all_pkts = fwd_pkts + bwd_pkts
    features['Fwd Pkt Len Max'] = max(fwd_pkts) if fwd_pkts else 0
    features['Fwd Pkt Len Min'] = min(fwd_pkts) if fwd_pkts else 0
    features['Fwd Pkt Len Mean'] = _safe_stat(statistics.mean, fwd_pkts)
    features['Fwd Pkt Len Std'] = _safe_stat(statistics.stdev, fwd_pkts)
    features['Bwd Pkt Len Max'] = max(bwd_pkts) if bwd_pkts else 0
    features['Bwd Pkt Len Min'] = min(bwd_pkts) if bwd_pkts else 0
    features['Bwd Pkt Len Mean'] = _safe_stat(statistics.mean, bwd_pkts)
    features['Bwd Pkt Len Std'] = _safe_stat(statistics.stdev, bwd_pkts)
    features['Pkt Len Min'] = min(all_pkts) if all_pkts else 0
    features['Pkt Len Max'] = max(all_pkts) if all_pkts else 0
    features['Pkt Len Mean'] = _safe_stat(statistics.mean, all_pkts)
    features['Pkt Len Std'] = _safe_stat(statistics.stdev, all_pkts)
    features['Pkt Len Var'] = _safe_stat(statistics.variance, all_pkts)
    features['Pkt Size Avg'] = features['Pkt Len Mean'] # Often synonymous
    features['Fwd Seg Size Avg'] = features['Fwd Pkt Len Mean'] # Approximation
    features['Bwd Seg Size Avg'] = features['Bwd Pkt Len Mean'] # Approximation

    # --- Rate Features ---
    total_packets = features['Tot Fwd Pkts'] + features['Tot Bwd Pkts']
    total_bytes = features['TotLen Fwd Pkts'] + features['TotLen Bwd Pkts']
    features['Flow Byts/s'] = total_bytes / flow_duration_sec_safe
    features['Flow Pkts/s'] = total_packets / flow_duration_sec_safe
    features['Fwd Pkts/s'] = features['Tot Fwd Pkts'] / flow_duration_sec_safe
    features['Bwd Pkts/s'] = features['Tot Bwd Pkts'] / flow_duration_sec_safe

    # --- Inter-Arrival Time (IAT) Statistics (in Microseconds) ---
    # Multiply by 1e6 for microseconds
    all_iats = [(t - s) * 1_000_000 for s, t in zip(flow_state['all_timestamps_ordered'], flow_state['all_timestamps_ordered'][1:])]
    fwd_iats = [(t - s) * 1_000_000 for s, t in zip(flow_state['fwd_timestamps'], flow_state['fwd_timestamps'][1:])]
    bwd_iats = [(t - s) * 1_000_000 for s, t in zip(flow_state['bwd_timestamps'], flow_state['bwd_timestamps'][1:])]

    features['Flow IAT Mean'] = _safe_stat(statistics.mean, all_iats)
    features['Flow IAT Std'] = _safe_stat(statistics.stdev, all_iats)
    features['Flow IAT Max'] = max(all_iats) if all_iats else 0
    features['Flow IAT Min'] = min(all_iats) if all_iats else 0

    features['Fwd IAT Tot'] = sum(fwd_iats)
    features['Fwd IAT Mean'] = _safe_stat(statistics.mean, fwd_iats)
    features['Fwd IAT Std'] = _safe_stat(statistics.stdev, fwd_iats)
    features['Fwd IAT Max'] = max(fwd_iats) if fwd_iats else 0
    features['Fwd IAT Min'] = min(fwd_iats) if fwd_iats else 0

    features['Bwd IAT Tot'] = sum(bwd_iats)
    features['Bwd IAT Mean'] = _safe_stat(statistics.mean, bwd_iats)
    features['Bwd IAT Std'] = _safe_stat(statistics.stdev, bwd_iats)
    features['Bwd IAT Max'] = max(bwd_iats) if bwd_iats else 0
    features['Bwd IAT Min'] = min(bwd_iats) if bwd_iats else 0

    # --- Header and Flag Features ---
    features['Fwd Header Len'] = flow_state['fwd_header_bytes']
    features['Bwd Header Len'] = flow_state['bwd_header_bytes']
    features['Fwd PSH Flags'] = flow_state['fwd_psh_flags']
    features['Fwd URG Flags'] = flow_state['fwd_urg_flags']
    features['Bwd PSH Flags'] = flow_state['bwd_psh_flags']
    features['Bwd URG Flags'] = flow_state['bwd_urg_flags']
    features['FIN Flag Cnt'] = flow_state['fin_flag_count']
    features['SYN Flag Cnt'] = flow_state['syn_flag_count']
    features['RST Flag Cnt'] = flow_state['rst_flag_count']
    features['PSH Flag Cnt'] = flow_state['psh_flag_count'] # Overall PSH
    features['ACK Flag Cnt'] = flow_state['ack_flag_count']
    features['URG Flag Cnt'] = flow_state['urg_flag_count'] # Overall URG
    features['CWE Flag Count'] = flow_state['cwe_flag_count']
    features['ECE Flag Cnt'] = flow_state['ece_flag_count']

    # --- Other Features ---
    features['Down/Up Ratio'] = features['Tot Bwd Pkts'] / features['Tot Fwd Pkts'] if features['Tot Fwd Pkts'] > 0 else 0
    features['Init Fwd Win Byts'] = flow_state['src_init_win_bytes']
    features['Init Bwd Win Byts'] = flow_state['dst_init_win_bytes']
    features['Fwd Act Data Pkts'] = flow_state['fwd_data_pkt_count'] # Packets with payload > 0
    features['Fwd Seg Size Min'] = flow_state['fwd_min_seg_size'] if flow_state['fwd_min_seg_size'] != float('inf') else 0

    # --- Protocol One-Hot Encoding ---
    proto = flow_state['protocol']
    features['Protocol_0'] = 1 if proto == 0 else 0 # HOPOPT
    features['Protocol_6'] = 1 if proto == 6 else 0 # TCP
    features['Protocol_17'] = 1 if proto == 17 else 0 # UDP
    # Add others if your model uses them, ensure they are in CSV_HEADER

    # --- Placeholders for unimplemented features ---
    for ph_feature in PLACEHOLDER_FEATURES:
        if ph_feature not in features: # Avoid overwriting if calculated above
             features[ph_feature] = DEFAULT_PLACEHOLDER_VALUE

    # --- Final Check: Ensure all header columns are present ---
    final_feature_dict = {header: features.get(header, DEFAULT_PLACEHOLDER_VALUE) for header in CSV_HEADER}

    return final_feature_dict

