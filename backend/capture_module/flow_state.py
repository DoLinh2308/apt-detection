# capture_module/flow_state.py
import time

def initialize_flow_state():
    """Initializes a dictionary to store the state of a network flow."""
    current_time = time.time()
    return {
        'start_time': current_time,
        'last_seen': current_time,
        'src_ip': None, 'dst_ip': None, 'src_port': None, 'dst_port': None, 'protocol': None,
        'fwd_packet_count': 0, 'fwd_total_bytes': 0, 'fwd_timestamps': [], 'fwd_pkt_lengths': [],
        'fwd_header_bytes': 0, 'fwd_psh_flags': 0, 'fwd_urg_flags': 0,
        'bwd_packet_count': 0, 'bwd_total_bytes': 0, 'bwd_timestamps': [], 'bwd_pkt_lengths': [],
        'bwd_header_bytes': 0, 'bwd_psh_flags': 0, 'bwd_urg_flags': 0,
        'fin_flag_count': 0, 'syn_flag_count': 0, 'rst_flag_count': 0,
        'psh_flag_count': 0, 'ack_flag_count': 0, 'urg_flag_count': 0,
        'cwe_flag_count': 0, 'ece_flag_count': 0,
        'all_timestamps_ordered': [],
        # 'active_periods': [], 'idle_periods': [], 'last_active_transition': current_time, # Simplified for now
        'flow_id': None, 'src_init_win_bytes': -1, 'dst_init_win_bytes': -1,
        'fwd_data_pkt_count': 0, 'fwd_min_seg_size': float('inf'),
    }

def get_flow_key(packet, ip_layer):
    """Generates a unique, order-independent key for a flow."""
    proto = ip_layer.proto
    src_ip = ip_layer.src
    dst_ip = ip_layer.dst
    src_port, dst_port = None, None

    if packet.haslayer('TCP'):
        tcp_layer = packet.getlayer('TCP')
        src_port, dst_port = tcp_layer.sport, tcp_layer.dport
    elif packet.haslayer('UDP'):
        udp_layer = packet.getlayer('UDP')
        src_port, dst_port = udp_layer.sport, udp_layer.dport
    else:
        return None # Ignore non-TCP/UDP for flow tracking

    # Ensure consistent key order
    flow_key_part1 = (src_ip, src_port)
    flow_key_part2 = (dst_ip, dst_port)
    if flow_key_part1 > flow_key_part2:
         flow_key_part1, flow_key_part2 = flow_key_part2, flow_key_part1
    flow_key = flow_key_part1 + flow_key_part2 + (proto,)
    return flow_key

def generate_flow_id(src_ip, src_port, dst_ip, dst_port, proto):
    """Creates a human-readable flow ID."""
    return f"{src_ip}:{src_port}-{dst_ip}:{dst_port}-{proto}"

