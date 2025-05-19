# capture_module/packet_processor.py
import time
from scapy.all import IP, TCP, UDP
from .flow_state import initialize_flow_state, get_flow_key, generate_flow_id

def process_packet(packet, active_flows):
    """
    Processes a single packet and updates the corresponding flow state in active_flows.

    Args:
        packet: The Scapy packet object.
        active_flows: Dictionary holding the state of active flows.
    """
    current_time = time.time()

    if not packet.haslayer(IP): return
    ip_layer = packet.getlayer(IP)

    flow_key = get_flow_key(packet, ip_layer)
    if flow_key is None: return # Ignore if not TCP/UDP or key couldn't be generated

    src_ip = ip_layer.src
    dst_ip = ip_layer.dst
    proto = ip_layer.proto
    src_port, dst_port, tcp_flags = None, None, None
    packet_len = len(packet) # Total packet length
    ip_header_len = ip_layer.ihl * 4
    header_len = ip_header_len
    init_win = -1

    if packet.haslayer(TCP):
        tcp_layer = packet.getlayer(TCP)
        src_port, dst_port = tcp_layer.sport, tcp_layer.dport
        tcp_flags = tcp_layer.flags
        header_len += tcp_layer.dataofs * 4
        init_win = tcp_layer.window
    elif packet.haslayer(UDP):
        udp_layer = packet.getlayer(UDP)
        src_port, dst_port = udp_layer.sport, udp_layer.dport
        header_len += 8 # UDP header is fixed 8 bytes
    # No else needed because get_flow_key already filtered

    actual_payload_len = packet_len - header_len
    if actual_payload_len < 0: actual_payload_len = 0 # Ensure non-negative

    # --- Flow Initialization or Update ---
    if flow_key not in active_flows:
        active_flows[flow_key] = initialize_flow_state()
        flow = active_flows[flow_key]
        # Store the actual first packet's direction info
        flow['src_ip'] = src_ip
        flow['dst_ip'] = dst_ip
        flow['src_port'] = src_port
        flow['dst_port'] = dst_port
        flow['protocol'] = proto
        flow['flow_id'] = generate_flow_id(src_ip, src_port, dst_ip, dst_port, proto)
        # Capture initial window size based on first packet's direction
        if proto == 6: # TCP
             flow['src_init_win_bytes'] = init_win # Assume first packet is forward
    else:
        flow = active_flows[flow_key]

    flow['last_seen'] = current_time
    flow['all_timestamps_ordered'].append(current_time)

    # Determine direction relative to the *first* packet seen for this flow
    is_forward = (src_ip == flow['src_ip'] and src_port == flow['src_port'])

    # --- Update Flow Statistics ---
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
        # Update Fwd Min Segment Size (using header length as approximation)
        if proto == 6: flow['fwd_min_seg_size'] = min(flow['fwd_min_seg_size'], header_len)
    else: # Backward direction
        # Capture initial window size for backward direction if not already set
        if flow['bwd_packet_count'] == 0 and proto == 6 and flow['dst_init_win_bytes'] == -1:
             flow['dst_init_win_bytes'] = init_win
        flow['bwd_packet_count'] += 1
        flow['bwd_total_bytes'] += packet_len
        flow['bwd_timestamps'].append(current_time)
        flow['bwd_pkt_lengths'].append(packet_len)
        flow['bwd_header_bytes'] += header_len
        if tcp_flags is not None:
             if 'P' in tcp_flags: flow['bwd_psh_flags'] += 1
             if 'U' in tcp_flags: flow['bwd_urg_flags'] += 1

    # Update overall TCP flags count
    if tcp_flags is not None:
        if 'F' in tcp_flags: flow['fin_flag_count'] += 1
        if 'S' in tcp_flags: flow['syn_flag_count'] += 1
        if 'R' in tcp_flags: flow['rst_flag_count'] += 1
        if 'P' in tcp_flags: flow['psh_flag_count'] += 1
        if 'A' in tcp_flags: flow['ack_flag_count'] += 1
        if 'U' in tcp_flags: flow['urg_flag_count'] += 1
        if 'C' in tcp_flags: flow['cwe_flag_count'] += 1
        if 'E' in tcp_flags: flow['ece_flag_count'] += 1

