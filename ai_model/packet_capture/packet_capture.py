from scapy.all import sniff, IP, TCP, UDP
import pandas as pd
def packet_callback(packet):
    if packet.haslayer(IP):  # Kiểm tra nếu có lớp IP
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        proto = packet[IP].proto

        print(f"IP: {src_ip} -> {dst_ip} | Protocol: {proto}")

# Bắt gói tin từ giao diện mạng (ví dụ: eth0)
sniff(prn=packet_callback, iface="Wi-Fi", store=False)

def extract_features(packet):
    if packet.haslayer(IP):
        return {
            "src_ip": packet[IP].src,
            "dst_ip": packet[IP].dst,
            "protocol": packet[IP].proto,
            "packet_length": len(packet),
            "tcp_flags": packet[TCP].flags if packet.haslayer(TCP) else 0,
        }
    return None

def process_packets(packets):
    data = [extract_features(p) for p in packets if extract_features(p)]
    return pd.DataFrame(data)

# Lưu thành DataFrame
packets = sniff(count=100, iface="Wi-Fi")
df = process_packets(packets)
print(df.head())
df.to_csv("captured_packets.csv", index=False)
