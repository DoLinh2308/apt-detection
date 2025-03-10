import pandas as pd
import numpy as np
import joblib
from scapy.all import rdpcap, IP, TCP, UDP

scaler = joblib.load("../model/scaler.pkl")
feature_names = scaler.feature_names_in_

print("Các đặc trưng cần có:")
print(feature_names)

# Đọc gói tin từ PCAP
packets = rdpcap("packet.pcap")
data = []

for pkt in packets:
    if IP in pkt:
        src_port = pkt[TCP].sport if TCP in pkt else (pkt[UDP].sport if UDP in pkt else 0)
        dst_port = pkt[TCP].dport if TCP in pkt else (pkt[UDP].dport if UDP in pkt else 0)
        protocol = pkt[IP].proto
        length = len(pkt)

        data.append([src_port, dst_port, protocol, length])

df_pcap = pd.DataFrame(
    data, columns=["src_port", "dst_port", "protocol", "packet_length"]
)

# Tải danh sách đặc trưng gốc từ scaler
scaler = joblib.load("../model/scaler.pkl")
feature_names = scaler.feature_names_in_

# Đảm bảo các cột đúng với mô hình AI
for col in feature_names:
    if col not in df_pcap.columns:
        df_pcap[col] = 0

df_pcap = df_pcap[feature_names]

# Chuẩn hóa dữ liệu
X_pcap_scaled = scaler.transform(df_pcap)

# Dự đoán bằng mô hình AI
model = joblib.load("../model/best_apt_detector.pkl")
y_pred = model.predict(X_pcap_scaled)

# Hiển thị kết quả
df_pcap["APT Attack"] = y_pred
print(df_pcap)
