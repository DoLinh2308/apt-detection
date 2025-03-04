import joblib
import pandas as pd
from sklearn.preprocessing import StandardScaler

# Load mô hình
model = joblib.load("apt_detector.pkl")
scaler = joblib.load("scaler.pkl")

pcap_csv_path = "data/DAPT-2020/csv/enp0s3-public-tuesday.pcap_Flow.csv"
df_pcap = pd.read_csv(pcap_csv_path)

df_pcap.columns = df_pcap.columns.str.lower()

# Tiền xử lý giống như dữ liệu huấn luyện
drop_columns = ["flow id", "src ip", "dst ip", "timestamp"]
df_pcap.drop(columns=[col for col in drop_columns if col in df_pcap.columns], inplace=True)

# Chuyển kiểu dữ liệu
for col in df_pcap.columns:
    if col not in ["activity", "stage"]:
        try:
            df_pcap[col] = df_pcap[col].astype(float)
        except ValueError:
            df_pcap.drop(columns=[col], inplace=True)

for col in ['activity', 'stage']:
    if col in df_pcap.columns:
        df_pcap[col] = df_pcap[col].astype(str)
        df_pcap[col] = pd.factorize(df_pcap[col])[0]

df_pcap.dropna(inplace=True)

# 2️⃣ Dự đoán với mô hình AI
X_pcap_scaled = scaler.transform(df_pcap)
y_pred_pcap = model.predict(X_pcap_scaled)

# 3️⃣ In kết quả
df_pcap["APT_Prediction"] = y_pred_pcap
print(df_pcap[["APT_Prediction"]])
df_pcap.to_csv("detection_result.csv", index=False)
print("✅ Kết quả dự đoán đã lưu vào 'detection_result.csv'!")
