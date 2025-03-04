import os
import pandas as pd
import numpy as np
import joblib
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler
from xgboost import XGBClassifier
from sklearn.metrics import classification_report, roc_auc_score

file_path = "data/DAPT-2020/merged_cleaned.csv"
df = pd.read_csv(file_path, low_memory=False)

df.columns = df.columns.str.lower()

drop_columns = ["flow id", "src ip", "dst ip", "timestamp"]
df.drop(columns=[col for col in drop_columns if col in df.columns], inplace=True)

for col in df.columns:
    if col not in ["activity", "stage"]:
        try:
            df[col] = df[col].astype(float)
        except ValueError:
            print(f"Cột {col} chứa giá trị không thể chuyển thành số, loại bỏ!")
            df.drop(columns=[col], inplace=True)

attack_labels = ['lateral movement', 'reconnaissance', 'establish foothold', 'data exfiltration']
df['apt_attack'] = df['stage'].astype(str).str.lower().apply(lambda x: 1 if x in attack_labels else 0)

for col in ['activity', 'stage']:
    if col in df.columns:
        df[col] = df[col].astype(str)
        df[col] = pd.factorize(df[col])[0]

df.dropna(inplace=True)

X = df.drop(columns=["apt_attack"])
y = df["apt_attack"]

scaler = StandardScaler()
X_scaled = scaler.fit_transform(X)

X_train, X_test, y_train, y_test = train_test_split(X_scaled, y, test_size=0.2, random_state=42)

model = XGBClassifier(n_estimators=100, learning_rate=0.1, max_depth=6, random_state=42)
model.fit(X_train, y_train)

y_pred = model.predict(X_test)
y_prob = model.predict_proba(X_test)[:, 1]

print("\n📌 ***Classification Report:***")
print(classification_report(y_test, y_pred))

roc_auc = roc_auc_score(y_test, y_prob)
print(f"\n📌 ***ROC-AUC: {roc_auc:.4f}***")

if roc_auc > 0.85:
    print("✅ Mô hình đạt yêu cầu với ROC-AUC > 85%!")

# 6️⃣ **Lưu mô hình AI**
joblib.dump(model, "apt_detector.pkl")
joblib.dump(scaler, "scaler.pkl")
print("✅ Mô hình đã được lưu thành 'apt_detector.pkl'!")
