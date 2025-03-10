import os
import pandas as pd
import numpy as np
import joblib
import warnings
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler, LabelEncoder
from xgboost import XGBClassifier
from lightgbm import LGBMClassifier
from sklearn.ensemble import RandomForestClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.svm import SVC
from sklearn.metrics import classification_report, roc_auc_score

warnings.filterwarnings("ignore")

# Đọc dữ liệu
file_path = "../dataset/DAPT-2020/merged_cleaned.csv"
if not os.path.exists(file_path):
    raise FileNotFoundError(f"Không tìm thấy file {file_path}")

df = pd.read_csv(file_path, low_memory=False)

df.columns = df.columns.str.lower()

# Xóa các cột không quan trọng
drop_columns = ["flow id", "src ip", "dst ip", "timestamp"]
df.drop(columns=[col for col in drop_columns if col in df.columns], inplace=True)

# Chuyển đổi dữ liệu số
for col in df.columns:
    if col not in ["activity", "stage"]:
        df[col] = pd.to_numeric(df[col], errors="coerce")

# Xử lý nhãn "APT Attack"
attack_labels = [
    "lateral movement",
    "reconnaissance",
    "establish foothold",
    "data exfiltration",
]
df["apt_attack"] = (
    df["stage"].astype(str).str.lower().apply(lambda x: 1 if x in attack_labels else 0)
)

# Mã hóa cột "activity" và "stage"
for col in ["activity", "stage"]:
    if col in df.columns:
        df[col] = df[col].fillna("Unknown")
        df[col] = LabelEncoder().fit_transform(df[col])

df.dropna(inplace=True)

# Chuẩn bị dữ liệu huấn luyện
X = df.drop(columns=["apt_attack"])
y = df["apt_attack"]

scaler = StandardScaler()
X_scaled = scaler.fit_transform(X)

X_train, X_test, y_train, y_test = train_test_split(
    X_scaled, y, test_size=0.2, random_state=42, stratify=y
)

# Huấn luyện và đánh giá với nhiều mô hình
models = {
    "XGBoost": XGBClassifier(
        n_estimators=200, learning_rate=0.05, max_depth=8, random_state=42
    ),
    "Random Forest": RandomForestClassifier(
        n_estimators=200, max_depth=8, random_state=42
    ),
    "LightGBM": LGBMClassifier(
        n_estimators=200, learning_rate=0.05, max_depth=8, random_state=42
    ),
    "Logistic Regression": LogisticRegression(),
    "SVM": SVC(probability=True),
}

results = {}

for name, model in models.items():
    print(f"\nHuấn luyện mô hình {name}...")
    model.fit(X_train, y_train)
    y_pred = model.predict(X_test)
    y_prob = model.predict_proba(X_test)[:, 1]

    acc = np.mean(y_pred == y_test)
    roc_auc = roc_auc_score(y_test, y_prob)

    print(f"\n{name} - Classification Report:")
    print(classification_report(y_test, y_pred))
    print(f"Accuracy: {acc:.4f} | ROC-AUC: {roc_auc:.4f}")

    results[name] = {"accuracy": acc, "roc_auc": roc_auc, "model": model}

# Chọn mô hình tốt nhất
best_model = max(results.items(), key=lambda x: x[1]["roc_auc"])
print(f"\nMô hình tốt nhất: {best_model[0]} với ROC-AUC = {best_model[1]['roc_auc']:.4f}")

# Lưu mô hình tốt nhất
joblib.dump(best_model[1]["model"], "../model/apt_detector.pkl")
joblib.dump(scaler, "../model/scaler.pkl")
print(f"Mô hình {best_model[0]} đã được lưu thành 'best_apt_detector.pkl'")
