import pandas as pd
import numpy as np
import joblib 
import os

from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler, OneHotEncoder # Example scalers/encoders
from sklearn.compose import ColumnTransformer
from sklearn.pipeline import Pipeline
from sklearn.metrics import classification_report, confusion_matrix, f1_score, precision_score, recall_score, accuracy_score, roc_auc_score, roc_curve, auc

from imblearn.over_sampling import SMOTE
from imblearn.under_sampling import RandomUnderSampler
from collections import Counter

# --- Cấu hình ---
PATH_TO_MODELS = 'D:/Do_an_tot_nghiep/apt-detection/ai_model/dataset/working2/'
RF_MODEL_FILE = 'random_forest_model.pkl'
XGB_MODEL_FILE = 'xgboost_model.pkl'
DAPT2020_DATA_FILE = 'D:/Do_an_tot_nghiep/apt-detection/ai_model/dataset/DAPT-2020/merged_cleaned.csv' 


# TODO: CẤU HÌNH CỘT NHÃN TRONG DAPT2020
# Cần biết tên cột chứa nhãn tấn công trong DAPT2020.
LABEL_COLUMN = 'label' # Example: The column in DAPT2020 that contains attack types/APT label

# TODO: ĐỊNH NGHĨA NHÃN APT VÀ BENIGN
# Bạn cần ánh xạ các giá trị trong LABEL_COLUMN của DAPT2020 sang 0 (Benign) và 1 (APT)
# VÍ DỤ (THAY THẾ BẰNG CÁC NHÃN THẬT CỦA BẠN):
print("\n🔍 Checking for Extra Spaces in Attack Labels...")

APT_LABELS_IN_DAPT2020 = ['Lateral Movement', 'Reconnaissance', 'Establish Foothold', 'Data Exfiltration']
BENIGN_LABELS_IN_DAPT2020 = ['Benign', 'BENIGN']

FEATURE_COLUMNS = [
    'Dst Port',
    'Flow Duration',
    'Tot Fwd Pkts',
    'Tot Bwd Pkts',
    'TotLen Fwd Pkts',
    'TotLen Bwd Pkts',
    'Fwd Pkt Len Max',
    'Fwd Pkt Len Min',
    'Fwd Pkt Len Mean',
    'Fwd Pkt Len Std',
    'Bwd Pkt Len Max',
    'Bwd Pkt Len Min',
    'Bwd Pkt Len Mean',
    'Bwd Pkt Len Std',
    'Flow Byts/s',
    'Flow Pkts/s',
    'Flow IAT Mean',
    'Flow IAT Std',
    'Flow IAT Max',
    'Flow IAT Min',
    'Fwd IAT Tot',
    'Fwd IAT Mean',
    'Fwd IAT Std',
    'Fwd IAT Max',
    'Fwd IAT Min',
    'Bwd IAT Tot',
    'Bwd IAT Mean',
    'Bwd IAT Std',
    'Bwd IAT Max',
    'Bwd IAT Min',
    'Fwd PSH Flags',
    'Fwd URG Flags',
    'Fwd Header Len',
    'Bwd Header Len',
    'Fwd Pkts/s',
    'Bwd Pkts/s',
    'Pkt Len Min',
    'Pkt Len Max',
    'Pkt Len Mean',
    'Pkt Len Std',
    'Pkt Len Var',
    'FIN Flag Cnt',
    'SYN Flag Cnt',
    'RST Flag Cnt',
    'PSH Flag Cnt',
    'ACK Flag Cnt',
    'URG Flag Cnt',
    'CWE Flag Count',
    'ECE Flag Cnt',
    'Down/Up Ratio',
    'Pkt Size Avg',
    'Fwd Seg Size Avg',
    'Bwd Seg Size Avg',
    'Subflow Fwd Pkts',
    'Subflow Fwd Byts',
    'Subflow Bwd Pkts',
    'Subflow Bwd Byts',
    'Init Fwd Win Byts',
    'Init Bwd Win Byts',
    'Fwd Act Data Pkts',
    'Fwd Seg Size Min',
    'Active Mean',
    'Active Std',
    'Active Max',
    'Active Min',
    'Idle Mean',
    'Idle Std',
    'Idle Max',
    'Idle Min',
]

# TODO: XÁC ĐỊNH CÁC CỘT CẦN TIỀN XỬ LÝ TRONG DAPT2020 DỰA TRÊN CÁCH BẠN ĐÃ LÀM VỚI CIC-IDS2018
# Đặc biệt lưu ý cột Protocol. Nếu DAPT2020 có cột Protocol gốc, bạn cần mã hóa nó.
# Nếu DAPT2020 đã có sẵn các cột Protocol_0, Protocol_6, Protocol_17, thì coi chúng là số.

# VÍ DỤ (Cần điều chỉnh dựa trên tiền xử lý thực tế của bạn):
# Giả định hầu hết các cột là số và đã được scale, còn Protocol_X là kết quả OHE và không scale thêm.
NUMERICAL_FEATURES_TO_SCALE = [
    'Flow Duration', 'Tot Fwd Pkts', 'Tot Bwd Pkts', 'TotLen Fwd Pkts',
    'TotLen Bwd Pkts', 'Fwd Pkt Len Max', 'Fwd Pkt Len Min',
    'Fwd Pkt Len Mean', 'Fwd Pkt Len Std', 'Bwd Pkt Len Max',
    'Bwd Pkt Len Min', 'Bwd Pkt Len Mean', 'Bwd Pkt Len Std',
    'Flow Byts/s', 'Flow Pkts/s', 'Flow IAT Mean', 'Flow IAT Std',
    'Flow IAT Max', 'Flow IAT Min', 'Fwd IAT Tot', 'Fwd IAT Mean',
    'Fwd IAT Std', 'Fwd IAT Max', 'Fwd IAT Min', 'Bwd IAT Tot',
    'Bwd IAT Mean', 'Bwd IAT Std', 'Bwd IAT Max', 'Bwd IAT Min',
    'Fwd Header Len', 'Bwd Header Len', 'Fwd Pkts/s', 'Bwd Pkts/s',
    'Pkt Len Min', 'Pkt Len Max', 'Pkt Len Mean', 'Pkt Len Std',
    'Pkt Len Var', 'Down/Up Ratio', 'Pkt Size Avg', 'Fwd Seg Size Avg',
    'Bwd Seg Size Avg', 'Subflow Fwd Pkts', 'Subflow Fwd Byts',
    'Subflow Bwd Pkts', 'Subflow Bwd Byts', 'Init Fwd Win Byts',
    'Init Bwd Win Byts', 'Fwd Act Data Pkts', 'Fwd Seg Size Min',
    'Active Mean', 'Active Std', 'Active Max', 'Active Min',
    'Idle Mean', 'Idle Std', 'Idle Max', 'Idle Min'
]

# Các cột cờ và Protocol_X thường là 0/1 hoặc đếm, có thể không cần scale
# Nếu bạn đã scale chúng, thêm vào danh sách trên. Nếu không, bỏ qua.
FEATURES_NOT_SCALED_BUT_NUMERICAL = [
    'Dst Port', # Cổng đích - có thể coi là số hoặc phân loại tùy cách dùng
    'Fwd PSH Flags', 'Fwd URG Flags', 'FIN Flag Cnt', 'SYN Flag Cnt',
    'RST Flag Cnt', 'PSH Flag Cnt', 'ACK Flag Cnt', 'URG Flag Cnt',
    'CWE Flag Count', 'ECE Flag Cnt',
    'Protocol_0', 'Protocol_6', 'Protocol_17' # Kết quả của OHE Protocol
]

# Các cột phân loại gốc (nếu DAPT2020 còn cột Protocol gốc, cần mã hóa)
# Nếu DAPT2020 đã có Protocol_X, thì không cần cột phân loại gốc nữa.
# CATEGORICAL_FEATURES_TO_ENCODE = ['Protocol'] # Example if DAPT2020 has original Protocol column

# --- Load Mô hình đã huấn luyện trên CIC-IDS2018 ---
print("Loading existing models...")
try:
    rf_model_cicids = joblib.load(os.path.join(PATH_TO_MODELS, RF_MODEL_FILE))
    xgb_model_cicids = joblib.load(os.path.join(PATH_TO_MODELS, XGB_MODEL_FILE))
    print("Models loaded successfully.")
    # Optional: print some info about loaded models
    # print("RF Model Params:", rf_model_cicids.get_params())
    # print("XGB Model Params:", xgb_model_cicids.get_params())
except FileNotFoundError as e:
    print(f"Error loading model files: {e}")
    print("Please check the file paths and names.")
    exit() # Exit if models can't be loaded

# --- Load Dữ liệu DAPT2020 ---
print(f"Loading DAPT2020 data from {DAPT2020_DATA_FILE}...")
try:
    # TODO: Kiểm tra encoding của file CSV DAPT2020 nếu gặp lỗi đọc file
    df_dapt2020 = pd.read_csv(DAPT2020_DATA_FILE)
    print(f"DAPT2020 data loaded. Shape: {df_dapt2020.shape}")
    # Optional: Display first few rows and info
    # print(df_dapt2020.head())
    # print(df_dapt2020.info())
except FileNotFoundError as e:
    print(f"Error loading DAPT2020 data file: {e}")
    print("Please check the file path.")
    exit()
except Exception as e:
     print(f"Error reading DAPT2020 data file: {e}")
     exit()


# --- Tiền xử lý DAPT2020 và Chuẩn bị Nhãn APT ---

# 1. Xử lý các giá trị không xác định/thiếu trong DAPT2020
# TODO: ÁP DỤNG CÁCH XỬ LÝ GIÁ TRỊ THIẾU NHẤT QUÁN VỚI CIC-IDS2018
# VÍ DỤ: điền bằng 0, giá trị trung bình, giá trị mode, hoặc loại bỏ hàng
print("Preprocessing DAPT2020 data...")
# Example: fill NaNs with 0 (adjust if needed)
df_dapt2020.fillna(0, inplace=True)

# TODO: Áp dụng xử lý các giá trị vô hạn (inf) nếu có
df_dapt2020.replace([np.inf, -np.inf], np.nan, inplace=True)
df_dapt2020.fillna(0, inplace=True) # Fill NaNs created by replacing inf

# 2. Ánh xạ nhãn gốc sang nhãn Benign (0) và APT (1)
# TODO: ÁP DỤNG LOGIC GÁN NHÃN APT/BENIGN CỦA BẠN
df_dapt2020['APT_Label'] = 0 # Default to Benign (0)
df_dapt2020.loc[df_dapt2020[LABEL_COLUMN].isin(APT_LABELS_IN_DAPT2020), 'APT_Label'] = 1 # Mark APT (1)

# Optional: Remove rows that are neither Benign nor APT if necessary
# print(f"Original number of rows: {df_dapt2020.shape[0]}")
# df_dapt2020 = df_dapt2020[df_dapt2020[LABEL_COLUMN].isin(APT_LABELS_IN_DAPT2020 + BENIGN_LABELS_IN_DAPT2020)].copy()
# print(f"Rows after filtering labels: {df_dapt2020.shape[0]}")


# Tách đặc trưng (X) và nhãn (y) TRƯỚC KHI áp dụng các transformer
try:
    # Đảm bảo chỉ chọn các cột đặc trưng đã định nghĩa
    X_dapt = df_dapt2020[FEATURE_COLUMNS].copy()
    y_dapt = df_dapt2020['APT_Label'].copy()
except KeyError as e:
    print(f"Error: Missing a defined feature or label column in DAPT2020 data: {e}")
    print("Please check if all columns in FEATURE_COLUMNS and LABEL_COLUMN exist in your DAPT2020 data.")
    exit()

print(f"Features shape before transformation: {X_dapt.shape}")
print(f"Labels shape: {y_dapt.shape}")
print(f"Label distribution in DAPT2020: {Counter(y_dapt)}")

# 3. Áp dụng tiền xử lý cho các đặc trưng (Scaling, Encoding, etc.)
# TODO: TẠO VÀ FIT TRANSFORMER HOẶC ÁP DỤNG SCALER ĐÃ FIT TỪ CIC-IDS2018
# Cách lý tưởng là sử dụng lại scaler/encoder đã fit trên CIC-IDS2018 để đảm bảo tính nhất quán.
# Nếu không có scaler/encoder đã lưu, bạn có thể fit mới trên DAPT2020 hoặc tập dữ liệu kết hợp.
print("Applying feature transformations...")

# --- Example: Create a preprocessor pipeline (adapt based on your actual preprocessing) ---
# Bạn cần điều chỉnh này cho phù hợp với cách bạn đã tiền xử lý dữ liệu CIC-IDS2018.
# Nếu bạn đã lưu đối tượng preprocessor từ lần huấn luyện trước, hãy load nó và chỉ gọi transform.
# Ví dụ: preprocessor = joblib.load('cicids_preprocessor.pkl')
# X_dapt_processed = preprocessor.transform(X_dapt)
# -----------------------------------------------------------------------------------------

# Nếu bạn cần fit lại preprocessor trên dữ liệu mới (ít lý tưởng hơn nhưng đôi khi cần):
# VÍ DỤ NÀY GIẢ ĐỊNH BẠN SCALE CÁC CỘT TRONG NUMERICAL_FEATURES_TO_SCALE
# VÀ ĐỂ NGUYÊN CÁC CỘT KHÁC BAO GỒM CÁC CỘT CỜ VÀ PROTOCOL_X
preprocessor = ColumnTransformer(
    transformers=[
        ('num', StandardScaler(), NUMERICAL_FEATURES_TO_SCALE)
        # TODO: Add other transformers if you had categorical features in CIC-IDS2018 besides Protocol
        # ('cat', OneHotEncoder(handle_unknown='ignore'), CATEGORICAL_FEATURES_TO_ENCODE)
    ],
    # Keep other columns (like flag counts, Dst Port, Protocol_X) as they are
    remainder='passthrough'
)

# Fit and transform the DAPT2020 data
X_dapt_processed = preprocessor.fit_transform(X_dapt)
print(f"Processed data shape: {X_dapt_processed.shape}")
print("DAPT2020 preprocessing complete.")

# --- Tùy chọn: Kết hợp dữ liệu (Nếu chọn phương án này) ---
# TODO: NẾU BẠN MUỐN KẾT HỢP DỮ LIỆU CIC-IDS2018 VÀ DAPT2020
# Bạn cần load và tiền xử lý một phần dữ liệu CIC-IDS2018 (benign và/hoặc các loại tấn công liên quan)
# sử dụng CÙNG đối tượng preprocessor ĐÃ FIT (hoặc fit mới trên toàn bộ dữ liệu kết hợp ban đầu).
# Sau đó nối X và y từ hai nguồn lại.
# Ví dụ (Conceptual - needs actual CIC-IDS2018 loading and preprocessing):
# X_cicids_subset, y_cicids_subset = load_and_preprocess_cicids_subset(...) # Ensure this also uses the *same* preprocessor
# X_combined = np.vstack((X_dapt_processed, X_cicids_subset))
# y_combined = np.concatenate((y_dapt, y_cicids_subset))
# print(f"Combined data shape: {X_combined.shape}")
# X_train_final, X_test_final, y_train_final, y_test_final = train_test_split(X_combined, y_combined, test_size=0.2, random_state=42, stratify=y_combined) # Use stratify for imbalance
# print(f"Combined Train/Test shapes: {X_train_final.shape} / {X_test_final.shape}")


# --- Chia tập dữ liệu (Nếu chỉ dùng DAPT2020) ---
# Nếu chỉ sử dụng DAPT2020 để huấn luyện lại
print("Splitting DAPT2020 data into train and test sets...")
X_train_final, X_test_final, y_train_final, y_test_final = train_test_split(
    X_dapt_processed, y_dapt,
    test_size=0.2,      # 20% for testing (adjust as needed)
    random_state=42,    # for reproducibility
    stratify=y_dapt     # Stratify to maintain class distribution (crucial for imbalance)
)
print(f"Train/Test shapes: {X_train_final.shape} / {X_test_final.shape}")
print(f"Train Label Distribution: {Counter(y_train_final)}")
print(f"Test Label Distribution: {Counter(y_test_final)}")


# --- Xử lý mất cân bằng lớp (trên tập huấn luyện) ---
# Tấn công APT (nhãn 1) có thể rất ít trong tập huấn luyện.
# Có nhiều cách xử lý:
# 1. Dùng class_weight trong mô hình (đối với RF)
# 2. Dùng scale_pos_weight trong mô hình (đối với XGBoost binary classification)
# 3. Áp dụng kỹ thuật lấy mẫu (sampling) như SMOTE, Undersampling (sử dụng thư viện imblearn)
print("Handling class imbalance...")

# Phương án 1/2: Sử dụng trọng số lớp tích hợp trong mô hình
# Tính toán trọng số lớp cho RF (sử dụng 'balanced' hoặc dict tùy chọn)
# from sklearn.utils.class_weight import compute_class_weight
# classes = np.unique(y_train_final)
# weights = compute_class_weight('balanced', classes=classes, y=y_train_final)
# class_weights_dict = dict(zip(classes, weights))
# print("Computed class weights for RF:", class_weights_dict) # Pass this dict to RF's fit method or use 'balanced'

# Tính toán scale_pos_weight cho XGBoost (phân loại nhị phân 0/1)
apt_count_train = sum(y_train_final == 1)
benign_count_train = sum(y_train_final == 0)
# Tránh chia cho 0 nếu không có mẫu APT trong tập huấn luyện (dù stratify cố gắng đảm bảo)
scale_pos_weight_value = benign_count_train / apt_count_train if apt_count_train > 0 else 1
print(f"Computed scale_pos_weight for XGBoost: {scale_pos_weight_value}") # Pass this value to XGBoost's fit method or set as parameter


# Phương án 3 (Sử dụng imblearn - cần cài đặt `pip install imbalanced-learn`)
# print("Applying SMOTE on training data...")
# smote = SMOTE(random_state=42)
# X_train_resampled, y_train_resampled = smote.fit_resample(X_train_final, y_train_final)
# print(f"Resampled train shape: {X_train_resampled.shape}")
# print(f"Resampled train label distribution: {Counter(y_train_resampled)}")
# # Use X_train_resampled, y_train_resampled for fitting instead of X_train_final, y_train_final


# --- Huấn luyện lại Mô hình (Retraining) ---
print("Retraining models on the new data...")

# Retrain Random Forest
# Sử dụng lại cấu trúc/siêu tham số từ mô hình CIC-IDS2018 hoặc điều chỉnh nếu cần
# Bạn có thể tạo lại đối tượng RF hoặc sử dụng lại rf_model_cicids và gọi .fit()
# Để sử dụng lại rf_model_cicids và các siêu tham số cũ:
rf_model_retrained = rf_model_cicids
# Hoặc tạo mới với các siêu tham số mong muốn, CẦN XỬ LÝ class_weight ở đây hoặc khi tạo đối tượng
# from sklearn.ensemble import RandomForestClassifier
# rf_model_retrained = RandomForestClassifier(n_estimators=..., max_depth=..., random_state=42, class_weight='balanced' # or pass class_weights_dict)

# Fit using the training data (original or resampled)
# If using class_weight='balanced' in constructor, no need for sample_weight here
rf_model_retrained.fit(X_train_final, y_train_final)
# If using class_weight dict:
# rf_model_retrained.fit(X_train_final, y_train_final, sample_weight=np.array([class_weights_dict[label] for label in y_train_final]))

print("Random Forest retraining complete.")

# Retrain XGBoost
# Sử dụng lại cấu trúc/siêu tham số từ mô hình CIC-IDS2018 hoặc điều chỉnh nếu cần
# Bạn có thể tạo lại đối tượng XGBoost hoặc sử dụng lại xgb_model_cicids và gọi .fit()
# Để sử dụng lại xgb_model_cicids và các siêu tham số cũ:
xgb_model_retrained = xgb_model_cicids
# Hoặc tạo mới với các siêu tham số mong muốn. CẦN XỬ LÝ scale_pos_weight ở đây hoặc khi tạo đối tượng
# import xgboost as xgb
# xgb_model_retrained = xgb.XGBClassifier(objective='binary:logistic', eval_metric='logloss', use_label_encoder=False, scale_pos_weight=scale_pos_weight_value, # other params)


# Fit using the training data (original or resampled)
# Pass scale_pos_weight for binary classification with imbalance, unless set in constructor
xgb_model_retrained.fit(X_train_final, y_train_final, scale_pos_weight=scale_pos_weight_value)

print("XGBoost retraining complete.")


# --- Đánh giá Mô hình mới ---
print("\nEvaluating retrained models on the test set...")

models_to_evaluate = {
    "Random Forest (Retrained)": rf_model_retrained,
    "XGBoost (Retrained)": xgb_model_retrained
}

for name, model in models_to_evaluate.items():
    print(f"\n--- Evaluation for {name} ---")

    # Dự đoán trên tập kiểm tra
    y_pred = model.predict(X_test_final)
    # Dự đoán xác suất (để tính AUC)
    # Đảm bảo mô hình có predict_proba (hầu hết các classifier của sklearn và XGBoost đều có)
    if hasattr(model, "predict_proba"):
       y_pred_proba = model.predict_proba(X_test_final)[:, 1] # Probability of the positive class (APT=1)
    else:
       y_pred_proba = [0] * len(y_test_final) # Placeholder if no predict_proba


    # In báo cáo phân loại chi tiết (Precision, Recall, F1-score)
    print("Classification Report:")
    # targets = ['Benign', 'APT']
    # print(classification_report(y_test_final, y_pred, target_names=targets, zero_division=0))
    # Sử dụng labels và target_names để kiểm soát thứ tự
    labels = [0, 1]
    target_names = ['Benign', 'APT']
    print(classification_report(y_test_final, y_pred, labels=labels, target_names=target_names, zero_division=0))


    # In Ma trận nhầm lẫn
    print("Confusion Matrix:")
    print(confusion_matrix(y_test_final, y_pred, labels=labels)) # Ensure order of labels

    # Tính và in các metrics quan trọng cho dữ liệu mất cân bằng
    accuracy = accuracy_score(y_test_final, y_pred)
    precision = precision_score(y_test_final, y_pred, pos_label=1, zero_division=0) # Precision for APT (positive class)
    recall = recall_score(y_test_final, y_pred, pos_label=1, zero_division=0)       # Recall for APT (positive class)
    f1 = f1_score(y_test_final, y_pred, pos_label=1, zero_division=0)         # F1-score for APT (positive class)

    print(f"Accuracy: {accuracy:.4f}")
    print(f"Precision (APT=1): {precision:.4f}")
    print(f"Recall (APT=1): {recall:.4f}")
    print(f"F1-score (APT=1): {f1:.4f}")

    # Tính và in AUC-ROC
    try:
        # Kiểm tra nếu tập test có cả 2 lớp
        if len(np.unique(y_test_final)) > 1:
            roc_auc = roc_auc_score(y_test_final, y_pred_proba)
            print(f"AUC-ROC: {roc_auc:.4f}")
        else:
             print("AUC-ROC cannot be calculated as only one class is present in test labels.")
    except Exception as e:
        print(f"Could not calculate AUC-ROC: {e}")


# --- Lưu Mô hình đã huấn luyện lại ---
print("\nSaving retrained models...")
NEW_RF_MODEL_FILE = 'rf_dapt2020_apt_retrained.pkl'
NEW_XGB_MODEL_FILE = 'xgb_dapt2020_apt_retrained.pkl'

try:
    joblib.dump(rf_model_retrained, os.path.join(PATH_TO_MODELS, NEW_RF_MODEL_FILE))
    joblib.dump(xgb_model_retrained, os.path.join(PATH_TO_MODELS, NEW_XGB_MODEL_FILE))
    print(f"Retrained models saved as {NEW_RF_MODEL_FILE} and {NEW_XGB_MODEL_FILE}")
except Exception as e:
    print(f"Error saving models: {e}")

print("\nFine-tuning process (retraining) complete.")