import pandas as pd
import xgboost as xgb
from sklearn.preprocessing import LabelEncoder, StandardScaler
from sklearn.metrics import precision_score, recall_score, f1_score, roc_auc_score, roc_curve
from sklearn.model_selection import GridSearchCV
from imblearn.over_sampling import SMOTE
import matplotlib.pyplot as plt
import logging
import pickle
import os

# Thiết lập logging
logging.basicConfig(filename='D:/Đồ án tốt nghiệp/backend/ai-training/training_log.log',
                    level=logging.INFO,
                    format='%(asctime)s - %(levelname)s - %(message)s')

# Đọc dữ liệu
train_data = pd.read_csv('data/UNSW_NB15-dataset/UNSW_NB15_training-set.csv')
test_data = pd.read_csv('data/UNSW_NB15-dataset/UNSW_NB15_testing-set.csv')

# Loại bỏ cột không cần thiết
train_data = train_data.drop(['id'], axis=1)
test_data = test_data.drop(['id'], axis=1)

# Lọc dữ liệu APT và tạo bản sao rõ ràng
apt_categories = ['Exploits', 'Reconnaissance']
train_apt = train_data[train_data['attack_cat'].isin(apt_categories) | (train_data['label'] == 0)].copy()
test_apt = test_data[test_data['attack_cat'].isin(apt_categories) | (test_data['label'] == 0)].copy()

logging.info(f"Train data shape: {train_apt.shape}")
logging.info(f"Test data shape: {test_apt.shape}")

# Xử lý cột phân loại
cat_columns = ['proto', 'service', 'state']
le = LabelEncoder()

for col in cat_columns:
    combined = pd.concat([train_apt[col], test_apt[col]], axis=0)
    le.fit(combined)
    train_apt.loc[:, col] = le.transform(train_apt[col])
    test_apt.loc[:, col] = le.transform(test_apt[col])

# Xử lý giá trị thiếu
train_apt.fillna(0, inplace=True)
test_apt.fillna(0, inplace=True)

# Tách đặc trưng và nhãn
X_train = train_apt.drop(['label', 'attack_cat'], axis=1)
y_train = train_apt['label']
X_test = test_apt.drop(['label', 'attack_cat'], axis=1)
y_test = test_apt['label']

# Chuẩn hóa dữ liệu
scaler = StandardScaler()
X_train = scaler.fit_transform(X_train)
X_test = scaler.transform(X_test)

# Xử lý dữ liệu không cân bằng bằng SMOTE (tùy chọn)
smote = SMOTE(random_state=42)
X_train_res, y_train_res = smote.fit_resample(X_train, y_train)
logging.info(f"After SMOTE - Train data shape: {X_train_res.shape}")

# Chuyển sang DMatrix
dtrain = xgb.DMatrix(X_train_res, label=y_train_res)
dtest = xgb.DMatrix(X_test, label=y_test)

# Tham số cơ bản (loại bỏ n_estimators)
params = {
    'objective': 'binary:logistic',
    'eval_metric': 'auc',
    'subsample': 0.8,
    'colsample_bytree': 0.8,
    'scale_pos_weight': sum(y_train == 0) / sum(y_train == 1)
}

# Tinh chỉnh tham số bằng GridSearchCV
xgb_model = xgb.XGBClassifier(**params)
param_grid = {
    'max_depth': [3, 5, 7],
    'learning_rate': [0.01, 0.1, 0.3],
    'n_estimators': [100, 200]
}
grid_search = GridSearchCV(estimator=xgb_model, param_grid=param_grid, scoring='roc_auc', cv=3, verbose=1)
grid_search.fit(X_train_res, y_train_res)

# Lấy tham số tốt nhất
best_params = grid_search.best_params_
logging.info(f"Best parameters from GridSearchCV: {best_params}")

# Cập nhật tham số (loại bỏ n_estimators vì dùng num_boost_round)
params.update({k: v for k, v in best_params.items() if k != 'n_estimators'})

# Huấn luyện mô hình cuối cùng
model = xgb.train(params, dtrain, num_boost_round=best_params['n_estimators'],
                  evals=[(dtest, 'test')], early_stopping_rounds=10, verbose_eval=True)

# Dự đoán
y_pred = model.predict(dtest)
y_pred_binary = [1 if x > 0.5 else 0 for x in y_pred]

# Đánh giá
precision = precision_score(y_test, y_pred_binary)
recall = recall_score(y_test, y_pred_binary)
f1 = f1_score(y_test, y_pred_binary)
auc = roc_auc_score(y_test, y_pred)

print(f"Precision: {precision:.4f}")
print(f"Recall: {recall:.4f}")
print(f"F1-score: {f1:.4f}")
print(f"ROC-AUC: {auc:.4f}")
logging.info(f"Precision: {precision:.4f}, Recall: {recall:.4f}, F1-score: {f1:.4f}, ROC-AUC: {auc:.4f}")

# Vẽ ROC Curve
fpr, tpr, _ = roc_curve(y_test, y_pred)
plt.figure()
plt.plot(fpr, tpr, color='blue', label=f'ROC curve (AUC = {auc:.4f})')
plt.plot([0, 1], [0, 1], color='gray', linestyle='--')
plt.xlabel('False Positive Rate')
plt.ylabel('True Positive Rate')
plt.title('ROC Curve')
plt.legend(loc="lower right")
plt.savefig('D:/Đồ án tốt nghiệp/backend/ai-training/roc_curve.png')
plt.close()
logging.info("ROC Curve đã được lưu vào roc_curve.png")

# Lưu mô hình
model.save_model('D:/Đồ án tốt nghiệp/backend/ai-training/xgboost_apt_model.json')
print("Mô hình đã được lưu vào xgboost_apt_model.json")
logging.info("Mô hình đã được lưu vào xgboost_apt_model.json")

# Lưu LabelEncoder và StandardScaler
for col in cat_columns:
    with open(f'D:/Đồ án tốt nghiệp/backend/ai-training/le_{col}.pkl', 'wb') as f:
        pickle.dump(le, f)
with open('D:/Đồ án tốt nghiệp/backend/ai-training/scaler.pkl', 'wb') as f:
    pickle.dump(scaler, f)
print("LabelEncoder và StandardScaler đã được lưu.")
logging.info("LabelEncoder và StandardScaler đã được lưu.")