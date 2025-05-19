
import pandas as pd
import numpy as np
import joblib
from datetime import datetime, timedelta
import logging
import collections
import os

# --- Cấu hình ---
MODEL_PATH = r'dataset/working2/random_forest_model.pkl'
SCALER_PATH = r'dataset/working2/scaler.pkl' 

# Đường dẫn đến tệp CSV cụ thể do CICFlowMeter tạo ra
NETWORK_FLOWS_CSV_PATH = r'D:/Do_an_tot_nghiep/apt-detection/backend/network_flows.csv'

# Tùy chọn: Đặt tên tệp đầu ra cho kết quả dự đoán
output_dir = os.path.dirname(NETWORK_FLOWS_CSV_PATH) # Lấy thư mục chứa tệp CSV
output_filename = os.path.basename(NETWORK_FLOWS_CSV_PATH).replace('.csv', '_Predictions.csv') # Tạo tên tệp đầu ra
OUTPUT_CSV_PATH = os.path.join(output_dir, output_filename) # Đường dẫn đầy đủ tệp đầu ra


EXPECTED_FEATURES = None # Sẽ lấy từ scaler hoặc định nghĩa thủ công nếu cần

ROLLING_WINDOW_MINUTES = 2 # Ví dụ: 2 phút (chỉ dùng nếu model có dùng)

# --- Logging ---
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# --- Tải Model và Scaler ---
logging.info("Đang tải model và scaler...")
if not os.path.exists(MODEL_PATH):
    logging.error(f"Lỗi: Không tìm thấy tệp model tại '{MODEL_PATH}'. Vui lòng cập nhật đường dẫn.")
    exit()
if not os.path.exists(SCALER_PATH):
    logging.error(f"Lỗi: Không tìm thấy tệp scaler tại '{SCALER_PATH}'. Vui lòng cập nhật đường dẫn.")
    exit()

try:
    model = joblib.load(MODEL_PATH)
    scaler = joblib.load(SCALER_PATH)
    logging.info(f"Đã tải thành công model từ: {MODEL_PATH}")
    logging.info(f"Đã tải thành công scaler từ: {SCALER_PATH}")

    if hasattr(scaler, 'feature_names_in_'):
        EXPECTED_FEATURES = list(scaler.feature_names_in_)
        logging.info(f"Đã lấy danh sách {len(EXPECTED_FEATURES)} đặc trưng từ scaler: {EXPECTED_FEATURES[:10]}...") # In vài đặc trưng đầu
    else:
        # EXPECTED_FEATURES = ['Flow_Duration', 'Tot_Fwd_Pkts', 'Fwd_IAT_Mean', 'Flow_Byts_s', 'time_since_last_flow_src_sec']
        logging.warning(f"Không lấy được tên đặc trưng từ scaler. Cần định nghĩa EXPECTED_FEATURES thủ công!")
        # Để tránh lỗi, tạm dừng ở đây nếu không định nghĩa thủ công
        if EXPECTED_FEATURES is None:
             raise ValueError("EXPECTED_FEATURES chưa được định nghĩa và không lấy được từ scaler. Vui lòng định nghĩa thủ công trong code.")
        logging.info(f"Sử dụng danh sách đặc trưng thủ công: {EXPECTED_FEATURES}")

except FileNotFoundError: # Bắt lỗi chung hơn ở trên rồi
    logging.error(f"Lỗi: Không tìm thấy tệp model ('{MODEL_PATH}') hoặc scaler ('{SCALER_PATH}').")
    exit()
except Exception as e:
    logging.error(f"Lỗi khi tải model/scaler: {e}", exc_info=True)
    exit()

# --- Đọc và Tiền xử lý CSV từ CICFlowMeter ---
logging.info(f"Đang đọc tệp CSV từ CICFlowMeter: {NETWORK_FLOWS_CSV_PATH}")
if not os.path.exists(NETWORK_FLOWS_CSV_PATH):
    logging.error(f"Lỗi: Không tìm thấy tệp CSV tại '{NETWORK_FLOWS_CSV_PATH}'. Kiểm tra lại đường dẫn.")
    exit()

try:
    df = pd.read_csv(NETWORK_FLOWS_CSV_PATH)
    logging.info(f"Đã đọc thành công {len(df)} dòng.")

    # Lưu lại thông tin gốc nếu cần (ví dụ để giữ lại cột không dùng cho model)
    df_original = df.copy()

    # 1. Làm sạch tên cột
    original_columns = df.columns.tolist()
    df.columns = df.columns.str.strip()
    df.columns = df.columns.str.replace('[^A-Za-z0-9_]+', '_', regex=True) # Thay ký tự đặc biệt bằng _
    renamed_cols = dict(zip(original_columns, df.columns)) # Theo dõi đổi tên
    # Kiểm tra xem có cột nào quan trọng bị đổi tên không
    logging.info(f"Tên cột sau khi làm sạch (ví dụ): {df.columns.tolist()[:15]}...")

    # 2. Chuyển đổi Timestamp (QUAN TRỌNG cho việc sắp xếp và tính đặc trưng động)
    # !!! Kiểm tra tên cột timestamp ('Timestamp', 'timestamp',...) và định dạng trong file CSV của bạn !!!
    timestamp_col_original = 'Timestamp' # Tên cột gốc thường gặp
    timestamp_col = renamed_cols.get(timestamp_col_original, timestamp_col_original) # Lấy tên đã làm sạch nếu có

    if timestamp_col not in df.columns:
         # Thử tìm tên khác nếu không thấy tên mặc định
         possible_ts_cols = [col for col in df.columns if 'timestamp' in col.lower()]
         if possible_ts_cols:
             timestamp_col = possible_ts_cols[0]
             logging.warning(f"Không tìm thấy cột '{renamed_cols.get(timestamp_col_original, timestamp_col_original)}', sử dụng cột tìm thấy: '{timestamp_col}'")
         else:
             raise ValueError("Không tìm thấy cột Timestamp nào trong CSV. Cần cột này để sắp xếp và tính đặc trưng động.")


    logging.info(f"Đang chuyển đổi cột Timestamp: {timestamp_col} (tên gốc có thể là '{timestamp_col_original}')")
    try:
        # Thử các định dạng phổ biến của CICFlowMeter
        df[timestamp_col] = pd.to_datetime(df[timestamp_col], format='%d/%m/%Y %I:%M:%S %p', errors='raise')
    except ValueError:
        logging.warning(f"Không khớp định dạng '%d/%m/%Y %I:%M:%S %p'. Đang thử định dạng khác...")
        try:
            df[timestamp_col] = pd.to_datetime(df[timestamp_col], format='%Y-%m-%d %H:%M:%S.%f', errors='raise')
        except ValueError:
            logging.warning("Không khớp định dạng '%Y-%m-%d %H:%M:%S.%f'. Đang thử tự động nhận diện (infer_datetime_format)...")
            try:
                # Thử infer_datetime_format nếu các định dạng trên sai
                 # errors='coerce' sẽ biến lỗi thành NaT (Not a Time)
                df[timestamp_col] = pd.to_datetime(df[timestamp_col], infer_datetime_format=True, errors='coerce')
                if df[timestamp_col].isnull().any():
                    logging.error(f"Lỗi: Có giá trị không thể chuyển đổi thành ngày giờ trong cột '{timestamp_col}' sau khi thử các định dạng.")
                    # In ra vài dòng bị lỗi để kiểm tra
                    print("Các dòng có vấn đề về timestamp:")
                    print(df_original[df[timestamp_col].isnull()])
                    exit()
            except Exception as e_infer:
                logging.error(f"Lỗi nghiêm trọng khi chuyển đổi Timestamp cột '{timestamp_col}': {e_infer}. Không thể xử lý timestamp.")
                exit()
    except Exception as e:
         logging.error(f"Lỗi không xác định khi xử lý timestamp cột '{timestamp_col}': {e}", exc_info=True)
         exit()

    logging.info(f"Chuyển đổi Timestamp thành công. Ví dụ: {df[timestamp_col].iloc[0]}")


    # 3. Xử lý giá trị vô cùng và NaN
    logging.info("Đang xử lý giá trị Infinity và NaN...")
    # Tìm các cột có thể chứa infinity (thường là rate khi duration=0)
    rate_cols = [col for col in df.columns if '_Byts_s' in col or '_Pkts_s' in col or 'Bytes_s' in col or 'Pkts_s' in col] # Bao gồm cả tên gốc có thể
    if rate_cols:
        logging.debug(f"  Tìm thấy các cột có thể là rate: {rate_cols}")
        for col in rate_cols:
            if col in df.columns and pd.api.types.is_numeric_dtype(df[col]):
                inf_count = np.isinf(df[col]).sum()
                if inf_count > 0:
                    logging.debug(f"    Tìm thấy {inf_count} giá trị Inf trong cột '{col}'. Thay thế bằng NaN.")
                    df[col] = df[col].replace([np.inf, -np.inf], np.nan)
                # Quyết định cách điền NaN cho các cột rate (ví dụ: bằng 0 hoặc giá trị lớn)
                # Ở đây chọn điền bằng 0, CẨN THẬN vì có thể ảnh hưởng model
                # nan_count_before = df[col].isnull().sum()
                # df[col] = df[col].fillna(0)
                # nan_count_after = df[col].isnull().sum()
                # if nan_count_before > nan_count_after:
                #     logging.debug(f"    Đã điền {nan_count_before - nan_count_after} giá trị NaN trong cột '{col}' bằng 0.")

            elif col in df.columns:
                 logging.warning(f"  Cột rate dự kiến '{col}' không phải dạng số. Bỏ qua xử lý inf.")

    # Điền NaN còn lại trong các cột số (ví dụ bằng 0)
    numeric_cols = df.select_dtypes(include=np.number).columns.tolist()
    if len(numeric_cols) > 0:
        nan_counts = df[numeric_cols].isnull().sum()
        cols_with_nan = nan_counts[nan_counts > 0]
        if not cols_with_nan.empty:
            logging.warning(f"  Tìm thấy NaN trong các cột số sau đây. Sẽ điền bằng 0: \n{cols_with_nan}")
            df[numeric_cols] = df[numeric_cols].fillna(0)
            logging.info(f"  Đã điền NaN trong các cột số bằng 0.")
        else:
            logging.info("  Không tìm thấy NaN trong các cột số.")


    # 4. Đảm bảo kiểu dữ liệu số cho các đặc trưng mong đợi
    logging.info("Đảm bảo các cột đặc trưng yêu cầu có kiểu dữ liệu số...")
    feature_cols_to_check = [col for col in EXPECTED_FEATURES if col in df.columns and col != timestamp_col]
    converted_cols = []
    for col in feature_cols_to_check:
        if not pd.api.types.is_numeric_dtype(df[col]):
            logging.warning(f"  Cột '{col}' không phải dạng số. Đang thử chuyển đổi sang số...")
            original_non_numeric = df[col].apply(type).value_counts()
            try:
                df[col] = pd.to_numeric(df[col], errors='coerce') # Lỗi sẽ thành NaN
                nan_after_coerce = df[col].isnull().sum()
                if nan_after_coerce > 0:
                     logging.warning(f"    Chuyển đổi cột '{col}' tạo ra {nan_after_coerce} giá trị NaN. Sẽ điền bằng 0.")
                     df[col] = df[col].fillna(0) # Điền lại NaN nếu có lỗi chuyển đổi
                converted_cols.append(col)
            except Exception as convert_err:
                 logging.error(f"    Không thể chuyển đổi cột '{col}' thành số: {convert_err}. Kiểm tra dữ liệu trong cột này.")
                 # Có thể dừng chương trình ở đây nếu cột này quá quan trọng
                 # exit()

    if converted_cols:
        logging.info(f"  Đã chuyển đổi thành công các cột sau sang dạng số (và điền NaN nếu có): {converted_cols}")

except FileNotFoundError: # Bắt lỗi này ở trên rồi
    logging.error(f"Lỗi: Không tìm thấy tệp CSV '{NETWORK_FLOWS_CSV_PATH}'.")
    exit()
except ValueError as ve:
    logging.error(f"Lỗi dữ liệu hoặc cấu trúc trong tệp CSV: {ve}", exc_info=True)
    exit()
except Exception as e:
    logging.error(f"Lỗi không xác định khi đọc hoặc tiền xử lý CSV: {e}", exc_info=True)
    exit()


# --- Tính toán Đặc trưng Động trên DataFrame (NẾU CẦN) ---
# Phần này chỉ nên chạy nếu model của bạn được huấn luyện với các đặc trưng này
logging.info("Kiểm tra và tính toán đặc trưng động (hành vi/thời gian)...")

# QUAN TRỌNG: Sắp xếp theo Timestamp trước khi tính
df = df.sort_values(by=timestamp_col)
df = df.reset_index(drop=True) # Reset index sau khi sắp xếp

# --- Ví dụ: Đặc trưng dựa trên thời gian ---
# 1. Tính Time Since Last Flow cho Src IP
# !!! Kiểm tra xem model có dùng đặc trưng 'time_since_last_flow_src_sec' không !!!
feature_time_since = 'time_since_last_flow_src_sec'
if feature_time_since in EXPECTED_FEATURES:
    # !!! Kiểm tra tên cột IP nguồn chính xác sau khi làm sạch !!!
    src_ip_col_original = 'Src IP'
    src_ip_col = renamed_cols.get(src_ip_col_original, src_ip_col_original)
    if src_ip_col in df.columns:
        logging.info(f"  Tính '{feature_time_since}' cho cột '{src_ip_col}'...")
        # Tính diff theo group và chuyển sang giây
        df[feature_time_since] = df.groupby(src_ip_col)[timestamp_col].diff().dt.total_seconds()
        # Điền NaN (cho flow đầu tiên của mỗi IP) và đảm bảo không âm
        # Có thể điền bằng giá trị lớn thay vì 0 nếu phù hợp hơn với model
        fill_value_time_since = 0 # Hoặc ví dụ: df[feature_time_since].max() nếu không phải 0
        df[feature_time_since] = df[feature_time_since].fillna(fill_value_time_since).clip(lower=0)
        logging.info(f"    Tính xong '{feature_time_since}'. Giá trị ví dụ: {df[feature_time_since].head().tolist()}")
    else:
        logging.warning(f"Không tìm thấy cột IP nguồn '{src_ip_col}' (tên gốc có thể là '{src_ip_col_original}'). Bỏ qua tính '{feature_time_since}'.")
        # Nếu đặc trưng này bắt buộc, cần tạo cột giả hoặc dừng lại
        df[feature_time_since] = 0.0 # Tạo cột với giá trị mặc định
else:
    logging.info(f"Bỏ qua tính '{feature_time_since}' vì không có trong EXPECTED_FEATURES.")


# --- Ví dụ: Đặc trưng Rolling Window ---
# Đặt Timestamp làm index tạm thời để dùng rolling theo thời gian
src_ip_col_original = 'Src IP' # Tên cột IP nguồn gốc
src_ip_col = renamed_cols.get(src_ip_col_original, src_ip_col_original) # Tên đã làm sạch
window_str = f"{ROLLING_WINDOW_MINUTES}min"

# Kiểm tra xem có cần tính rolling window nào không
rolling_features_in_expected = [f for f in EXPECTED_FEATURES if f.startswith(('flow_count_roll', 'sum_', 'mean_', 'std_', 'nunique_')) and f'roll{ROLLING_WINDOW_MINUTES}m' in f]

if rolling_features_in_expected and src_ip_col in df.columns:
    logging.info(f"Chuẩn bị tính các đặc trưng rolling window ({window_str}) cho '{src_ip_col}'...")
    df_indexed = df.set_index(timestamp_col)
    grouped_src_indexed = df_indexed.groupby(src_ip_col)

    # Ví dụ 1: Rolling count
    feature_name_roll_count = f'flow_count_roll{ROLLING_WINDOW_MINUTES}m_src'
    if feature_name_roll_count in EXPECTED_FEATURES:
        logging.info(f"  Tính {feature_name_roll_count}...")
        # Cần một cột luôn tồn tại để count, dùng src_ip_col hoặc cột đầu tiên
        count_col = src_ip_col if src_ip_col in df_indexed.columns else df_indexed.columns[0]
        # .rolling(...).count() trả về Series với multi-index (src_ip, timestamp)
        rolling_count_result = grouped_src_indexed[count_col].rolling(window=window_str, closed='left').count() # closed='left' để không bao gồm dòng hiện tại
        # Reset index để timestamp thành cột, rồi map lại vào df_indexed
        rolling_count_result = rolling_count_result.reset_index(level=0, drop=True) # Bỏ index src_ip
        df_indexed[feature_name_roll_count] = rolling_count_result
        # Điền NaN (các dòng đầu tiên trong window) bằng 0 hoặc 1 tùy logic
        df_indexed[feature_name_roll_count] = df_indexed[feature_name_roll_count].fillna(0) # Giả sử bắt đầu từ 0
        logging.info(f"    Tính xong '{feature_name_roll_count}'.")
    else:
        logging.debug(f"Bỏ qua tính '{feature_name_roll_count}' vì không có trong EXPECTED_FEATURES.")

    # !!! Kiểm tra tên cột 'Total Fwd Packets' sau khi làm sạch !!!
    feature_to_sum_original = 'Total Fwd Packets'
    feature_to_sum = renamed_cols.get(feature_to_sum_original, feature_to_sum_original)
    feature_name_roll_sum = f'sum_fwd_pkts_roll{ROLLING_WINDOW_MINUTES}m_src' # Đặt tên nhất quán

    if feature_name_roll_sum in EXPECTED_FEATURES:
        if feature_to_sum in df_indexed.columns:
             logging.info(f"  Tính {feature_name_roll_sum} từ cột '{feature_to_sum}'...")
             rolling_sum_result = grouped_src_indexed[feature_to_sum].rolling(window=window_str, closed='left').sum()
             rolling_sum_result = rolling_sum_result.reset_index(level=0, drop=True)
             df_indexed[feature_name_roll_sum] = rolling_sum_result
             df_indexed[feature_name_roll_sum] = df_indexed[feature_name_roll_sum].fillna(0)
             logging.info(f"    Tính xong '{feature_name_roll_sum}'.")
        else:
            logging.warning(f"  Không tìm thấy cột '{feature_to_sum}' (tên gốc có thể là '{feature_to_sum_original}') để tính {feature_name_roll_sum}. Bỏ qua hoặc điền 0.")
            # Nếu đặc trưng này bắt buộc, tạo cột giả hoặc dừng
            df_indexed[feature_name_roll_sum] = 0.0 # Tạo cột với giá trị mặc định
    else:
        logging.debug(f"Bỏ qua tính '{feature_name_roll_sum}' vì không có trong EXPECTED_FEATURES.")

    df = df_indexed.reset_index()
    logging.info("Đã tính xong các đặc trưng rolling window.")

elif not rolling_features_in_expected:
     logging.info("Không có đặc trưng rolling window nào trong EXPECTED_FEATURES. Bỏ qua tính toán rolling.")
elif src_ip_col not in df.columns:
     logging.warning(f"Có đặc trưng rolling trong EXPECTED_FEATURES nhưng không tìm thấy cột IP nguồn '{src_ip_col}'. Không thể tính rolling window.")
     # Tạo các cột rolling với giá trị mặc định nếu chúng bắt buộc
     for roll_feat in rolling_features_in_expected:
         logging.warning(f"  Tạo cột '{roll_feat}' với giá trị mặc định 0.0.")
         df[roll_feat] = 0.0

# --- Chuẩn bị Dữ liệu cho Model ---
logging.info("Chuẩn bị dữ liệu cho model...")

# 1. Lấy danh sách các cột hiện có trong DataFrame sau khi xử lý
current_columns = df.columns.tolist()

# 2. Xác định cột thiếu và cột thừa so với EXPECTED_FEATURES
if EXPECTED_FEATURES is None:
    logging.error("Lỗi: EXPECTED_FEATURES chưa được xác định. Không thể tiếp tục.")
    exit()

expected_set = set(EXPECTED_FEATURES)
current_set = set(current_columns)

missing_features = list(expected_set - current_set)
extra_features = list(current_set - expected_set)

# 3. Xử lý cột thiếu: Thêm vào DataFrame với giá trị mặc định
if missing_features:
    logging.warning(f"Tìm thấy {len(missing_features)} cột bị thiếu so với yêu cầu của model: {missing_features}")
    logging.warning("Sẽ thêm các cột này vào DataFrame và điền giá trị mặc định là 0.")
    for col in missing_features:
        df[col] = 0.0 # Thêm cột mới và điền 0.0 (kiểu float)
    logging.info(f"Đã thêm các cột thiếu vào DataFrame.")
else:
    logging.info("Không có cột nào bị thiếu so với yêu cầu của model.")

# 4. Xử lý cột thừa: Không cần xóa khỏi df, chỉ cần chọn đúng cột ở bước sau
if extra_features:
    logging.info(f"Tìm thấy {len(extra_features)} cột thừa trong DataFrame (sẽ không được sử dụng cho model): {extra_features[:10]}...") # In vài cột thừa đầu
else:
    logging.info("Không có cột thừa nào trong DataFrame so với yêu cầu của model.")


# 5. Chọn đúng các cột đặc trưng THEO ĐÚNG THỨ TỰ và đảm bảo kiểu float
logging.info(f"Đang chọn và sắp xếp {len(EXPECTED_FEATURES)} cột theo đúng thứ tự yêu cầu: {EXPECTED_FEATURES[:10]}...")
try:
    # Bước này sẽ tự động chọn cột cần thiết VÀ sắp xếp theo thứ tự của EXPECTED_FEATURES
    X_test = df[EXPECTED_FEATURES].astype(float)
except KeyError as ke:
     # Lỗi này không nên xảy ra nữa nếu bước thêm cột thiếu thành công
     logging.error(f"Lỗi KeyError không mong muốn khi chọn cột: {ke}. Có vẻ cột thiếu chưa được thêm đúng cách.")
     exit()
except Exception as e_astype:
     logging.error(f"Lỗi khi chuyển đổi các cột đặc trưng đã chọn sang float: {e_astype}", exc_info=True)
     # Kiểm tra xem cột nào gây lỗi
     for col in EXPECTED_FEATURES:
         if col in df.columns: # Kiểm tra cột tồn tại trước khi thử astype
             try:
                 df[col].astype(float)
             except Exception as col_err:
                 logging.error(f"  Cột '{col}' có thể đang gây lỗi chuyển đổi kiểu dữ liệu.")
         else:
             # Điều này cũng không nên xảy ra
             logging.error(f"  Cột '{col}' không tìm thấy trong df ngay cả sau khi đã cố thêm?")
     exit()

logging.info(f"Đã tạo thành công DataFrame X_test với đúng các cột và thứ tự, shape: {X_test.shape}")

# --- Chuẩn hóa Dữ liệu ---
logging.info(f"Áp dụng scaler cho {X_test.shape[0]} dòng dữ liệu với {X_test.shape[1]} đặc trưng...")
try:
    # Kiểm tra lại số lượng đặc trưng trước khi transform (nên khớp)
    n_features_in_scaler = getattr(scaler, 'n_features_in_', None)
    if n_features_in_scaler is not None and n_features_in_scaler != X_test.shape[1]:
         # Lỗi này giờ rất khó xảy ra trừ khi EXPECTED_FEATURES khác với scaler
         logging.error(f"Lỗi nghiêm trọng: Số lượng đặc trưng trong X_test ({X_test.shape[1]}) vẫn không khớp với scaler ({n_features_in_scaler}) sau khi đã điều chỉnh.")
         logging.error(f"Kiểm tra lại danh sách EXPECTED_FEATURES đã được lấy từ scaler hoặc định nghĩa thủ công có khớp với scaler đã lưu không.")
         exit()
    elif X_test.shape[1] != len(EXPECTED_FEATURES):
         # Lỗi logic nếu điều này xảy ra
         logging.error(f"Lỗi logic: Số lượng cột trong X_test ({X_test.shape[1]}) không bằng độ dài của EXPECTED_FEATURES ({len(EXPECTED_FEATURES)}).")
         exit()


    X_test_scaled = scaler.transform(X_test)
except ValueError as e:
    # Bắt lỗi cụ thể hơn nếu có thể
    if "Input contains NaN" in str(e):
        logging.error(f"Lỗi khi áp dụng scaler: Dữ liệu đầu vào (X_test) chứa NaN.")
        nan_in_xtest = X_test.isnull().sum()
        logging.error(f"Số lượng NaN trong các cột đặc trưng TRƯỚC khi scale:\n{nan_in_xtest[nan_in_xtest > 0]}")
        logging.error("Kiểm tra lại bước xử lý NaN hoặc bước thêm cột thiếu (có thể tạo NaN nếu có lỗi).")
    elif "features, but" in str(e): # Lỗi số lượng đặc trưng, không nên xảy ra nữa
         logging.error(f"Lỗi không mong muốn khi áp dụng scaler: Số lượng đặc trưng không khớp. {e}")
    else:
        logging.error(f"Lỗi ValueError khi áp dụng scaler: {e}. Kiểm tra sự khớp giữa dữ liệu và scaler.")
    exit()
except Exception as e:
    logging.error(f"Lỗi không xác định khi áp dụng scaler: {e}", exc_info=True)
    exit()

logging.info("Chuẩn hóa dữ liệu thành công.")

# --- Dự đoán ---
logging.info("Bắt đầu dự đoán bằng model...")
try:
    predictions = model.predict(X_test_scaled)
    try:
        probabilities = model.predict_proba(X_test_scaled)
        # Lấy xác suất của lớp dự đoán (hoặc lớp tấn công)
        prediction_probabilities = np.max(probabilities, axis=1)
    except AttributeError:
         logging.info("Model không có phương thức 'predict_proba'.")
         probabilities = None # Hoặc một giá trị mặc định khác
except Exception as e:
    logging.error(f"Lỗi khi dự đoán bằng model: {e}", exc_info=True)
    exit()

logging.info("Dự đoán hoàn thành.")

# --- Phân tích Kết quả ---

df['Prediction'] = predictions

# Đếm số lượng dự đoán cho mỗi loại
prediction_counts = df['Prediction'].value_counts()
logging.info("\n--- Thống kê Kết quả Dự đoán ---")
print(prediction_counts)

# Xác định các luồng đáng ngờ
benign_labels = ['Benign', 0, 'BENIGN'] # Các nhãn có thể của lưu lượng bình thường
# Kiểm tra xem nhãn nào thực sự có trong kết quả dự đoán
actual_benign_labels = [label for label in benign_labels if label in df['Prediction'].unique()]

if actual_benign_labels:
     logging.info(f"Xác định luồng đáng ngờ (không phải là: {actual_benign_labels})...")
     suspicious_label_condition = ~df['Prediction'].isin(actual_benign_labels) # Dùng isin cho nhiều nhãn
else:
     logging.warning("Không tìm thấy nhãn bình thường nào trong kết quả dự đoán (đã kiểm tra: {benign_labels}). Coi tất cả là đáng ngờ.")
     suspicious_label_condition = pd.Series([True] * len(df), index=df.index) # Chọn tất cả

suspicious_flows = df[suspicious_label_condition]

logging.info(f"\n--- Phát hiện {len(suspicious_flows)} luồng đáng ngờ trên tổng số {len(df)} luồng ---")

if not suspicious_flows.empty:
    print("\nVí dụ về các luồng được dự đoán là đáng ngờ:")
    # Chọn các cột quan trọng để hiển thị
    display_cols_suspicious = [
        timestamp_col, # Cột timestamp đã xử lý
        renamed_cols.get('Flow ID', 'Flow ID'),
        renamed_cols.get('Src IP', 'Src_IP'),
        renamed_cols.get('Src Port', 'Src_Port'),
        renamed_cols.get('Dst IP', 'Dst_IP'),
        renamed_cols.get('Dst Port', 'Dst_Port'),
        renamed_cols.get('Protocol', 'Protocol'),
        'Prediction' # Cột dự đoán
    ]
    # Lọc ra những cột thực sự tồn tại trong df để tránh lỗi KeyError
    display_cols_suspicious_existing = [col for col in display_cols_suspicious if col in df.columns]

    # Thêm một vài đặc trưng quan trọng từ EXPECTED_FEATURES

    print(suspicious_flows[display_cols_suspicious_existing].head(10)) # In 10 dòng đầu

    # Lưu toàn bộ DataFrame với dự đoán
    try:
        logging.info(f"Đang lưu kết quả dự đoán (tất cả các luồng) vào: {OUTPUT_CSV_PATH}")
        df.to_csv(OUTPUT_CSV_PATH, index=False, encoding='utf-8') # Thêm encoding
        logging.info("Lưu kết quả thành công.")

        # Lưu riêng các luồng đáng ngờ
        suspicious_output_path = os.path.join(output_dir, 'Suspicious_' + output_filename)
        logging.info(f"Đang lưu các luồng đáng ngờ vào: {suspicious_output_path}")
        suspicious_flows.to_csv(suspicious_output_path, index=False, encoding='utf-8')
        logging.info("Lưu luồng đáng ngờ thành công.")

    except Exception as e:
        logging.error(f"Lỗi khi lưu kết quả vào CSV: {e}")

else:
    logging.info("Không phát hiện luồng nào được dự đoán là đáng ngờ trong tệp này.")
    # Vẫn lưu kết quả nếu muốn xem các dự đoán 'Benign'
    try:
        logging.info(f"Đang lưu kết quả dự đoán (chỉ chứa luồng bình thường) vào: {OUTPUT_CSV_PATH}")
        df.to_csv(OUTPUT_CSV_PATH, index=False, encoding='utf-8')
        logging.info("Lưu kết quả thành công.")
    except Exception as e:
         logging.error(f"Lỗi khi lưu kết quả vào CSV: {e}")


logging.info("\n--- Hoàn thành ---")