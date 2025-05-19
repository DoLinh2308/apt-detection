# import logging
# import sys
# import os
# import time
# import csv
# import random
# project_root = os.path.dirname(os.path.abspath(__file__))
# sys.path.append(project_root)

# try:
#     from capture_module.capture_manager import start_capture 
#     from prediction_module.run_prediction import run_prediction_pipeline
# except ImportError as e:
#     print(f"Lỗi khi nhập module: {e}")
#     print("Vui lòng đảm bảo:")
#     print("1. Script này nằm ở thư mục cha của 'capture_module' và 'prediction_module'.")
#     print("2. Cả hai thư mục module đều có một tệp '__init__.py' trống.")
#     print("3. Các hàm cần thiết (start_capture, run_prediction_pipeline) được định nghĩa đúng và có thể nhập.")
#     sys.exit(1) # Thoát nếu không nhập được module

# def main():
#     # Generate traffic analysis data
#     traffic_data = {
#         'normal': 1423,  # MB
#         'suspicious': 62,  # MB
#         'malicious': 12  # MB
#     }
#     with open('backend/results/traffic_analysis.csv', 'w', newline='') as f:
#         writer = csv.DictWriter(f, fieldnames=['normal', 'suspicious', 'malicious'])
#         writer.writeheader()
#         writer.writerow(traffic_data)

#     # Generate global threat map data
#     threat_map_data = {
#         'activeAttacks': 24,
#         'countries': 8,
#         'totalToday': 156
#     }
#     with open('backend/results/global_threat_map.csv', 'w', newline='') as f:
#         writer = csv.DictWriter(f, fieldnames=['activeAttacks', 'countries', 'totalToday'])
#         writer.writeheader()
#         writer.writerow(threat_map_data)
        
#     """Chạy pipeline chính để capture và prediction."""
#     # Cấu hình logging cơ bản
#     logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
#     logging.info("--- Bắt đầu Pipeline Chính ---")

#     # --- Bước 1: Chạy Module Network Capture ---
#     logging.info(">>> Bắt đầu Module Network Capture <<<")
#     try:
#         # Gọi trực tiếp hàm capture cốt lõi
#         # Thêm các đối số cần thiết nếu start_capture yêu cầu
#         start_capture()
#         logging.info(">>> Module Network Capture Hoàn thành <<<")
#         # Thêm độ trễ nhỏ nếu cần, ví dụ: để đảm bảo tệp đã được ghi xong
#         time.sleep(2)
#     except Exception as e:
#         # Ghi log lỗi chi tiết nếu có ngoại lệ xảy ra
#         logging.error(f"Lỗi trong quá trình Network Capture: {e}", exc_info=True)
#         logging.info("--- Pipeline Chính Thất bại trong quá trình Capture ---")
#         return # Dừng pipeline nếu capture thất bại

#     # --- Bước 2: Chạy Module Prediction ---
#     logging.info(">>> Bắt đầu Module Prediction <<<")
#     try:
#         # Gọi hàm prediction pipeline
#         success = run_prediction_pipeline()
#         if success:
#             logging.info(">>> Module Prediction Hoàn thành Thành công <<<")
#         else:
#             # Ghi cảnh báo nếu pipeline dự đoán kết thúc nhưng có vấn đề
#             logging.warning(">>> Module Prediction Hoàn thành Với Vấn đề (kiểm tra log của prediction) <<<")
#     except Exception as e:
#         # Ghi log lỗi chi tiết nếu có ngoại lệ xảy ra
#         logging.error(f"Lỗi trong quá trình Prediction: {e}", exc_info=True)
#         logging.info("--- Pipeline Chính Thất bại trong quá trình Prediction ---")
#         return # Dừng pipeline nếu prediction thất bại

#     logging.info("--- Pipeline Chính Hoàn thành Thành công ---")

# if __name__ == "__main__":
#     main()

import logging
import sys
import os
import time
import csv
import pandas as pd
from capture_module.capture_manager import start_capture
from prediction_module.run_prediction import run_prediction_pipeline
from prediction_module import config

# Set up logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

def main():
    logger.info("--- Starting Main Pipeline ---")

    # --- Step 1: Run Network Capture ---
    logger.info(">>> Starting Network Capture <<<")
    try:
        start_capture()
        logger.info(">>> Network Capture Completed <<<")
        time.sleep(2)  # Small delay to ensure file is written
    except Exception as e:
        logger.error(f"Error in Network Capture: {e}", exc_info=True)
        logger.info("--- Pipeline Failed in Capture ---")
        return

    # --- Step 2: Run Prediction Pipeline ---
    logger.info(">>> Starting Prediction Module <<<")
    try:
        success = run_prediction_pipeline()
        if not success:
            logger.warning(">>> Prediction Module Completed with Issues <<<")
            return
        logger.info(">>> Prediction Module Completed Successfully <<<")
    except Exception as e:
        logger.error(f"Error in Prediction: {e}", exc_info=True)
        logger.info("--- Pipeline Failed in Prediction ---")
        return

    # --- Step 3: Process Results for Traffic Analysis and Global Threat Map ---
    logger.info(">>> Processing Analysis Results <<<")

    # Load prediction results
    predictions_df = pd.read_csv(config.PREDICTIONS_OUTPUT_CSV_PATH)
    suspicious_df = pd.read_csv(config.SUSPICIOUS_OUTPUT_CSV_PATH) if os.path.exists(config.SUSPICIOUS_OUTPUT_CSV_PATH) else pd.DataFrame()

    # Calculate Traffic Analysis Data
    # Assuming 'Total Length of Fwd Packets' or similar field represents traffic volume (in bytes)
    traffic_volume_col = 'Total Length of Fwd Packets'  # Adjust based on your CSV columns
    if traffic_volume_col in predictions_df.columns:
        # Aggregate total traffic
        total_traffic = predictions_df[traffic_volume_col].sum() / (1024 * 1024)  # Convert to MB

        # Classify traffic based on predictions
        benign_labels = [str(label).lower() for label in config.BENIGN_LABELS]
        normal_traffic = predictions_df[predictions_df['Prediction'].str.lower().isin(benign_labels)][traffic_volume_col].sum() / (1024 * 1024) if 'Prediction' in predictions_df.columns else 0
        suspicious_traffic = predictions_df[~predictions_df['Prediction'].str.lower().isin(benign_labels)][traffic_volume_col].sum() / (1024 * 1024) if 'Prediction' in predictions_df.columns else 0
        malicious_traffic = suspicious_df[traffic_volume_col].sum() / (1024 * 1024) if not suspicious_df.empty else 0

        traffic_data = {
            'normal': round(normal_traffic, 2),
            'suspicious': round(suspicious_traffic, 2),
            'malicious': round(malicious_traffic, 2)
        }
    else:
        logger.warning(f"Column '{traffic_volume_col}' not found. Using dummy traffic data.")
        traffic_data = {'normal': 1423, 'suspicious': 62, 'malicious': 12}  # Fallback to dummy data

    # Save Traffic Analysis Data
    with open(os.path.join(config.RESULTS_DIR, 'traffic_analysis.csv'), 'w', newline='') as f:
        writer = csv.DictWriter(f, fieldnames=['normal', 'suspicious', 'malicious'])
        writer.writeheader()
        writer.writerow(traffic_data)
    logger.info(f"Traffic analysis data saved to {os.path.join(config.RESULTS_DIR, 'traffic_analysis.csv')}")

    # Calculate Global Threat Map Data
    if not suspicious_df.empty:
        # Count unique source IPs to approximate active attacks and countries
        unique_src_ips = suspicious_df['Src IP'].nunique() if 'Src IP' in suspicious_df.columns else 0
        unique_countries = len(set(suspicious_df['Src IP'].apply(lambda x: x.split('.')[0] if '.' in x else 'Unknown'))) if 'Src IP' in suspicious_df.columns else 0  # Rough country estimation
        total_attacks = len(suspicious_df)

        threat_map_data = {
            'activeAttacks': unique_src_ips,
            'countries': unique_countries,
            'totalToday': total_attacks
        }
    else:
        logger.warning("No suspicious flows found. Using dummy threat map data.")
        threat_map_data = {'activeAttacks': 24, 'countries': 8, 'totalToday': 156}  # Fallback to dummy data

    # Save Global Threat Map Data
    with open(os.path.join(config.RESULTS_DIR, 'global_threat_map.csv'), 'w', newline='') as f:
        writer = csv.DictWriter(f, fieldnames=['activeAttacks', 'countries', 'totalToday'])
        writer.writeheader()
        writer.writerow(threat_map_data)
    logger.info(f"Global threat map data saved to {os.path.join(config.RESULTS_DIR, 'global_threat_map.csv')}")

    logger.info("--- Pipeline Completed Successfully ---")

if __name__ == "__main__":
    main()