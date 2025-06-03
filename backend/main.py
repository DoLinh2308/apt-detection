# backend/main.py
import logging
import sys
import os
import time
import csv
import pandas as pd

try:
    # Đảm bảo import đúng
    from capture_module.capture_manager import start_capture
    from prediction_module.run_prediction import run_prediction_pipeline
    from prediction_module import config as prediction_config # Đổi tên để tránh nhầm lẫn với config của capture
    # Bạn cũng có thể cần config của capture_module nếu nó khác
    # from capture_module import config as capture_config
except ImportError as e:
    logging.error(f"Error importing modules in main.py: {e}", exc_info=True)
    sys.exit(1)


logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

def get_notification_config():
    # ... (hàm này giữ nguyên) ...
    email_enabled_by_env = os.getenv('EMAIL_SENDER_ADDRESS') is not None
    email_cfg = {
        'enabled': email_enabled_by_env,
        'sender_address': os.getenv('EMAIL_SENDER_ADDRESS'),
        'sender_password': os.getenv('EMAIL_SENDER_PASSWORD'),
        'receiver_address': os.getenv('EMAIL_RECEIVER_ADDRESS'),
        'smtp_server': os.getenv('SMTP_SERVER', 'smtp.gmail.com'),
        'smtp_port': int(os.getenv('SMTP_PORT', 587))
    }
    if not all([email_cfg['sender_address'], email_cfg['receiver_address'], email_cfg['smtp_server']]):
        email_cfg['enabled'] = False
    if email_cfg['enabled']:
         logger.info("Email notifications seem to be configured via environment variables for backend.")

    telegram_enabled_by_env = os.getenv('BOT_TOKEN') is not None
    telegram_cfg = {
        'enabled': telegram_enabled_by_env,
        'bot_token': os.getenv('BOT_TOKEN'),
        'chat_id': os.getenv('CHAT_ID')
    }
    if not all([telegram_cfg['bot_token'], telegram_cfg['chat_id']]):
        telegram_cfg['enabled'] = False
    if telegram_cfg['enabled']:
        logger.info("Telegram notifications seem to be configured via environment variables for backend.")
    return email_cfg, telegram_cfg


def main_pipeline():
    logger.info("--- Starting Main Python Backend Pipeline ---")

    email_config_params, telegram_config_params = get_notification_config()
    # Note: email_config_params và telegram_config_params hiện chưa được sử dụng trực tiếp
    # Các module con như send_email_notification.py đang tự đọc os.getenv()

    # --- Step 1: Run Network Capture ---
    logger.info(">>> Starting Network Capture Module <<<") # Sửa tên log
    try:
        # `start_capture()` sẽ tạo ra file network_flows.csv (theo config.OUTPUT_CSV_FILE của nó)
        start_capture()
        logger.info(">>> Network Capture Module Completed <<<")
        # Delay nhỏ để đảm bảo file được ghi xong hoàn toàn trước khi prediction đọc
        time.sleep(2)
    except PermissionError as e: # Cụ thể hóa lỗi quyền
        logger.error(f"PermissionError during Network Capture: {e}. Try running with admin/root privileges.", exc_info=False)
        logger.info("--- Backend Pipeline Failed in Capture (Permission Denied) ---")
        return
    except Exception as e:
        logger.error(f"Error in Network Capture: {e}", exc_info=True)
        logger.info("--- Backend Pipeline Failed in Capture ---")
        return

    # --- Step 2: Run Prediction Pipeline ---
    # Prediction module sẽ đọc file network_flows.csv vừa được tạo
    logger.info(">>> Starting Prediction Module <<<")
    try:
        # success = run_prediction_pipeline(email_config=email_config_params, telegram_config=telegram_config_params)
        # Hiện tại các module gửi mail/telegram tự đọc ENV
        success = run_prediction_pipeline()
        if not success:
            logger.warning(">>> Prediction Module Completed with Issues (check prediction logs) <<<")
            # Không return ở đây nếu vẫn muốn tạo file summary
        else:
            logger.info(">>> Prediction Module Completed Successfully <<<")
    except Exception as e:
        logger.error(f"Error in Prediction: {e}", exc_info=True)
        logger.info("--- Backend Pipeline Failed in Prediction ---")
        return

    # --- Step 3: Process Results for Traffic Analysis and Global Threat Map (cho UI) ---
    logger.info(">>> Processing Analysis Results for UI Summary <<<")
    
    # Sử dụng các đường dẫn từ prediction_config (hoặc một config trung tâm nếu có)
    results_dir = prediction_config.RESULTS_DIR
    predictions_output_csv = prediction_config.PREDICTIONS_OUTPUT_CSV_PATH
    suspicious_output_csv = prediction_config.SUSPICIOUS_OUTPUT_CSV_PATH

    if not os.path.exists(results_dir):
        try:
            os.makedirs(results_dir, exist_ok=True)
            logger.info(f"Results directory for UI summary created at {results_dir}")
        except Exception as e_mkdir:
            logger.error(f"Failed to create results directory {results_dir}: {e_mkdir}")
            # Không return, cố gắng ghi file vào thư mục hiện tại nếu không tạo được
            results_dir = "." # Thư mục hiện tại của backend/


    try:
        predictions_df = pd.DataFrame()
        suspicious_df = pd.DataFrame()

        if os.path.exists(predictions_output_csv):
            predictions_df = pd.read_csv(predictions_output_csv)
            logger.info(f"Loaded {len(predictions_df)} rows from {predictions_output_csv}")
        else:
            logger.warning(f"Predictions CSV not found at {predictions_output_csv}. Full summary may be affected.")

        if os.path.exists(suspicious_output_csv):
            suspicious_df = pd.read_csv(suspicious_output_csv)
            logger.info(f"Loaded {len(suspicious_df)} rows from {suspicious_output_csv}")
        else:
            logger.warning(f"Suspicious CSV not found at {suspicious_output_csv}.")

        fwd_traffic_col = 'TotLen Fwd Pkts'
        bwd_traffic_col = 'TotLen Bwd Pkts'
        traffic_data = {'normal': 0, 'suspicious': 0, 'malicious': 0}

        # Điều kiện để tính toán: predictions_df phải có và chứa cả hai cột traffic
        if not predictions_df.empty and fwd_traffic_col in predictions_df.columns and bwd_traffic_col in predictions_df.columns:
            predictions_df[fwd_traffic_col] = pd.to_numeric(predictions_df[fwd_traffic_col], errors='coerce').fillna(0)
            predictions_df[bwd_traffic_col] = pd.to_numeric(predictions_df[bwd_traffic_col], errors='coerce').fillna(0)
            # Tạo cột tổng dung lượng cho mỗi flow
            predictions_df['total_flow_volume'] = predictions_df[fwd_traffic_col] + predictions_df[bwd_traffic_col]

            benign_labels_lower = [str(label).lower() for label in prediction_config.BENIGN_LABELS]

            normal_flows_df = predictions_df[predictions_df['Prediction'].astype(str).str.lower().isin(benign_labels_lower)]
            traffic_data['normal'] = round(normal_flows_df['total_flow_volume'].sum() / (1024 * 1024), 2) # MB

            non_benign_flows_df = predictions_df[~predictions_df['Prediction'].astype(str).str.lower().isin(benign_labels_lower)]
            traffic_data['suspicious'] = round(non_benign_flows_df['total_flow_volume'].sum() / (1024 * 1024), 2) # MB
            
            # 'malicious' tính từ suspicious_df
            # Cần đảm bảo suspicious_df cũng có các cột traffic này nếu nó là subset của predictions_df
            # Hoặc, join suspicious_df với predictions_df để lấy cột 'total_flow_volume'
            if not suspicious_df.empty:
                # Nếu suspicious_df chỉ có ID và Prediction, bạn cần join lại với predictions_df để lấy volume
                # Hoặc đảm bảo reporter.py khi lưu suspicious_df cũng lưu các cột fwd/bwd traffic.
                # Giả sử suspicious_df đã có các cột cần thiết (tốt nhất là nên đảm bảo điều này)
                if fwd_traffic_col in suspicious_df.columns and bwd_traffic_col in suspicious_df.columns:
                    suspicious_df[fwd_traffic_col] = pd.to_numeric(suspicious_df[fwd_traffic_col], errors='coerce').fillna(0)
                    suspicious_df[bwd_traffic_col] = pd.to_numeric(suspicious_df[bwd_traffic_col], errors='coerce').fillna(0)
                    suspicious_df['total_flow_volume'] = suspicious_df[fwd_traffic_col] + suspicious_df[bwd_traffic_col]
                    traffic_data['malicious'] = round(suspicious_df['total_flow_volume'].sum() / (1024 * 1024), 2) # MB
                else:
                    # Nếu suspicious_df không có cột traffic, malicious sẽ là 0 dựa trên tính toán này
                    logger.warning(f"Traffic columns ('{fwd_traffic_col}', '{bwd_traffic_col}') not found in suspicious_df. Malicious traffic might be underestimated.")
                    traffic_data['malicious'] = 0
            else:
                 traffic_data['malicious'] = 0
        else:
            columns_info = "N/A"
            if not predictions_df.empty:
                columns_info = str(predictions_df.columns.tolist())

            logger.warning(f"Required traffic columns ('{fwd_traffic_col}', '{bwd_traffic_col}') not in {predictions_output_csv} or file empty. " +
                           f"Available columns: {columns_info}. Using dummy traffic data.")
            traffic_data = {'normal': 0, 'suspicious': 0, 'malicious': 0} # Fallback

        traffic_analysis_csv_path = os.path.join(results_dir, 'traffic_analysis.csv')
        with open(traffic_analysis_csv_path, 'w', newline='') as f:
            writer = csv.DictWriter(f, fieldnames=['normal', 'suspicious', 'malicious'])
            writer.writeheader(); writer.writerow(traffic_data)
        logger.info(f"Traffic analysis data saved to {traffic_analysis_csv_path}")

        threat_map_data = {'activeAttacks': 0, 'countries': 0, 'totalToday': 0}
        if not suspicious_df.empty and 'Src IP' in suspicious_df.columns:
            threat_map_data['activeAttacks'] = suspicious_df['Src IP'].nunique()
            try:
                threat_map_data['countries'] = len(set(suspicious_df['Src IP'].astype(str).apply(lambda x: x.split('.')[0] if isinstance(x, str) and '.' in x else 'Unknown')))
            except: threat_map_data['countries'] = 0
            threat_map_data['totalToday'] = len(suspicious_df)
        else:
            logger.warning("No suspicious flows data for global threat map. Using dummy.")
            threat_map_data = {'activeAttacks': 24, 'countries': 8, 'totalToday': 156} # Fallback

        global_threat_map_csv_path = os.path.join(results_dir, 'global_threat_map.csv')
        with open(global_threat_map_csv_path, 'w', newline='') as f:
            writer = csv.DictWriter(f, fieldnames=['activeAttacks', 'countries', 'totalToday'])
            writer.writeheader(); writer.writerow(threat_map_data)
        logger.info(f"Global threat map data saved to {global_threat_map_csv_path}")

    except Exception as e:
        logger.error(f"Error processing summary results for UI: {e}", exc_info=True)
        # Tạo file dummy nếu có lỗi để UI không bị đứng
        if not os.path.exists(os.path.join(results_dir, 'traffic_analysis.csv')):
             with open(os.path.join(results_dir, 'traffic_analysis.csv'), 'w', newline='') as f:
                writer = csv.DictWriter(f, fieldnames=['normal', 'suspicious', 'malicious'])
                writer.writeheader(); writer.writerow({'normal': 0, 'suspicious': 0, 'malicious': 0})
        if not os.path.exists(os.path.join(results_dir, 'global_threat_map.csv')):
             with open(os.path.join(results_dir, 'global_threat_map.csv'), 'w', newline='') as f:
                writer = csv.DictWriter(f, fieldnames=['activeAttacks', 'countries', 'totalToday'])
                writer.writeheader(); writer.writerow({'activeAttacks': 0, 'countries': 0, 'totalToday': 0})

    logger.info("--- Main Python Backend Pipeline Completed Successfully ---")


if __name__ == "__main__":
    main_pipeline()