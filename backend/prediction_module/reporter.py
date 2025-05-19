# prediction_module/reporter.py
import pandas as pd
import numpy as np
import logging
import os
import requests
from . import config
from dotenv import load_dotenv
from .send_telegram_messege import process_attack_detection
# import config
def analyze_and_save_results(df_original_with_preds, predictions, probabilities):
    """
    Analyzes prediction results, identifies suspicious flows, prints summaries,
    and saves results to CSV files.

    Args:
        df_original_with_preds: Original DataFrame with 'Prediction' column added.
        predictions: Numpy array of predictions. (Used for checks, main data in df)
        probabilities: Numpy array of probabilities (or None).
    """
    if df_original_with_preds is None or df_original_with_preds.empty:
        logging.warning("Result analysis skipped: Input DataFrame is None or empty.")
        return

    logging.info("\n--- Analyzing Prediction Results ---")

    # Add probabilities if available
    if probabilities is not None and len(probabilities) == len(df_original_with_preds):
         try:
            # Assuming binary or multi-class, get probability of the predicted class
            df_original_with_preds['Prediction_Probability'] = np.max(probabilities, axis=1)
         except Exception as e:
              logging.warning(f"Could not add prediction probabilities: {e}")

    # --- Summary ---
    prediction_counts = df_original_with_preds['Prediction'].value_counts()
    logging.info("Prediction Counts:")
    print(prediction_counts) # Print to console for visibility

    # --- Identify Suspicious Flows ---
    # Use lower case for comparison to make it case-insensitive
    benign_labels_lower = [str(label).lower() for label in config.BENIGN_LABELS]
    df_original_with_preds['Prediction_Lower'] = df_original_with_preds['Prediction'].astype(str).str.lower()

    suspicious_condition = ~df_original_with_preds['Prediction_Lower'].isin(benign_labels_lower)
    suspicious_flows = df_original_with_preds[suspicious_condition].copy() # Create a copy

    # Drop the temporary lower case column
    df_original_with_preds.drop(columns=['Prediction_Lower'], inplace=True)
    if 'Prediction_Lower' in suspicious_flows.columns:
        suspicious_flows.drop(columns=['Prediction_Lower'], inplace=True)


    num_suspicious = len(suspicious_flows)
    num_total = len(df_original_with_preds)
    logging.info(f"\nIdentified {num_suspicious} suspicious flows out of {num_total} total flows.")

    if num_suspicious > 0:
        logging.info("Examples of suspicious flows (first 10):")
        # Select relevant columns for display (use original names if possible, fallback to cleaned)
        # This requires the renamed_cols_map, which we don't have here.
        # We'll just display key columns assuming common names exist.
        display_cols = ['Timestamp', 'Flow ID', 'Src IP', 'Src Port', 'Dst IP', 'Dst Port', 'Protocol', 'Prediction']
        if 'Prediction_Probability' in suspicious_flows.columns:
             display_cols.append('Prediction_Probability')
        # Filter display_cols to only those present in the dataframe
        display_cols_existing = [col for col in display_cols if col in suspicious_flows.columns]
        # Print to console
        print(suspicious_flows[display_cols_existing].head(10).to_string())
        process_attack_detection(suspicious_flows[display_cols_existing].head(10))


    # --- Save Results ---
    try:
        logging.info(f"Saving all predictions to: {config.PREDICTIONS_OUTPUT_CSV_PATH}")
        # Ensure directory exists
        os.makedirs(os.path.dirname(config.PREDICTIONS_OUTPUT_CSV_PATH), exist_ok=True)
        df_original_with_preds.to_csv(config.PREDICTIONS_OUTPUT_CSV_PATH, index=False, encoding='utf-8')
        logging.info("Successfully saved all predictions.")
    except Exception as e:
        logging.error(f"Error saving all predictions CSV: {e}", exc_info=True)

    if num_suspicious > 0:
        try:
            logging.info(f"Saving suspicious flows to: {config.SUSPICIOUS_OUTPUT_CSV_PATH}")
            # Ensure directory exists
            os.makedirs(os.path.dirname(config.SUSPICIOUS_OUTPUT_CSV_PATH), exist_ok=True)
            suspicious_flows.to_csv(config.SUSPICIOUS_OUTPUT_CSV_PATH, index=False, encoding='utf-8')
            logging.info("Successfully saved suspicious flows.")
        except Exception as e:
            logging.error(f"Error saving suspicious flows CSV: {e}", exc_info=True)
    else:
        logging.info("No suspicious flows to save.")
        

# def process_attack_detection():
#     """Xử lý dữ liệu tấn công và gửi thông báo Telegram."""
#     bot_token = "7645973969:AAFHTo3C-95Ghs5MOQVSGwfEDcTkXn_2iZQ"
#     user_chat_id = "6647932489"

#     message = f"⚠️ CẢNH BÁO TẤN CÔNG ⚠️\n\n"
#     message += "\nVui lòng kiểm tra hệ thống ngay lập tức!"

#     send_telegram_message(bot_token, user_chat_id, message)
# def process_attack_detection(attack_data):
#     """Xử lý dữ liệu tấn công và gửi thông báo Telegram."""
#     bot_token = "7645973969:AAFHTo3C-95Ghs5MOQVSGwfEDcTkXn_2iZQ"
#     user_chat_id = "6647932489"

#     message = f"⚠️ CẢNH BÁO TẤN CÔNG ⚠️\n\n"
#     message += f"Thời gian: {attack_data['timestamp']}\n"
#     message += f"Loại tấn công: {attack_data['attack_type']}\n"
#     message += f"Nguồn: {attack_data.get('source', 'Không xác định')}\n"
#     message += f"Mức độ: {attack_data['severity']}\n"
#     message += "\nVui lòng kiểm tra hệ thống ngay lập tức!"
#     send_telegram_message(bot_token, user_chat_id, message)

# def send_telegram_message(bot_token, chat_id, message):
#     """Gửi tin nhắn đến người dùng Telegram."""
#     api_url = f"https://api.telegram.org/bot{'7645973969:AAFHTo3C-95Ghs5MOQVSGwfEDcTkXn_2iZQ'}/sendMessage"
#     params = {
#         'chat_id': chat_id,
#         'text': message
#     }
#     try:
#         response = requests.post(api_url, params=params)
#         response.raise_for_status()  # Báo lỗi nếu request không thành công
#         print("Tin nhắn Telegram đã được gửi thành công!")
#     except requests.exceptions.RequestException as e:
#         print(f"Lỗi khi gửi tin nhắn Telegram: {e}")