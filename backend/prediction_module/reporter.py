# prediction_module/reporter.py
import pandas as pd
import numpy as np
import logging
import os
# import requests # Not needed here if send_telegram_messege handles it
from . import config
# from dotenv import load_dotenv # Not needed here
from .send_telegram_messege import process_attack_detection
from .send_email_notification import notify_by_email_on_prediction_completion # <<< MODIFIED IMPORT

def analyze_and_save_results(df_original_with_preds, predictions, probabilities):
    """
    Analyzes prediction results, identifies suspicious flows, prints summaries,
    saves results to CSV files, and sends notifications.

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

    # Define display_cols for console/telegram and ensure they exist
    console_display_cols = ['Timestamp', 'Flow ID', 'Src IP', 'Src Port', 'Dst IP', 'Dst Port', 'Protocol', 'Prediction']
    if 'Prediction_Probability' in suspicious_flows.columns:
             console_display_cols.append('Prediction_Probability')
    
    # Filter display_cols to only those present in suspicious_flows
    # These columns will be used for console output and Telegram alerts
    # The email notification will receive the full suspicious_flows df and decide on columns itself
    cols_for_console_telegram_alert = [col for col in console_display_cols if col in suspicious_flows.columns]
    
    sample_for_console_and_telegram = pd.DataFrame() # Initialize as empty

    if num_suspicious > 0:
        logging.info("Examples of suspicious flows (first 10 for console):")
        
        if cols_for_console_telegram_alert:
            # For console, print up to 10
            print(suspicious_flows[cols_for_console_telegram_alert].head(10).to_string())
            # For Telegram, use a configured sample size or default
            telegram_sample_size = getattr(config, 'TELEGRAM_ALERT_SAMPLE_SIZE', 10)
            sample_for_console_and_telegram = suspicious_flows[cols_for_console_telegram_alert].head(telegram_sample_size)
            if not sample_for_console_and_telegram.empty:
                 process_attack_detection(sample_for_console_and_telegram)
        else:
            # Fallback if desired display columns are not found (less likely)
            logging.warning("Essential columns for formatted alert display not found. Printing generic suspicious flow data.")
            print(suspicious_flows.head(10).to_string()) # Print whatever is available
            # If specific columns are critical for process_attack_detection, it might fail or need adjustment
            # For now, try sending the head() of the raw suspicious_flows.
            telegram_sample_size = getattr(config, 'TELEGRAM_ALERT_SAMPLE_SIZE', 10)
            sample_for_console_and_telegram = suspicious_flows.head(telegram_sample_size)
            if not sample_for_console_and_telegram.empty:
                 process_attack_detection(sample_for_console_and_telegram)
    
    # --- Send Email Notification ---
    # The email function receives the full original DF with predictions, and the suspicious flows DF.
    # It will handle formatting and content based on whether suspicious_flows is empty.
    # The suspicious_flows DataFrame passed here should contain all its original columns,
    # as the email function might want to select different columns or show all of them in an attachment.
    notify_by_email_on_prediction_completion(df_original_with_preds, suspicious_flows)


    # --- Save Results ---
    try:
        logging.info(f"Saving all predictions to: {config.PREDICTIONS_OUTPUT_CSV_PATH}")
        os.makedirs(os.path.dirname(config.PREDICTIONS_OUTPUT_CSV_PATH), exist_ok=True)
        df_original_with_preds.to_csv(config.PREDICTIONS_OUTPUT_CSV_PATH, index=False, encoding='utf-8')
        logging.info("Successfully saved all predictions.")
    except Exception as e:
        logging.error(f"Error saving all predictions CSV: {e}", exc_info=True)

    if num_suspicious > 0:
        try:
            logging.info(f"Saving suspicious flows to: {config.SUSPICIOUS_OUTPUT_CSV_PATH}")
            os.makedirs(os.path.dirname(config.SUSPICIOUS_OUTPUT_CSV_PATH), exist_ok=True)
            suspicious_flows.to_csv(config.SUSPICIOUS_OUTPUT_CSV_PATH, index=False, encoding='utf-8')
            logging.info("Successfully saved suspicious flows.")
        except Exception as e:
            logging.error(f"Error saving suspicious flows CSV: {e}", exc_info=True)
    else:
        logging.info("No suspicious flows to save (related CSV not created or is empty).")