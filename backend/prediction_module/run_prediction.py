# prediction_module/run_prediction.py
import logging
import sys
import os

from . import config
from .loader import load_model_scaler, load_data
from .preprocessor import preprocess_data
from .feature_engineer import calculate_dynamic_features
from .predictor import align_features, make_predictions
from .reporter import analyze_and_save_results
from .send_telegram_messege import process_attack_detection

def run_prediction_pipeline():
    """Executes the full prediction pipeline."""
    logging.basicConfig(level=config.LOGGING_LEVEL, format=config.LOGGING_FORMAT)
    logging.info("--- Starting Prediction Module ---")

    # 1. Load Model, Scaler, and Expected Features
    model, scaler, expected_features = load_model_scaler()
    if model is None or scaler is None or expected_features is None:
        logging.error("Failed to load model/scaler or determine expected features. Exiting.")
        return False

    # 2. Load Data
    df = load_data()
    if df is None:
        logging.error(f"Failed to load data from '{config.NETWORK_FLOWS_CSV_PATH}'. Exiting.")
        return False
    if df.empty:
        logging.warning("Input data file is empty. Nothing to predict.")
        return True

    df_original_copy = df.copy() # Keep a copy for final reporting with original columns

    
    # 3. Preprocess Data -> nhận renamed_cols_map
    df_processed, timestamp_col, renamed_cols_map = preprocess_data(df, expected_features) # Lấy map ở đây
    if df_processed is None or renamed_cols_map is None: # Kiểm tra cả map
        logging.error("Data preprocessing failed. Exiting.")
        return False

    # 4. Feature Engineering (Optional)
    if config.CALCULATE_DYNAMIC_FEATURES:
        # Truyền map vào feature engineer nếu nó cũng cần
        df_engineered = calculate_dynamic_features(df_processed, timestamp_col, renamed_cols_map)
        if df_engineered is None:
             logging.error("Feature engineering failed. Exiting.")
             return False
    else:
        df_engineered = df_processed

    # 5. Align Features -> truyền map vào đây
    df_aligned = align_features(df_engineered, expected_features, renamed_cols_map) # Truyền map
    if df_aligned is None:
        logging.error("Feature alignment failed. Exiting.")
        return False

    # 6. Make Predictions (df_aligned giờ đã có tên cột gốc)
    predictions, probabilities = make_predictions(df_aligned, model, scaler)
    if predictions is None:
        logging.error("Prediction failed. Exiting.")
        return False

    # 7. Analyze and Save Results
    if len(predictions) == len(df_original_copy):
         # Giả định df_original_copy vẫn giữ nguyên tên cột gốc từ lúc load_data
         df_original_copy['Prediction'] = predictions

         analyze_and_save_results(df_original_copy, predictions, probabilities)
         logging.info("--- Prediction Module Finished Successfully ---")
         return True
    else:
         logging.error(f"Prediction length ({len(predictions)}) does not match original data length ({len(df_original_copy)}). Cannot merge results.")
         return False


if __name__ == "__main__":
    run_prediction_pipeline()

