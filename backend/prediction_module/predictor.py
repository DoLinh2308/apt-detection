# prediction_module/predictor.py
import pandas as pd
import numpy as np
import logging

def align_features(df, expected_features):
    logging.info(f"Aligning DataFrame columns with {len(expected_features)} expected features...")
    current_columns = df.columns.tolist()
    expected_set = set(expected_features)
    current_set = set(current_columns)

    missing_features = list(expected_set - current_set)
    extra_features = list(current_set - expected_set)

    if missing_features:
        logging.warning(f"Missing {len(missing_features)} expected features: {missing_features}. Adding them with value 0.")
        for col in missing_features:
            df[col] = 0.0 

    if extra_features:
        logging.info(f"Found {len(extra_features)} extra columns not needed by the model: {extra_features[:10]}...") # Log first few

    try:
        if not expected_set.issubset(set(df.columns)):
             raise ValueError("Not all expected features are present in the DataFrame even after adding missing ones.")
        df_aligned = df[expected_features].astype(float) # Select and ensure float type
        logging.info(f"DataFrame aligned. Shape: {df_aligned.shape}")
        return df_aligned
    except KeyError as e:
        logging.error(f"KeyError during feature alignment: {e}. This shouldn't happen if missing columns were added correctly.")
        return None
    except ValueError as e:
         logging.error(f"ValueError during feature alignment (e.g., could not convert to float): {e}")
         # You might want to log which column caused the issue if possible
         return None
    except Exception as e:
        logging.error(f"Unexpected error during feature alignment: {e}", exc_info=True)
        return None


def make_predictions(df_aligned, model, scaler):
    if df_aligned is None or df_aligned.empty:
        logging.warning("Prediction skipped: Aligned DataFrame is None or empty.")
        return np.array([]), None

    logging.info(f"Scaling data ({df_aligned.shape[0]} rows, {df_aligned.shape[1]} features)...")
    try:
        if df_aligned.isnull().values.any() or np.isinf(df_aligned.values).any():
             logging.error("NaN or Inf values detected in data just before scaling. Check preprocessing steps.")
             return None, None 

        X_scaled = scaler.transform(df_aligned)
        logging.info("Data scaling successful.")
    except ValueError as e:
        logging.error(f"ValueError during scaling: {e}. Check scaler compatibility and data.")
        n_features_in_scaler = getattr(scaler, 'n_features_in_', 'N/A')
        logging.error(f"  Data shape: {df_aligned.shape}, Scaler expected features: {n_features_in_scaler}")
        return None, None 
    except Exception as e:
        logging.error(f"Unexpected error during scaling: {e}", exc_info=True)
        return None, None

    logging.info("Making predictions...")
    try:
        predictions = model.predict(X_scaled)
        probabilities = None
        if hasattr(model, "predict_proba"):
            probabilities = model.predict_proba(X_scaled)
            logging.info("Generated prediction probabilities.")
        else:
            logging.info("Model does not support predict_proba.")
        logging.info("Predictions completed.")
        return predictions, probabilities
    except Exception as e:
        logging.error(f"Error during model prediction: {e}", exc_info=True)
        return None, None # Indicate failure


# --- THÊM renamed_cols_map LÀM THAM SỐ ---
def align_features(df, expected_features, renamed_cols_map):
    """
    Aligns DataFrame columns with the list of features expected by the model,
    considering potential column name cleaning.
    Adds missing columns with 0, ensures correct order.
    """
    logging.info(f"Aligning DataFrame columns with {len(expected_features)} expected features...")

    # Tạo một map ngược: cleaned_name -> original_name (nếu cần tham chiếu ngược)
    # Hoặc tạo map: original_expected_name -> current_cleaned_name
    original_to_cleaned_map = {v: k for k, v in renamed_cols_map.items()} # Ngược lại map ban đầu

    # Tìm tên cột hiện tại (đã được làm sạch) tương ứng với tên cột mong đợi (gốc)
    current_feature_names_to_select = []
    missing_original_features = []
    available_cleaned_columns = set(df.columns.tolist())

    for expected_col_original in expected_features:
        # Tìm tên đã được làm sạch tương ứng trong map
        # Giả sử renamed_cols_map là {original: cleaned}
        cleaned_name = renamed_cols_map.get(expected_col_original)

        # Nếu không tìm thấy trong map (có thể tên gốc không có ký tự đặc biệt)
        # thì thử dùng chính tên gốc xem có trong cột hiện tại không
        if cleaned_name is None:
             # Trường hợp tên gốc và tên mong đợi giống nhau và không bị clean
             if expected_col_original in available_cleaned_columns:
                  cleaned_name = expected_col_original
             # Trường hợp tên mong đợi gốc KHÔNG CÓ trong map đổi tên VÀ cũng không có trong cột hiện tại
             # -> thực sự thiếu feature này từ nguồn
             elif expected_col_original not in available_cleaned_columns:
                 missing_original_features.append(expected_col_original)
                 continue # Bỏ qua feature này

        # Nếu tên đã clean được tìm thấy (từ map hoặc trực tiếp) VÀ nó có trong các cột hiện tại của df
        if cleaned_name is not None and cleaned_name in available_cleaned_columns:
            current_feature_names_to_select.append(cleaned_name)
        # Nếu tên đã clean được tìm thấy nhưng lại không có trong df (lạ?) hoặc tên gốc bị thiếu
        else:
             missing_original_features.append(expected_col_original)


    if missing_original_features:
        logging.warning(f"Missing {len(missing_original_features)} expected original features even after mapping: {missing_original_features}. Adding them with value 0.")
        for original_col in missing_original_features:
            # Cần quyết định đặt tên cột mới là gì, dùng tên gốc hay tên đã clean (nếu có)
            # An toàn nhất là dùng tên gốc mong đợi, vì bước sau sẽ chọn theo expected_features
            if original_col not in df.columns: # Chỉ thêm nếu chưa có
                 df[original_col] = 0.0

    # --- CHỌN CỘT THEO TÊN ĐÃ ĐƯỢC LÀM SẠCH tương ứng ---
    # df_selection = df[current_feature_names_to_select] # Chọn các cột hiện có theo thứ tự mong muốn

    # --- SAU KHI CHỌN, ĐỔI TÊN CỘT LẠI THÀNH TÊN GỐC MONG ĐỢI ---
    # Tạo một map từ tên đã clean (trong current_feature_names_to_select) về tên gốc mong đợi
    cleaned_to_original_for_selected = {
         renamed_cols_map.get(orig, orig) : orig
         for orig in expected_features
         if renamed_cols_map.get(orig, orig) in current_feature_names_to_select
    }

    try:
         # Chọn các cột theo tên đã được làm sạch tìm thấy
         df_selection = df[current_feature_names_to_select]

         # Đổi tên cột của df_selection thành tên gốc mà model/scaler mong đợi
         df_aligned = df_selection.rename(columns=cleaned_to_original_for_selected)

         # Bây giờ df_aligned có các cột với tên gốc, theo đúng thứ tự mong đợi.
         # Kiểm tra lại lần cuối xem tất cả cột mong đợi có trong df_aligned không
         final_missing = list(set(expected_features) - set(df_aligned.columns))
         if final_missing:
              logging.warning(f"After renaming, still missing expected features: {final_missing}. Adding with 0.")
              for col in final_missing:
                   df_aligned[col] = 0.0

         # Đảm bảo thứ tự cột cuối cùng khớp với expected_features
         df_aligned = df_aligned[expected_features].astype(float)

         logging.info(f"DataFrame aligned successfully. Shape: {df_aligned.shape}")
         return df_aligned

    except KeyError as e:
        logging.error(f"KeyError during feature alignment/renaming: {e}. Problematic key likely in current_feature_names_to_select or cleaned_to_original_for_selected.", exc_info=True)
        return None
    except ValueError as e:
         logging.error(f"ValueError during feature alignment (e.g., could not convert to float): {e}")
         return None
    except Exception as e:
        logging.error(f"Unexpected error during feature alignment: {e}", exc_info=True)
        return None


def make_predictions(df_aligned, model, scaler):
    """
    Scales the aligned data and makes predictions using the model.
    Args:
        df_aligned: DataFrame with features aligned and ordered correctly (TÊN CỘT LÀ TÊN GỐC).
        model: Loaded prediction model.
        scaler: Loaded scaler.
    Returns:
        Tuple: (predictions_array, probabilities_array or None)
    """
    if df_aligned is None or df_aligned.empty:
        logging.warning("Prediction skipped: Aligned DataFrame is None or empty.")
        return np.array([]), None # Return empty array and None

    logging.info(f"Scaling data ({df_aligned.shape[0]} rows, {df_aligned.shape[1]} features)...")
    try:
        # Dữ liệu đầu vào cho scaler phải có tên cột khớp với scaler.feature_names_in_
        if df_aligned.isnull().values.any() or np.isinf(df_aligned.values).any():
             logging.error("NaN or Inf values detected in data just before scaling. Check preprocessing steps.")
             return None, None # Indicate failure

        X_scaled = scaler.transform(df_aligned) # Scaler hoạt động với tên cột gốc
        logging.info("Data scaling successful.")
    except ValueError as e:
        logging.error(f"ValueError during scaling: {e}. Check scaler compatibility and data.")
        n_features_in_scaler = getattr(scaler, 'n_features_in_', 'N/A')
        scaler_features = getattr(scaler, 'feature_names_in_', [])
        logging.error(f"  Data shape: {df_aligned.shape}, Scaler expected features: {n_features_in_scaler}")
        logging.error(f"  Scaler features: {list(scaler_features)[:10]}...") # Log vài feature của scaler
        logging.error(f"  Data features: {df_aligned.columns.tolist()[:10]}...") # Log vài feature của data đưa vào scaler
        return None, None # Indicate failure
    except Exception as e:
        logging.error(f"Unexpected error during scaling: {e}", exc_info=True)
        return None, None # Indicate failure

    logging.info("Making predictions...")
    try:
        predictions = model.predict(X_scaled)
        probabilities = None
        if hasattr(model, "predict_proba"):
            probabilities = model.predict_proba(X_scaled)
            logging.info("Generated prediction probabilities.")
        else:
            logging.info("Model does not support predict_proba.")
        logging.info("Predictions completed.")
        return predictions, probabilities
    except Exception as e:
        logging.error(f"Error during model prediction: {e}", exc_info=True)
        return None, None