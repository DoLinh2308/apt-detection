# prediction_module/feature_engineer.py
import pandas as pd
import logging
from . import config # Import config to check flags/settings

def calculate_dynamic_features(df, timestamp_col, renamed_cols_map):
    """
    Calculates time-based or rolling window features if enabled in config.

    Args:
        df: Preprocessed DataFrame, sorted by timestamp.
        timestamp_col: Name of the datetime timestamp column.
        renamed_cols_map: Dictionary mapping original to cleaned column names.

    Returns:
        DataFrame with added dynamic features.
    """
    if not config.CALCULATE_DYNAMIC_FEATURES:
        logging.info("Skipping dynamic feature calculation (disabled in config).")
        return df

    if timestamp_col not in df.columns or not pd.api.types.is_datetime64_any_dtype(df[timestamp_col]):
         logging.error("Cannot calculate dynamic features: Valid timestamp column missing or not converted.")
         return df # Return original df, prediction might fail later if features are expected

    logging.info("Calculating dynamic features...")
    df = df.sort_values(by=timestamp_col).reset_index(drop=True)

    # --- Example 1: Time Since Last Flow from Source IP ---
    feature_time_since = 'time_since_last_flow_src_sec'
    src_ip_col_original = 'Src IP'
    src_ip_col = renamed_cols_map.get(src_ip_col_original, src_ip_col_original)

    if src_ip_col in df.columns:
        logging.info(f"  Calculating '{feature_time_since}' based on '{src_ip_col}'...")
        df[feature_time_since] = df.groupby(src_ip_col)[timestamp_col].diff().dt.total_seconds()
        # Fill NaN for the first occurrence of each IP, clip negative (shouldn't happen with diff)
        df[feature_time_since] = df[feature_time_since].fillna(0).clip(lower=0)
        logging.info(f"  Finished calculating '{feature_time_since}'.")
    else:
        logging.warning(f"  Cannot calculate '{feature_time_since}': Source IP column '{src_ip_col}' not found.")
        # If this feature is critical for the model, you might need to add a dummy column later
        # or handle its absence in the align_features step. For now, we just skip calculation.

    # --- Example 2: Rolling Window Features (e.g., count, sum over X minutes) ---
    # Check if any rolling features are expected (you might need a more robust check based on model needs)
    needs_rolling = any('roll' in feature for feature in config.EXPECTED_FEATURES or [])

    if needs_rolling and src_ip_col in df.columns:
        window_str = f"{config.ROLLING_WINDOW_MINUTES}min"
        logging.info(f"  Calculating rolling window features (window: {window_str}) based on '{src_ip_col}'...")
        # Set timestamp as index for rolling operations
        df_indexed = df.set_index(timestamp_col)
        grouped_src_indexed = df_indexed.groupby(src_ip_col)

        # Rolling Count Example
        feature_roll_count = f'flow_count_roll{config.ROLLING_WINDOW_MINUTES}m_src'
        # Check if model actually needs this specific feature
        # if feature_roll_count in (config.EXPECTED_FEATURES or []): # Check against expected list
        logging.info(f"    Calculating rolling count: {feature_roll_count}")
        # Use a reliable column for counting (like the group key itself or index)
        rolling_count_result = grouped_src_indexed[src_ip_col].rolling(window=window_str, closed='left').count()
        rolling_count_result = rolling_count_result.reset_index(level=0, drop=True) # Drop the src_ip level index
        df_indexed[feature_roll_count] = rolling_count_result.fillna(0) # Fill NaNs at the start of windows

        # Rolling Sum Example (e.g., sum of 'Total Fwd Packets')
        feature_to_sum_original = 'Total Fwd Packets' # Check original name
        feature_to_sum = renamed_cols_map.get(feature_to_sum_original, feature_to_sum_original)
        feature_roll_sum = f'sum_fwd_pkts_roll{config.ROLLING_WINDOW_MINUTES}m_src'

        if feature_to_sum in df_indexed.columns:
            # if feature_roll_sum in (config.EXPECTED_FEATURES or []): # Check if needed
            logging.info(f"    Calculating rolling sum: {feature_roll_sum} from '{feature_to_sum}'")
            rolling_sum_result = grouped_src_indexed[feature_to_sum].rolling(window=window_str, closed='left').sum()
            rolling_sum_result = rolling_sum_result.reset_index(level=0, drop=True)
            df_indexed[feature_roll_sum] = rolling_sum_result.fillna(0)
        else:
            logging.warning(f"    Cannot calculate rolling sum '{feature_roll_sum}': Column '{feature_to_sum}' not found.")

        # Add more rolling calculations (mean, std, nunique) here if needed...

        # Reset index to bring timestamp back as a column
        df = df_indexed.reset_index()
        logging.info("  Finished calculating rolling window features.")

    elif needs_rolling and src_ip_col not in df.columns:
         logging.warning(f"  Cannot calculate rolling features: Source IP column '{src_ip_col}' not found.")

    logging.info("Dynamic feature calculation finished.")
    return df
