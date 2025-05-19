# prediction_module/preprocessor.py
import pandas as pd
import numpy as np
import logging
import re

def clean_column_names(df):
    """Cleans DataFrame column names: strips whitespace, replaces special chars with underscores."""
    original_columns = df.columns.tolist()
    df.columns = df.columns.str.strip()
    # Replace sequences of non-alphanumeric chars (excluding _) with a single underscore
    df.columns = df.columns.map(lambda x: re.sub(r'[^A-Za-z0-9_]+', '_', x))
    # Optional: Remove leading/trailing underscores that might result
    df.columns = df.columns.map(lambda x: x.strip('_'))
    # Optional: Handle potential duplicate names after cleaning (e.g., append count)
    if df.columns.duplicated().any():
        logging.warning(f"Duplicate column names found after cleaning: {df.columns[df.columns.duplicated()].tolist()}. Consider renaming.")
        # Basic handling: append suffix - could be improved
        df.columns = pd.io.parsers.base_parser.ParserBase({'names': df.columns})._maybe_dedup_names(df.columns)

    renamed_cols_map = dict(zip(original_columns, df.columns))
    logging.info("Cleaned column names.")
    # logging.debug(f"Column name mapping: {renamed_cols_map}") # Optional: Log the mapping
    return df, renamed_cols_map

def convert_timestamp_col(df, renamed_cols_map):
    """
    Converts the timestamp column to datetime objects.
    Tries multiple formats and falls back to inference.
    """
    # Try to find the timestamp column using original and cleaned names
    timestamp_col_original = 'Timestamp'
    timestamp_col = renamed_cols_map.get(timestamp_col_original, timestamp_col_original)

    if timestamp_col not in df.columns:
        possible_ts_cols = [col for col in df.columns if 'timestamp' in col.lower()]
        if possible_ts_cols:
            timestamp_col = possible_ts_cols[0]
            logging.warning(f"Default timestamp column '{renamed_cols_map.get(timestamp_col_original, timestamp_col_original)}' not found. Using inferred column: '{timestamp_col}'")
        else:
            logging.error("Timestamp column not found in DataFrame. Cannot proceed without timestamps for potential feature engineering.")
            return df, None # Return None for timestamp_col_name

    logging.info(f"Attempting to convert timestamp column: '{timestamp_col}'")
    if pd.api.types.is_datetime64_any_dtype(df[timestamp_col]):
        logging.info("Timestamp column already in datetime format.")
        return df, timestamp_col

    # Try specific formats first (adjust based on your capture output)
    formats_to_try = [
        '%Y-%m-%d %H:%M:%S',        # Format from original test.py
        '%d/%m/%Y %I:%M:%S %p',    # Common CICFlowMeter format
        '%Y-%m-%d %H:%M:%S.%f',   # Format with microseconds
        '%m/%d/%Y %H:%M',         # Another possible format
    ]

    original_dtype = df[timestamp_col].dtype
    converted = False
    for fmt in formats_to_try:
        try:
            df[timestamp_col] = pd.to_datetime(df[timestamp_col], format=fmt, errors='raise')
            logging.info(f"Converted timestamp using format: {fmt}")
            converted = True
            break
        except (ValueError, TypeError):
            logging.debug(f"Timestamp format '{fmt}' did not match.")
            # Reset column to original if conversion failed partially (unlikely with errors='raise')
            # df[timestamp_col] = df[timestamp_col].astype(original_dtype) # Careful with this

    if not converted:
        logging.warning("Specific timestamp formats failed. Attempting automatic inference (infer_datetime_format=True)...")
        try:
            # Ensure the column is string type before inferring if it's object type
            if df[timestamp_col].dtype == 'object':
                 df[timestamp_col] = df[timestamp_col].astype(str)

            df[timestamp_col] = pd.to_datetime(df[timestamp_col], infer_datetime_format=True, errors='coerce')
            if df[timestamp_col].isnull().any():
                logging.error(f"Timestamp conversion resulted in NaT values after inference. Check data in column '{timestamp_col}'.")
                # Consider logging problematic rows: df[df[timestamp_col].isnull()]
                return df, None # Indicate failure
            logging.info("Timestamp conversion successful using inference.")
            converted = True
        except Exception as e_infer:
            logging.error(f"Fatal error during timestamp inference for column '{timestamp_col}': {e_infer}", exc_info=True)
            return df, None # Indicate failure

    if not converted:
         logging.error(f"Could not convert timestamp column '{timestamp_col}' to datetime.")
         return df, None

    return df, timestamp_col # Return df and the name of the converted column

def handle_missing_values(df):
    """Handles NaN and Infinity values in numeric columns."""
    logging.info("Handling Infinity and NaN values...")
    numeric_cols = df.select_dtypes(include=np.number).columns.tolist()

    inf_handled_cols = []
    for col in numeric_cols:
        if np.isinf(df[col]).any():
            inf_count = np.isinf(df[col]).sum()
            logging.debug(f"  Replacing {inf_count} Inf values with NaN in column '{col}'.")
            df[col] = df[col].replace([np.inf, -np.inf], np.nan)
            inf_handled_cols.append(col)

    if inf_handled_cols:
         logging.info(f"Replaced Inf values in columns: {inf_handled_cols}")

    # Fill NaN values - Strategy: fill with 0 for now.
    # Consider more sophisticated strategies (mean, median, model-based) if appropriate.
    nan_counts = df[numeric_cols].isnull().sum()
    cols_with_nan = nan_counts[nan_counts > 0]
    if not cols_with_nan.empty:
        logging.warning(f"Found NaN values in numeric columns. Filling with 0: \n{cols_with_nan}")
        df[numeric_cols] = df[numeric_cols].fillna(0)
        logging.info("Filled NaN values in numeric columns with 0.")
    else:
        logging.info("No NaN values found in numeric columns after Inf handling.")

    return df

def ensure_numeric_features(df, feature_list):
    """Ensures all features expected by the model are numeric, converting if necessary."""
    logging.info("Ensuring required features are numeric...")
    converted_cols = []
    errors = 0
    for col in feature_list:
        if col in df.columns:
            if not pd.api.types.is_numeric_dtype(df[col]):
                logging.warning(f"  Feature '{col}' is not numeric (type: {df[col].dtype}). Attempting conversion.")
                try:
                    # Keep track of NaNs before conversion (if any)
                    nan_before = df[col].isnull().sum()
                    df[col] = pd.to_numeric(df[col], errors='coerce')
                    nan_after = df[col].isnull().sum()
                    if nan_after > nan_before:
                         logging.warning(f"    Conversion of '{col}' created {nan_after - nan_before} NaN values. Filling these with 0.")
                         df[col] = df[col].fillna(0) # Fill NaNs created by coercion
                    converted_cols.append(col)
                except Exception as e:
                    logging.error(f"    Failed to convert column '{col}' to numeric: {e}. Check data.")
                    errors += 1
        # else: # This case is handled later in align_features
        #     logging.warning(f"  Expected feature '{col}' not found in DataFrame during numeric check.")

    if converted_cols:
        logging.info(f"Successfully converted non-numeric feature columns: {converted_cols}")
    if errors > 0:
         logging.error(f"Encountered {errors} errors during numeric conversion. Prediction might fail.")
         return None # Indicate failure

    return df

def preprocess_data(df, expected_features):
    """Runs the standard preprocessing pipeline."""
    if df is None or df.empty:
        logging.warning("Preprocessing skipped: DataFrame is None or empty.")
        return df, None, None

    df_processed, renamed_cols_map = clean_column_names(df.copy()) # Work on a copy
    df_processed, timestamp_col_name = convert_timestamp_col(df_processed, renamed_cols_map)
    if timestamp_col_name is None:
         logging.error("Preprocessing failed due to timestamp conversion issues.")
         return None, None, None # Indicate failure

    df_processed = handle_missing_values(df_processed)
    df_processed = ensure_numeric_features(df_processed, expected_features)
    if df_processed is None:
         logging.error("Preprocessing failed due to numeric conversion issues.")
         return None, None, None

    logging.info("Core preprocessing steps completed.")
    return df_processed, timestamp_col_name, renamed_cols_map

