# prediction_module/loader.py
import pandas as pd
import joblib
import os
import logging
from . import config


def load_model_scaler():
    """Loads the trained model and scaler."""
    logging.info("Loading model and scaler...")
    if not os.path.exists(config.MODEL_PATH):
        logging.error(f"Model file not found at '{config.MODEL_PATH}'")
        return None, None, None
    if not os.path.exists(config.SCALER_PATH):
        logging.error(f"Scaler file not found at '{config.SCALER_PATH}'")
        return None, None, None

    try:
        model = joblib.load(config.MODEL_PATH)
        scaler = joblib.load(config.SCALER_PATH)
        logging.info(f"Successfully loaded model from: {config.MODEL_PATH}")
        logging.info(f"Successfully loaded scaler from: {config.SCALER_PATH}")
        expected_features = config.EXPECTED_FEATURES
        if expected_features is None: 
            if hasattr(scaler, 'feature_names_in_'):
                expected_features = list(scaler.feature_names_in_)
                logging.info(f"Derived {len(expected_features)} expected features from scaler.")
            elif hasattr(scaler, 'n_features_in_'):
                 logging.warning(f"Scaler has 'n_features_in_' ({scaler.n_features_in_}) but not 'feature_names_in_'. Cannot derive feature names.")
                 return None, None, None
            else:
                logging.error("Scaler object does not have 'feature_names_in_' or 'n_features_in_'. Cannot determine expected features.")
                logging.error("Please define EXPECTED_FEATURES manually in prediction_module/config.py")
                return None, None, None
        else:
             logging.info(f"Using manually defined EXPECTED_FEATURES list from config ({len(expected_features)} features).")
        return model, scaler, expected_features

    except FileNotFoundError: 
        logging.error(f"FileNotFoundError during loading. Check paths: '{config.MODEL_PATH}', '{config.SCALER_PATH}'")
        return None, None, None
    except Exception as e:
        logging.error(f"Error loading model/scaler: {e}", exc_info=True)
        return None, None, None

def load_data():
    """Loads the network flow data from the CSV file."""
    logging.info(f"Loading network flow data from: {config.NETWORK_FLOWS_CSV_PATH}")
    if not os.path.exists(config.NETWORK_FLOWS_CSV_PATH):
        logging.error(f"Input CSV file not found: '{config.NETWORK_FLOWS_CSV_PATH}'")
        return None

    try:
        df = pd.read_csv(config.NETWORK_FLOWS_CSV_PATH)
        logging.info(f"Successfully loaded {len(df)} rows from CSV.")
        if df.empty:
            logging.warning("Loaded CSV file is empty.")
        return df
    except FileNotFoundError: # Redundant check, but safe
        logging.error(f"FileNotFoundError loading CSV: '{config.NETWORK_FLOWS_CSV_PATH}'")
        return None
    except pd.errors.EmptyDataError:
        logging.warning(f"Input CSV file is empty: '{config.NETWORK_FLOWS_CSV_PATH}'")
        return pd.DataFrame() # Return empty DataFrame
    except Exception as e:
        logging.error(f"Error reading CSV file '{config.NETWORK_FLOWS_CSV_PATH}': {e}", exc_info=True)
        return None
