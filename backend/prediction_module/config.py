# prediction_module/config.py
import os
from pathlib import Path

# --- Model and Scaler Paths ---
# Use paths relative to the backend directory or absolute paths

current_file_path = Path(__file__).resolve()  # config.py
CONFIGS_DIR = current_file_path.parent        
BACKEND_DIR = CONFIGS_DIR.parent              
PROJECT_ROOT = BACKEND_DIR.parent             

CURRENT_FILE_PATH = Path(__file__).resolve()

PROJECT_ROOT = CURRENT_FILE_PATH.parent.parent.parent

MODEL_PATH = PROJECT_ROOT / 'model' / 'xgboost_model.pkl'
SCALER_PATH = PROJECT_ROOT / 'model' / 'scaler.pkl'

BACKEND_DIR = CURRENT_FILE_PATH.parent.parent # /path/to/your_project/backend

NETWORK_FLOWS_CSV_PATH = BACKEND_DIR / 'prediction_module' / 'network_flows.csv'

BACKEND_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
RESULTS_DIR = os.path.join(BACKEND_DIR, 'results') 

# --- Input/Output CSV Paths ---
# Input CSV is the output of the capture module
NETWORK_FLOWS_CSV_PATH = os.path.join(BACKEND_DIR, 'network_flows.csv') 

_input_filename = os.path.basename(NETWORK_FLOWS_CSV_PATH)

# Lưu file output vào thư mục RESULTS_DIR đã định nghĩa
PREDICTIONS_OUTPUT_CSV_PATH = os.path.join(RESULTS_DIR, _input_filename.replace('.csv', '_Predictions.csv'))
SUSPICIOUS_OUTPUT_CSV_PATH = os.path.join(RESULTS_DIR, 'Suspicious_' + _input_filename.replace('.csv', '_Predictions.csv'))

# --- Feature Engineering Settings (Optional) ---
# Enable/disable dynamic feature calculation if your model needs them
CALCULATE_DYNAMIC_FEATURES = False # Set to True if model uses time_since_last or rolling features
ROLLING_WINDOW_MINUTES = 2 # Used only if CALCULATE_DYNAMIC_FEATURES is True and model needs rolling features

# --- Prediction Settings ---
BENIGN_LABELS = ['Benign', 0, 'BENIGN'] # Case-insensitive check might be better later

# --- Logging Configuration ---
LOGGING_LEVEL = 'INFO' # e.g., DEBUG, INFO, WARNING, ERROR
LOGGING_FORMAT = '%(asctime)s - %(levelname)s - %(module)s - %(message)s'

# --- Expected Features ---
# Set to None to derive from scaler, or provide a list manually if scaler lacks feature names
# Example: EXPECTED_FEATURES = ['Flow Duration', 'Tot Fwd Pkts', ...]
EXPECTED_FEATURES = None

# Đảm bảo thư mục results tồn tại khi config được load
os.makedirs(RESULTS_DIR, exist_ok=True)
