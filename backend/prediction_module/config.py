# prediction_module/config.py
import os

# --- Model and Scaler Paths ---
# Use paths relative to the backend directory or absolute paths
MODEL_PATH = r'model/random_forest_model.pkl'
SCALER_PATH = r'model/dataset/working2/scaler.pkl'

# Get the path to the 'backend' directory (assuming config.py is in prediction_module)
BACKEND_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
RESULTS_DIR = os.path.join(BACKEND_DIR, 'results') # Define results directory

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
