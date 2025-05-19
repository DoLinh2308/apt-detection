# capture_module/run_capture.py
import sys
import os

# Add backend directory to sys.path to allow imports from sibling modules if needed
# Or adjust based on how you run your scripts
# sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from .capture_manager import start_capture

if __name__ == "__main__":
    print("--- Running Network Capture Module ---")
    start_capture()
    print("--- Network Capture Module Finished ---")
