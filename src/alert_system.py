"""
src/alert_system.py

Automatic alerting system for network anomalies.
- Monitors processed data folder
- Runs anomaly detection
- Sends alerts if suspicious activity is found
"""

import os
import time
import logging
import pandas as pd
import torch
from detect_anomalies import Autoencoder, load_models, detect_anomalies

# ===== Settings =====
ALERT_THRESHOLD = 0.05  # لو أكتر من 5% من الترافيك شاذ → ندي تنبيه
PROCESSED_DIR = "data/processed"
ALERT_LOG = "data/alerts.log"
MODEL_DIR = "models"

# ===== Logger =====
logging.basicConfig(level=logging.INFO, format="[%(asctime)s] %(levelname)s - %(message)s")
logger = logging.getLogger("alert_system")


def send_alert(file_path, anomaly_rate):
    """Send or log alert"""
    msg = f"[ALERT] 🚨 Suspicious activity detected in {file_path} (Anomaly Rate = {anomaly_rate*100:.2f}%)"
    logger.warning(msg)
    with open(ALERT_LOG, "a") as f:
        f.write(msg + "\n")


def analyze_file(file_path, autoencoder, iso_model, scaler):
    """Run anomaly detection on a single file"""
    logger.info(f"Analyzing file: {file_path}")
    df = pd.read_csv(file_path)
    df_num = df.select_dtypes(include="number")

    # Detect anomalies
    anomalies = detect_anomalies(df, autoencoder, iso_model, scaler, threshold=0.02)
    anomaly_rate = len(anomalies) / len(df) if len(df) > 0 else 0
    logger.info(f"Anomaly rate: {anomaly_rate*100:.2f}%")
    return anomaly_rate


def monitor_folder():
    """Watch processed folder and trigger detection"""
    logger.info(f"Monitoring folder: {PROCESSED_DIR}")

    # Load models once at start
    example_file = next((f for f in os.listdir(PROCESSED_DIR) if f.endswith(".csv")), None)
    if not example_file:
        logger.error("No processed CSV files found to infer input dimension.")
        return

    example_df = pd.read_csv(os.path.join(PROCESSED_DIR, example_file))
    input_dim = example_df.select_dtypes(include="number").shape[1]
    autoencoder, iso_model, scaler = load_models(input_dim)

    seen_files = set()
    while True:
        for fname in os.listdir(PROCESSED_DIR):
            if fname.endswith(".csv"):
                fpath = os.path.join(PROCESSED_DIR, fname)
                if fpath not in seen_files:
                    logger.info(f"New file detected: {fpath}")
                    anomaly_rate = analyze_file(fpath, autoencoder, iso_model, scaler)
                    if anomaly_rate > ALERT_THRESHOLD:
                        send_alert(fpath, anomaly_rate)
                    seen_files.add(fpath)
        time.sleep(10)


if __name__ == "__main__":
    monitor_folder()
