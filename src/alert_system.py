"""
src/alert_system.py

Automatic alerting system for network anomalies.
-------------------------------------------------
- Monitors the 'data/processed' folder for new CSV files.
- Runs anomaly detection using detect_anomalies.py.
- Sends alerts to Elasticsearch (viewable via Kibana).

"""

import os
import time
import logging
from datetime import datetime
from pathlib import Path
import pandas as pd
import requests
from detect_anomalies import detect_anomalies, load_models

# ====== Configuration ======
PROCESSED_DIR = Path("data/processed")
ALERT_LOG = Path("data/alerts.log")
CHECK_INTERVAL = 10  # seconds between folder scans
ALERT_THRESHOLD = 0.05  # if >5% anomalies → trigger alert

# Elasticsearch settings
ELASTIC_URL = "http://localhost:9200"
INDEX_NAME = "network_alerts"
# ===========================

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format="[%(asctime)s] %(levelname)s - %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
logger = logging.getLogger("alert_system")


def send_alert(file_path: str, anomaly_rate: float) -> None:
    """
    Log and send an alert to Elasticsearch when suspicious traffic is detected.
    """
    alert_msg = (
        f"Suspicious activity detected in '{file_path}' "
        f"(Anomaly Rate = {anomaly_rate*100:.2f}%)"
    )

    # Log alert
    logger.warning(alert_msg)

    # Append to local log file
    ALERT_LOG.parent.mkdir(parents=True, exist_ok=True)
    with open(ALERT_LOG, "a", encoding="utf-8") as f:
        f.write(f"{datetime.now().strftime('%Y-%m-%d %H:%M:%S')} - {alert_msg}\n")

    # Prepare alert document for Elasticsearch
    alert_doc = {
        "timestamp": datetime.now().isoformat(),
        "file": str(file_path),
        "anomaly_rate": round(anomaly_rate * 100, 2),
        "alert_message": alert_msg,
        "status": "Critical" if anomaly_rate > 20 else "Warning",
    }

    try:
        response = requests.post(
            f"{ELASTIC_URL}/{INDEX_NAME}/_doc",
            json=alert_doc,
            headers={"Content-Type": "application/json"},
            timeout=5
        )
        if response.status_code in [200, 201]:
            logger.info(f"Alert indexed in Elasticsearch: {file_path}")
        else:
            logger.error(f"Failed to index alert: {response.text}")
    except Exception as e:
        logger.error(f"Error sending alert to Elasticsearch: {e}")


def monitor_processed_folder() -> None:
    """Continuously monitors the processed data folder and triggers detection."""
    logger.info(f"Monitoring folder: {PROCESSED_DIR}")
    seen_files = set()
    PROCESSED_DIR.mkdir(parents=True, exist_ok=True)

    # Load models once at the start
    sample_csv = next(PROCESSED_DIR.glob("*.csv"), None)
    if sample_csv:
        df_sample = pd.read_csv(sample_csv)
        input_dim = df_sample.select_dtypes(include="number").shape[1]
        autoencoder, iso_model, scaler = load_models(input_dim)
    else:
        logger.error("No sample CSV found to infer model input size.")
        return

    while True:
        try:
            for csv_file in PROCESSED_DIR.glob("*.csv"):
                if csv_file not in seen_files:
                    logger.info(f"New file detected: {csv_file}")
                    df = pd.read_csv(csv_file)
                    anomalies = detect_anomalies(df, autoencoder, iso_model, scaler)
                    anomaly_rate = len(anomalies) / len(df) if len(df) > 0 else 0

                    if anomaly_rate > ALERT_THRESHOLD:
                        send_alert(str(csv_file), anomaly_rate)
                    else:
                        logger.info(
                            f"No significant anomaly found ({anomaly_rate*100:.2f}%) in {csv_file}"
                        )

                    seen_files.add(csv_file)
            time.sleep(CHECK_INTERVAL)
        except KeyboardInterrupt:
            logger.info("Monitoring stopped by user.")
            break
        except Exception as e:
            logger.exception(f"Error during monitoring: {e}")
            time.sleep(5)


if __name__ == "__main__":
    monitor_processed_folder()
"""
src/alert_system.py

Automatic alerting system for network anomalies.
-------------------------------------------------
- Monitors the 'data/processed' folder for new CSV files.
- Runs anomaly detection using detect_anomalies.py.
- Sends alerts to Elasticsearch (viewable via Kibana).

Author: Abdelhalim Fathallah
"""

import os
import time
import logging
from datetime import datetime
from pathlib import Path
import pandas as pd
import requests
from detect_anomalies import detect_anomalies, load_models

# ====== Configuration ======
PROCESSED_DIR = Path("data/processed")
ALERT_LOG = Path("data/alerts.log")
CHECK_INTERVAL = 10  # seconds between folder scans
ALERT_THRESHOLD = 0.05  # if >5% anomalies → trigger alert

# Elasticsearch settings
ELASTIC_URL = "http://localhost:9200"
INDEX_NAME = "network_alerts"
# ===========================

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format="[%(asctime)s] %(levelname)s - %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
logger = logging.getLogger("alert_system")


def send_alert(file_path: str, anomaly_rate: float) -> None:
    """
    Log and send an alert to Elasticsearch when suspicious traffic is detected.
    """
    alert_msg = (
        f"Suspicious activity detected in '{file_path}' "
        f"(Anomaly Rate = {anomaly_rate*100:.2f}%)"
    )

    # Log alert
    logger.warning(alert_msg)

    # Append to local log file
    ALERT_LOG.parent.mkdir(parents=True, exist_ok=True)
    with open(ALERT_LOG, "a", encoding="utf-8") as f:
        f.write(f"{datetime.now().strftime('%Y-%m-%d %H:%M:%S')} - {alert_msg}\n")

    # Prepare alert document for Elasticsearch
    alert_doc = {
        "timestamp": datetime.now().isoformat(),
        "file": str(file_path),
        "anomaly_rate": round(anomaly_rate * 100, 2),
        "alert_message": alert_msg,
        "status": "Critical" if anomaly_rate > 20 else "Warning",
    }

    try:
        response = requests.post(
            f"{ELASTIC_URL}/{INDEX_NAME}/_doc",
            json=alert_doc,
            headers={"Content-Type": "application/json"},
            timeout=5
        )
        if response.status_code in [200, 201]:
            logger.info(f"Alert indexed in Elasticsearch: {file_path}")
        else:
            logger.error(f"Failed to index alert: {response.text}")
    except Exception as e:
        logger.error(f"Error sending alert to Elasticsearch: {e}")


def monitor_processed_folder() -> None:
    """Continuously monitors the processed data folder and triggers detection."""
    logger.info(f"Monitoring folder: {PROCESSED_DIR}")
    seen_files = set()
    PROCESSED_DIR.mkdir(parents=True, exist_ok=True)

    # Load models once at the start
    sample_csv = next(PROCESSED_DIR.glob("*.csv"), None)
    if sample_csv:
        df_sample = pd.read_csv(sample_csv)
        input_dim = df_sample.select_dtypes(include="number").shape[1]
        autoencoder, iso_model, scaler = load_models(input_dim)
    else:
        logger.error("No sample CSV found to infer model input size.")
        return

    while True:
        try:
            for csv_file in PROCESSED_DIR.glob("*.csv"):
                if csv_file not in seen_files:
                    logger.info(f"New file detected: {csv_file}")
                    df = pd.read_csv(csv_file)
                    anomalies = detect_anomalies(df, autoencoder, iso_model, scaler)
                    anomaly_rate = len(anomalies) / len(df) if len(df) > 0 else 0

                    if anomaly_rate > ALERT_THRESHOLD:
                        send_alert(str(csv_file), anomaly_rate)
                    else:
                        logger.info(
                            f"No significant anomaly found ({anomaly_rate*100:.2f}%) in {csv_file}"
                        )

                    seen_files.add(csv_file)
            time.sleep(CHECK_INTERVAL)
        except KeyboardInterrupt:
            logger.info("Monitoring stopped by user.")
            break
        except Exception as e:
            logger.exception(f"Error during monitoring: {e}")
            time.sleep(5)


if __name__ == "__main__":
    monitor_processed_folder()
