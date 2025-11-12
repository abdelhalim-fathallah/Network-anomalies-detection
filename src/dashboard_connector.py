"""
src/dashboard_connector.py

Integration with ELK Stack (Elasticsearch + Kibana)
---------------------------------------------------
- Sends anomaly alerts to Elasticsearch index: 'network_alerts'
- Kibana can visualize these alerts in real-time.

Make sure Elasticsearch is running at http://localhost:9200
"""

import logging
import requests
from datetime import datetime
from typing import Dict

# Elasticsearch configuration
ELASTIC_URL = "http://localhost:9200"
INDEX_NAME = "network_alerts"

logging.basicConfig(
    level=logging.INFO,
    format="[%(asctime)s] %(levelname)s - %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
logger = logging.getLogger("dashboard_connector")


def ensure_index_exists():
    """Create index in Elasticsearch if it doesn't exist"""
    url = f"{ELASTIC_URL}/{INDEX_NAME}"
    resp = requests.get(url)
    if resp.status_code == 404:
        logger.info("Index not found. Creating index: %s", INDEX_NAME)
        mapping = {
            "mappings": {
                "properties": {
                    "timestamp": {"type": "date"},
                    "file": {"type": "keyword"},
                    "anomaly_rate": {"type": "float"},
                    "message": {"type": "text"},
                }
            }
        }
        requests.put(url, json=mapping)
        logger.info("Index created successfully.")


def send_to_elasticsearch(alert_data: Dict):
    """
    Send alert JSON data to Elasticsearch index.
    """
    ensure_index_exists()
    url = f"{ELASTIC_URL}/{INDEX_NAME}/_doc"
    try:
        resp = requests.post(url, json=alert_data)
        if resp.status_code in (200, 201):
            logger.info("Alert indexed successfully to Kibana Dashboard.")
        else:
            logger.error(f"Failed to index alert: {resp.text}")
    except Exception as e:
        logger.error(f"Error sending alert to Elasticsearch: {e}")


def log_alert_to_dashboard(file_path: str, anomaly_rate: float):
    """
    Wrapper to format and send alert data.
    """
    alert = {
        "timestamp": datetime.utcnow().isoformat(),
        "file": file_path,
        "anomaly_rate": anomaly_rate,
        "message": f"Suspicious activity detected (Rate={anomaly_rate*100:.2f}%)",
    }
    send_to_elasticsearch(alert)


if __name__ == "__main__":
    # Example test alert
    log_alert_to_dashboard(
        file_path="data/processed/2025-11-10_19-38-51.csv",
        anomaly_rate=0.12
    )
