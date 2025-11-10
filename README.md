# Network Anomalies Detection for Insider Attacks

## Overview
This is a **graduation project** by our team at **HIMIT**. The project focuses on detecting **network anomalies caused by insider attacks**. Insider attacks are malicious actions performed by users within an organization and are often difficult to detect using traditional security methods.

Our system uses **machine learning and statistical analysis** to monitor network traffic, extract key features, detect suspicious patterns, and alert administrators about potential insider threats.

---

## Objectives
- Detect anomalies in network traffic indicative of insider threats.  
- Provide a **scalable and automated solution** for organizational network monitoring.  
- Generate real-time alerts for suspicious activities to prevent potential data breaches.  

---

## Features
- Collect network traffic using Wireshark/Tcpdump.  
- Extract network features from PCAP files.  
- Train AI models for anomaly detection:  
  - **Autoencoder**: Detects deviations from normal traffic patterns.  
  - **Isolation Forest**: Identifies outliers in network behavior.  
- Detect anomalies in processed network data.  
- Send notifications and alerts for suspicious activities.  
- Integrate results with **ELK Stack / Kibana** dashboards for visualization.  

---

## Project Structure
```
network-anomaly-detection/
│
├── data/
│ ├── raw/ ← PCAP files from Wireshark/Tcpdump
│ ├── processed/ ← CSV files after feature extraction
│ └── datasets/ ← Training and testing datasets
│
├── models/
│ ├── autoencoder_model.pth
│ └── isolation_forest.pkl
│
├── src/
│ ├── sniffing.py ← Collect network traffic
│ ├── preprocess.py ← Extract features from PCAP
│ ├── train_model.py ← Train AI models
│ ├── detect_anomalies.py ← Detect suspicious activities
│ ├── alert_system.py ← Send notifications and alerts
│ └── dashboard_connector.py ← Connect results to ELK/Kibana
│
├── notebooks/
│ └── exploration.ipynb ← Initial data exploration and analysis
│
├── requirements.txt ← Project dependencies
├── README.md ← Project description
└── config.yaml ← Network and paths configuration
```

---

## How to Run

1. Clone the repository:
```
git clone https://github.com/your-repo/network-anomaly-detection.git
```
Install dependencies:
```
pip install -r requirements.txt
```
Preprocess the PCAP data:
```
python src/preprocess.py --input data/raw --output data/processed
```
Train the models:
```
python src/train_model.py
```
Detect anomalies:
```
python src/detect_anomalies.py --input data/processed
```
Send alerts (optional):
```
python src/alert_system.py
```
Connect to dashboard (optional):
```
python src/dashboard_connector.py
```

### Technologies Used
Python 3.10+
PyShark (PCAP analysis)
Pandas & NumPy (data processing)
Scikit-learn (Isolation Forest)
PyTorch (Autoencoder)
Matplotlib & Seaborn (visualization)
ELK Stack / Kibana (optional dashboard visualization)


## Team Members
```
Abdelhalim
sameh
Asmaa 
mohamed 
mohamed
```

### References
Insider threat detection literature
Machine learning for anomaly detection
PCAP analysis techniques

### Notes
Ensure Wireshark/Tshark is installed for PCAP processing.
The system is designed for educational purposes and graduation project demonstration.
Update config.yaml with proper network paths and settings before running scripts.
