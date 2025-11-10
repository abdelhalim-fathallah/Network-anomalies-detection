"""
src/detect_anomalies.py

Description:
-------------
Real-time anomaly detection module that loads the trained models
(Autoencoder & Isolation Forest) and uses them to identify
abnormal or suspicious network activity.

Pipeline:
----------
- Automatically loads the latest processed traffic CSV.
- Normalizes data using the saved scaler.
- Detects anomalies using Autoencoder reconstruction error + Isolation Forest score.
- Prints alerts for detected anomalies.

Author: Abdelhalim Fathallah
"""

import os
import pandas as pd
import numpy as np
import torch
import torch.nn as nn
from sklearn.ensemble import IsolationForest
import joblib
from colorama import Fore, Style, init

# Initialize colored output
init(autoreset=True)

# ===== Paths =====
MODEL_DIR = "models"
DATA_DIR = "data/processed"


# ===== Autoencoder Class =====
class Autoencoder(nn.Module):
    def __init__(self, input_dim):
        super(Autoencoder, self).__init__()
        self.encoder = nn.Sequential(
            nn.Linear(input_dim, 64),
            nn.ReLU(),
            nn.Linear(64, 16),
            nn.ReLU(),
        )
        self.decoder = nn.Sequential(
            nn.Linear(16, 64),
            nn.ReLU(),
            nn.Linear(64, input_dim),
        )

    def forward(self, x):
        return self.decoder(self.encoder(x))


# ===== Load Models =====
def load_models(input_dim):
    print(Fore.CYAN + "[+] Loading trained models...")

    autoencoder = Autoencoder(input_dim)
    ae_path = os.path.join(MODEL_DIR, "autoencoder.pth")
    autoencoder.load_state_dict(torch.load(ae_path))
    autoencoder.eval()

    iso_path = os.path.join(MODEL_DIR, "isolation_forest.pkl")
    iso_model = joblib.load(iso_path)

    scaler_path = os.path.join(MODEL_DIR, "scaler.pkl")
    scaler = joblib.load(scaler_path)

    print(Fore.GREEN + "[✓] Models loaded successfully.\n")
    return autoencoder, iso_model, scaler


# ===== Detect Anomalies =====
def detect_anomalies(df, autoencoder, iso_model, scaler, threshold=0.02):
    df_num = df.select_dtypes(include=[np.number])
    X_scaled = scaler.transform(df_num.values)

    # Autoencoder reconstruction error
    with torch.no_grad():
        inputs = torch.tensor(X_scaled, dtype=torch.float32)
        outputs = autoencoder(inputs)
        reconstruction_error = torch.mean((inputs - outputs) ** 2, dim=1).numpy()

    # Isolation Forest prediction
    iso_pred = iso_model.predict(X_scaled)  # -1 = anomaly, 1 = normal

    anomalies = []
    for i, (err, iso) in enumerate(zip(reconstruction_error, iso_pred)):
        if err > threshold or iso == -1:
            anomalies.append(i)

    print(Fore.YELLOW + f"[!] Detected {len(anomalies)} anomalies out of {len(df)} packets.")
    return anomalies


# ===== Main =====
def main():
    # Automatically detect latest CSV file
    files = [f for f in os.listdir(DATA_DIR) if f.endswith(".csv")]
    if not files:
        print(Fore.RED + "[x] No processed CSV files found in data/processed.")
        return

    latest_file = max(files, key=lambda f: os.path.getmtime(os.path.join(DATA_DIR, f)))
    test_file = os.path.join(DATA_DIR, latest_file)
    print(Fore.CYAN + f"[+] Using latest processed file: {test_file}\n")

    # Load and process
    df = pd.read_csv(test_file)
    input_dim = df.select_dtypes(include=[np.number]).shape[1]

    autoencoder, iso_model, scaler = load_models(input_dim)
    anomalies = detect_anomalies(df, autoencoder, iso_model, scaler, threshold=0.02)

    if anomalies:
        print(Fore.RED + Style.BRIGHT + "\n[⚠] Anomalous activity detected in the following rows:\n")
        print(df.iloc[anomalies])
    else:
        print(Fore.GREEN + "[✓] No anomalies detected. Network traffic appears normal.\n")


if __name__ == "__main__":
    main()
