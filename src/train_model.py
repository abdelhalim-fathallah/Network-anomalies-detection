"""
src/train_model.py

Description:
-------------
This script trains two AI-based models for detecting network anomalies:

1. Autoencoder (PyTorch): Learns to reconstruct normal network traffic, and high reconstruction error indicates anomalies.
2. IsolationForest (Scikit-learn): Detects outliers based on data distribution.

Pipeline Steps:
---------------
- Reads CSV files from `data/processed/`
- Performs feature normalization
- Trains Autoencoder & IsolationForest models
- Saves trained models to `models/`

Author: Abdelhalim Fathallah
"""

import os
import pandas as pd
import numpy as np
import torch
import torch.nn as nn
from torch.utils.data import DataLoader, TensorDataset
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler
import joblib

# ===== Paths =====
PROCESSED_DIR = "data/processed"
MODEL_DIR = "models"
os.makedirs(MODEL_DIR, exist_ok=True)

# ===== Autoencoder Model =====
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
        encoded = self.encoder(x)
        decoded = self.decoder(encoded)
        return decoded


# ===== Train Autoencoder =====
def train_autoencoder(data, epochs=20, batch_size=64, lr=0.001):
    input_dim = data.shape[1]
    model = Autoencoder(input_dim)
    criterion = nn.MSELoss()
    optimizer = torch.optim.Adam(model.parameters(), lr=lr)

    dataset = TensorDataset(torch.tensor(data, dtype=torch.float32))
    loader = DataLoader(dataset, batch_size=batch_size, shuffle=True)

    print("[+] Training Autoencoder...")
    for epoch in range(epochs):
        total_loss = 0
        for batch in loader:
            batch_data = batch[0]
            output = model(batch_data)
            loss = criterion(output, batch_data)
            optimizer.zero_grad()
            loss.backward()
            optimizer.step()
            total_loss += loss.item()
        print(f"Epoch [{epoch+1}/{epochs}] - Loss: {total_loss/len(loader):.6f}")

    torch.save(model.state_dict(), os.path.join(MODEL_DIR, "autoencoder.pth"))
    print("[✓] Autoencoder model saved.")
    return model


# ===== Train Isolation Forest =====
def train_isolation_forest(data):
    print("[+] Training Isolation Forest...")
    iso = IsolationForest(contamination=0.05, random_state=42)
    iso.fit(data)
    joblib.dump(iso, os.path.join(MODEL_DIR, "isolation_forest.pkl"))
    print("[✓] Isolation Forest model saved.")
    return iso


# ===== Main =====
def main():
    print("[+] Loading preprocessed data...")

    # Get the latest CSV file from data/processed/
    csv_files = sorted(
        [os.path.join(PROCESSED_DIR, f) for f in os.listdir(PROCESSED_DIR) if f.endswith(".csv")],
        key=os.path.getmtime
    )

    if not csv_files:
        raise FileNotFoundError("No processed CSV files found in data/processed/. Please run preprocess.py first.")
    latest_csv = csv_files[-1]
    print(f"[+] Using latest processed file: {latest_csv}")
    df = pd.read_csv(latest_csv)
        # Remove non-numeric columns if any
    df = df.select_dtypes(include=[np.number])
    # Normalize features
    scaler = StandardScaler()
    X_scaled = scaler.fit_transform(df.values)
    X_scaled = np.nan_to_num(X_scaled, nan=0.0, posinf=0.0, neginf=0.0)

    joblib.dump(scaler, os.path.join(MODEL_DIR, "scaler.pkl"))

    joblib.dump(scaler, os.path.join(MODEL_DIR, "scaler.pkl"))

    # Train models
    autoencoder = train_autoencoder(X_scaled)
    iso = train_isolation_forest(X_scaled)

    print("[✓] Training complete. Models saved in 'models/' directory.")


if __name__ == "__main__":
    main()
