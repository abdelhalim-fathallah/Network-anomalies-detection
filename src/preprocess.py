"""
src/preprocess.py

Extracts network traffic features from PCAP files and saves them as CSV.

Steps:
 - Read PCAPs from data/raw/
 - Extract basic per-packet features (timestamp, src, dst, protocol, length)
 - Compute per-session statistics (packet count, avg size, duration, inter-arrival times)
 - Save processed dataset to data/processed/

Usage:
  python preprocess.py --input ../data/raw/capture1.pcap --output ../data/processed/capture1.csv
"""

import os
import time
import argparse
import logging
from pathlib import Path
from typing import List, Dict

import pandas as pd
import pyshark

# Add Wireshark path if needed
DEFAULT_TSHARK_PATH = r"D:\wireshark"

# Logging setup
logging.basicConfig(
    level=logging.INFO,
    format="[%(asctime)s] %(levelname)s - %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
logger = logging.getLogger("preprocess")


def ensure_tshark_on_path():
    """Add Wireshark (tshark) to PATH if not already."""
    if DEFAULT_TSHARK_PATH not in os.environ.get("PATH", ""):
        os.environ["PATH"] += os.pathsep + DEFAULT_TSHARK_PATH
        logger.info("Added Wireshark to PATH: %s", DEFAULT_TSHARK_PATH)


def extract_features(pcap_path: str) -> pd.DataFrame:
    """
    Extracts per-packet features from a PCAP file using pyshark.
    Returns a DataFrame.
    """
    ensure_tshark_on_path()
    pcap_path = Path(pcap_path).resolve()
    if not pcap_path.exists():
        raise FileNotFoundError(f"PCAP file not found: {pcap_path}")

    logger.info("Processing PCAP: %s", pcap_path)

    packets_data: List[Dict] = []
    capture = pyshark.FileCapture(str(pcap_path), keep_packets=False)

    last_timestamps = {}

    for pkt in capture:
        try:
            # Basic fields
            timestamp = float(pkt.sniff_timestamp)
            src_ip = getattr(pkt.ip, "src", None)
            dst_ip = getattr(pkt.ip, "dst", None)
            length = int(pkt.length)
            protocol = str(pkt.highest_layer).lower() if hasattr(pkt, "highest_layer") else "unknown"


            # Compute inter-arrival time (per src_ip)
            inter_arrival = None
            if src_ip:
                if src_ip in last_timestamps:
                    inter_arrival = timestamp - last_timestamps[src_ip]
                last_timestamps[src_ip] = timestamp

            packets_data.append({
                "timestamp": timestamp,
                "src_ip": src_ip,
                "dst_ip": dst_ip,
                "protocol": protocol,
                "length": length,
                "inter_arrival": inter_arrival,
            })

        except AttributeError:
            continue
        except Exception as e:
            logger.warning("Skipping packet due to error: %s", e)
            continue

    capture.close()

    df = pd.DataFrame(packets_data)
    logger.info("Extracted %d packets from %s", len(df), pcap_path)
    return df


def aggregate_sessions(df: pd.DataFrame) -> pd.DataFrame:
    """
    Aggregates packets into sessions based on (src_ip, dst_ip, protocol).
    Returns a session-level DataFrame.
    """
    logger.info("Aggregating sessions...")

    # Drop rows missing key fields
    df = df.dropna(subset=["src_ip", "dst_ip", "protocol"])

    grouped = df.groupby(["src_ip", "dst_ip", "protocol"])

    sessions = grouped.agg(
        packet_count=("length", "count"),
        avg_packet_size=("length", "mean"),
        total_bytes=("length", "sum"),
        duration=("timestamp", lambda x: x.max() - x.min()),
        avg_interarrival=("inter_arrival", "mean"),
    ).reset_index()

    logger.info("Created %d sessions.", len(sessions))
    return sessions


def save_csv(df: pd.DataFrame, output_path: str):
    """Save dataframe as CSV."""
    output_path = Path(output_path).resolve()
    output_path.parent.mkdir(parents=True, exist_ok=True)
    df.to_csv(output_path, index=False)
    logger.info("Saved CSV: %s", output_path)

def main():
    parser = argparse.ArgumentParser(description="Extract features from PCAP and save as CSV.")
    parser.add_argument("--input", "-i", required=False, help="Input PCAP file path")
    parser.add_argument("--output", "-o", required=False, help="Output CSV file path")
    parser.add_argument("--sessions", action="store_true", help="Aggregate packets into sessions")
    args = parser.parse_args()

    # Default paths if not provided
    raw_dir = Path("data/raw").resolve()
    processed_dir = Path("data/processed").resolve()
    processed_dir.mkdir(parents=True, exist_ok=True)
    pcaps = sorted(raw_dir.glob("*.pcap"), key=os.path.getmtime)
    default_input = pcaps[-1] if pcaps else None
    if default_input is None:
        raise FileNotFoundError("No PCAP files found in data/raw/. Please run sniffing.py first.")
    timestamp = time.strftime("%Y-%m-%d_%H-%M-%S")
    default_output = processed_dir / f"{timestamp}.csv"


    input_path = Path(args.input).resolve() if args.input else default_input
    output_path = Path(args.output).resolve() if args.output else default_output

    start = time.time()
    df_packets = extract_features(input_path)
    if args.sessions:
        df_result = aggregate_sessions(df_packets)
    else:
        df_result = df_packets
    save_csv(df_result, output_path)
    logger.info("Processing finished in %.2f seconds", time.time() - start)

if __name__ == "__main__":
    main()
