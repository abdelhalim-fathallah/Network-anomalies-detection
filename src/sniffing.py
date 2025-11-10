"""
src/sniffing.py

Network traffic capture utilities using pyshark (tshark).
Features:
 - Ensure tshark (Wireshark) directory is available in PATH (Windows example).
 - Live capture for a specified duration and save to a pcap file.
 - Real-time anomaly detection (optional, via --realtime).
 - Read packets from an existing pcap file (generator).
 - Simple command line interface for quick tests.

Usage examples:
  python sniffing.py --live --interface "Ethernet" --duration 30 --out "../data/raw/capture1.pcap"
  python sniffing.py --read "../data/raw/capture1.pcap"
  python sniffing.py --live --interface "Wi-Fi" --duration 30 --realtime

Notes:
 - Requires pyshark and tshark installed.
 - If tshark is installed in a non-standard location (e.g. D:/wireshark/), it will be appended to PATH automatically.
"""

import os
import sys
import time
import logging
from pathlib import Path
from typing import Generator, Optional
import datetime
import pyshark
import pandas as pd

# Optional imports for real-time detection
try:
    from preprocess import extract_features_from_pcap
    from detect_anomaly import detect_anomalies, load_models
except ImportError:
    extract_features_from_pcap = None
    detect_anomalies = None
    load_models = None


# ------- Configuration: modify if needed -------
DEFAULT_TSHARK_PATH = r"D:\wireshark\tshark.exe"
# ----------------------------------------------

logging.basicConfig(
    level=logging.INFO,
    format="[%(asctime)s] %(levelname)s - %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
logger = logging.getLogger("sniffing")


def ensure_tshark_on_path(tshark_path: Optional[str] = None) -> None:
    path_to_add = tshark_path or DEFAULT_TSHARK_PATH
    if not path_to_add:
        return

    path_to_add = str(Path(path_to_add).resolve())
    if path_to_add not in os.environ.get("PATH", ""):
        os.environ["PATH"] += os.pathsep + path_to_add
        logger.info("Added to PATH: %s", path_to_add)
    else:
        logger.info("tshark path already in PATH: %s", path_to_add)


def start_live_capture(
    interface: str,
    output_path: str,
    capture_filter: Optional[str] = None,
    duration: Optional[int] = None,
    packet_count: Optional[int] = None,
    realtime: bool = False,
) -> str:
    """
    Start a live capture and optionally perform real-time anomaly detection.
    """
    ensure_tshark_on_path()
    out = Path(output_path).expanduser().resolve()
    out.parent.mkdir(parents=True, exist_ok=True)

    logger.info("Starting live capture: interface=%s, out=%s", interface, out)
    if realtime:
        logger.info("[REAL-TIME MODE ENABLED] Packets will be analyzed on the fly.")

    try:
        capture = pyshark.LiveCapture(interface=interface, output_file=str(out), bpf_filter=capture_filter)
    except Exception as e:
        logger.exception("Failed to create LiveCapture: %s", e)
        raise

    # Initialize detection models once
    if realtime and load_models and extract_features_from_pcap:
        model_loaded = False
        autoencoder, iso_model, scaler, input_dim = None, None, None, None

    batch_packets = []
    start_time = time.time()
    try:
        for pkt in capture.sniff_continuously():
            batch_packets.append(pkt)
            if len(batch_packets) >= 20:  # analyze every 20 packets
                if realtime and extract_features_from_pcap and detect_anomalies:
                    df = extract_features_from_pcap(batch_packets, live_mode=True)
                    if not model_loaded:
                        input_dim = df.select_dtypes(include="number").shape[1]
                        autoencoder, iso_model, scaler = load_models(input_dim)
                        model_loaded = True

                    anomalies = detect_anomalies(df, autoencoder, iso_model, scaler, threshold=0.02)
                    if anomalies:
                        logger.warning("[!] %d anomalies detected in current batch!", len(anomalies))
                    else:
                        logger.info("[✓] Batch clean (no anomalies).")

                batch_packets.clear()

            if duration and (time.time() - start_time) >= duration:
                logger.info("Reached capture duration limit (%ds).", duration)
                break

    except KeyboardInterrupt:
        logger.info("Capture interrupted by user.")
    except Exception as e:
        logger.exception("Error during live capture: %s", e)
    finally:
        try:
            capture.close()
        except Exception:
            pass

    elapsed = time.time() - start_time
    logger.info("Capture finished, saved to %s (%.2f sec)", out, elapsed)
    return str(out)


def read_pcap(file_path: str) -> Generator[pyshark.packet.packet.Packet, None, None]:
    ensure_tshark_on_path()
    file_path = str(Path(file_path).expanduser().resolve())
    if not Path(file_path).exists():
        raise FileNotFoundError(f"PCAP file not found: {file_path}")

    logger.info("Opening pcap file: %s", file_path)
    try:
        capture = pyshark.FileCapture(file_path, keep_packets=False)
        for pkt in capture:
            yield pkt
    except Exception as e:
        logger.exception("Failed to read pcap: %s", e)
        raise
    finally:
        try:
            capture.close()
        except Exception:
            pass


def count_packets_in_pcap(file_path: str) -> int:
    cnt = 0
    for _ in read_pcap(file_path):
        cnt += 1
    logger.info("Packet count in %s: %d", file_path, cnt)
    return cnt


# -------------------- CLI --------------------
def _print_help_and_exit():
    print(__doc__)
    print("CLI usage examples:")
    print('  python sniffing.py --live --interface "Ethernet" --duration 30 --out "../data/raw/capture1.pcap"')
    print('  python sniffing.py --read "../data/raw/capture1.pcap"')
    print('  python sniffing.py --live --interface "Wi-Fi" --duration 30 --realtime')
    sys.exit(1)


def _cli():
    import argparse

    parser = argparse.ArgumentParser(description="sniffing.py - live capture and pcap reader utilities")
    group = parser.add_mutually_exclusive_group(required=False)

    group.add_argument("--live", action="store_true", help="Start live capture")
    group.add_argument("--read", metavar="PCAP", help="Read a pcap file and print basic info")

    parser.add_argument("--interface", "-i", type=str, help="Interface name for live capture (e.g., Ethernet)")
    parser.add_argument("--out", "-o", type=str, help="Output pcap path for live capture")
    parser.add_argument("--duration", "-t", type=int, help="Duration in seconds for live capture")
    parser.add_argument("--count", "-c", type=int, help="Stop after this many packets")
    parser.add_argument("--filter", type=str, help="BPF capture filter (e.g., 'tcp and port 80')")
    parser.add_argument("--realtime", action="store_true", help="Enable real-time anomaly detection")

    args = parser.parse_args()

    if not args.live and not args.read:
        logger.warning("No mode specified. Running in default live mode for testing...")
        args.live = True
        args.interface = args.interface or "Wi-Fi"
        timestamp = datetime.datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
        args.out = f"data/raw/{timestamp}.pcap"
        args.duration = args.duration or 60

    if args.live:
        if not args.interface or not args.out:
            logger.error("Live capture requires --interface and --out")
            _print_help_and_exit()
        out = start_live_capture(
            interface=args.interface,
            output_path=args.out,
            capture_filter=args.filter,
            duration=args.duration,
            packet_count=args.count,
            realtime=args.realtime,
        )
        logger.info("Saved capture to %s", out)

    elif args.read:
        pcap = args.read
        cnt = 0
        for pkt in read_pcap(pcap):
            cnt += 1
            try:
                ts = getattr(pkt, "sniff_time", None)
                layers = [l.layer_name for l in pkt.layers]
                print(f"[{cnt}] time={ts} layers={layers}")
            except Exception:
                print(f"[{cnt}] (packet summary unavailable)")
        logger.info("Finished reading pcap. Total packets: %d", cnt)


if __name__ == "__main__":
    _cli()
