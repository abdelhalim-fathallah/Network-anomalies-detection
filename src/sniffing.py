"""
src/sniffing.py

Network traffic capture utilities using pyshark (tshark).
Features:
 - Ensure tshark (Wireshark) directory is available in PATH (Windows example).
 - Live capture for a specified duration and save to a pcap file.
 - Read packets from an existing pcap file (generator).
 - Simple command line interface for quick tests.

Usage examples:
  python sniffing.py --live --interface "Ethernet" --duration 30 --out "../data/raw/capture1.pcap"
  python sniffing.py --read "../data/raw/capture1.pcap"

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



# ------- Configuration: modify if needed -------
# Add Wireshark/TShark path here (Windows example provided by user)
DEFAULT_TSHARK_PATH = r"D:\wireshark\tshark.exe"  # change if your tshark path is different
# ----------------------------------------------

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format="[%(asctime)s] %(levelname)s - %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
logger = logging.getLogger("sniffing")

def ensure_tshark_on_path(tshark_path: Optional[str] = None) -> None:
    """
    Ensure the tshark/Wireshark directory is in PATH so pyshark can find tshark.
    If tshark_path is None, use DEFAULT_TSHARK_PATH.
    """
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
    tshark_path=r"D:\Wireshark\tshark.exe"
) -> str:
    """
    Start a live capture on `interface` and write to `output_path` (pcap).
    - capture_filter: BPF filter string (e.g., "tcp and port 80")
    - duration: capture duration in seconds (if None and packet_count is None, runs until Ctrl+C)
    - packet_count: stop after this many packets (overrides duration if provided)
    Returns the path to the created pcap file.
    """
    ensure_tshark_on_path()

    out = Path(output_path).expanduser().resolve()
    out.parent.mkdir(parents=True, exist_ok=True)

    logger.info("Starting live capture: interface=%s, out=%s", interface, out)
    if capture_filter:
        logger.info("Using capture filter: %s", capture_filter)
    if duration:
        logger.info("Capture duration (s): %d", duration)
    if packet_count:
        logger.info("Packet count limit: %d", packet_count)

    try:
        capture = pyshark.LiveCapture(interface=interface, output_file=str(out), bpf_filter=capture_filter)
    except Exception as e:
        logger.exception("Failed to create LiveCapture: %s", e)
        raise

    start_time = time.time()
    try:
        if packet_count:
            # Capture until packet_count reached
            capture.sniff(timeout=duration) if duration else None
            # pyshark LiveCapture does not have a direct packet_count parameter for sniff,
            # so we loop and break when reached.
            pkt_seen = 0
            logger.info("Capturing until %d packets seen...", packet_count)
            for pkt in capture.sniff_continuously():
                pkt_seen += 1
                if pkt_seen >= packet_count:
                    logger.info("Reached packet_count=%d -> stopping", packet_count)
                    break
        elif duration:
            # sniff with timeout
            logger.info("Capturing for %d seconds...", duration)
            capture.sniff(timeout=duration)
        else:
            # No duration and no packet_count: run until KeyboardInterrupt
            logger.info("Capturing until user stops (Ctrl+C)...")
            for _ in capture.sniff_continuously():
                pass
    except KeyboardInterrupt:
        logger.info("Capture interrupted by user.")
    except Exception as e:
        logger.exception("Error during live capture: %s", e)
        raise
    finally:
        try:
            capture.close()
        except Exception:
            pass

    elapsed = time.time() - start_time
    logger.info("Capture finished, saved to %s (%.2f sec)", out, elapsed)
    return str(out)


def read_pcap(file_path: str) -> Generator[pyshark.packet.packet.Packet, None, None]:
    """
    Generator that yields pyshark Packet objects read from a pcap file.
    Use for downstream feature extraction or quick inspection.
    """
    ensure_tshark_on_path()
    file_path = str(Path(file_path).expanduser().resolve())
    if not Path(file_path).exists():
        raise FileNotFoundError(f"PCAP file not found: {file_path}")

    logger.info("Opening pcap file: %s", file_path)
    try:
        capture = pyshark.FileCapture(file_path, keep_packets=False)  # stream packets to save memory
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
    """
    Utility: quick count of packets in a pcap (uses FileCapture iteration).
    """
    cnt = 0
    for _ in read_pcap(file_path):
        cnt += 1
    logger.info("Packet count in %s: %d", file_path, cnt)
    return cnt


# -------------------- Simple CLI --------------------
def _print_help_and_exit():
    print(__doc__)
    print("CLI usage examples:")
    print('  python sniffing.py --live --interface "Ethernet" --duration 30 --out "../data/raw/capture1.pcap"')
    print('  python sniffing.py --read "../data/raw/capture1.pcap"')
    sys.exit(1)

def _cli():
    import argparse

    parser = argparse.ArgumentParser(description="sniffing.py - live capture and pcap reader utilities")
    group = parser.add_mutually_exclusive_group(required=False)  # <-- changed to False

    group.add_argument("--live", action="store_true", help="Start live capture")
    group.add_argument("--read", metavar="PCAP", help="Read a pcap file and print basic info")

    parser.add_argument("--interface", "-i", type=str, help="Interface name for live capture (e.g., Ethernet)")
    parser.add_argument("--out", "-o", type=str, help="Output pcap path for live capture")
    parser.add_argument("--duration", "-t", type=int, help="Duration in seconds for live capture")
    parser.add_argument("--count", "-c", type=int, help="Stop after this many packets")
    parser.add_argument("--filter", type=str, help="BPF capture filter (e.g., 'tcp and port 80')")

    args = parser.parse_args()

    # Default behavior if no arguments are given
    if not args.live and not args.read:
        logger.warning("No mode specified. Running in default live mode for testing...")
        args.live = True
        args.interface = args.interface or "Wi-Fi"

        # === Create timestamped filename ===
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
