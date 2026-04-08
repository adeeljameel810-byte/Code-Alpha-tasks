#!/usr/bin/env python3
"""Simple packet sniffer using scapy with a fallback to raw sockets."""

import argparse
import sys
import time

try:
    from scapy.all import sniff, IP, TCP, UDP, ICMP, Raw, conf
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False
    import socket


def hexdump(data: bytes, length: int = 16) -> str:
    lines = []
    for i in range(0, len(data), length):
        chunk = data[i : i + length]
        hex_bytes = " ".join(f"{b:02x}" for b in chunk)
        text = ''.join((chr(b) if 32 <= b < 127 else '.') for b in chunk)
        lines.append(f"{i:04x}  {hex_bytes:<{length*3}}  {text}")
    return "\n".join(lines)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Capture and inspect network packets.")
    parser.add_argument("-i", "--interface", help="Network interface to sniff on.")
    parser.add_argument("-c", "--count", type=int, default=0, help="Number of packets to capture (0 = unlimited).")
    parser.add_argument("-f", "--filter", default="", help="BPF filter expression for scapy sniffing.")
    parser.add_argument("-v", "--verbose", action="store_true", help="Show payload and protocol details.")
    return parser.parse_args()


def format_packet_info(pkt, verbose: bool = False) -> str:
    lines = []
    timestamp = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())
    if SCAPY_AVAILABLE:
        src = pkt[IP].src if IP in pkt else getattr(pkt, 'src', 'unknown')
        dst = pkt[IP].dst if IP in pkt else getattr(pkt, 'dst', 'unknown')
        proto = None
        payload = b""

        if IP in pkt:
            if pkt.haslayer(TCP):
                proto = 'TCP'
                payload = bytes(pkt[TCP].payload)
            elif pkt.haslayer(UDP):
                proto = 'UDP'
                payload = bytes(pkt[UDP].payload)
            elif pkt.haslayer(ICMP):
                proto = 'ICMP'
                payload = bytes(pkt[ICMP].payload)
            else:
                proto = pkt[IP].proto
                payload = bytes(pkt[IP].payload)

        summary = pkt.summary() if hasattr(pkt, 'summary') else 'Packet'
        lines.append(f"[{timestamp}] {src} -> {dst} | {proto} | {summary}")

        if verbose:
            lines.append(f"Layers: {', '.join(layer.name for layer in pkt.layers())}")
            lines.append(f"Payload length: {len(payload)} bytes")
            if payload:
                lines.append("Payload (hex/ascii):")
                lines.append(hexdump(payload))
    else:
        header = pkt[:20]
        if len(header) >= 20:
            src = socket.inet_ntoa(header[12:16])
            dst = socket.inet_ntoa(header[16:20])
            proto = header[9]
            proto_name = {6: 'TCP', 17: 'UDP', 1: 'ICMP'}.get(proto, str(proto))
            ihl = (header[0] & 0x0F) * 4
            payload = pkt[ihl:]
            lines.append(f"[{timestamp}] {src} -> {dst} | {proto_name} | raw packet")
            if verbose:
                lines.append(f"Header length: {ihl} bytes")
                lines.append(f"Payload length: {len(payload)} bytes")
                if payload:
                    lines.append("Payload (hex/ascii):")
                    lines.append(hexdump(payload))
        else:
            lines.append(f"[{timestamp}] Packet too small to parse")

    return "\n".join(lines)


def sniff_with_scapy(interface: str, count: int, bpf_filter: str, verbose: bool) -> None:
    if interface:
        conf.iface = interface
    print(f"Starting capture using scapy on interface: {conf.iface}")
    if bpf_filter:
        print(f"Using filter: {bpf_filter}")

    def process(packet):
        print(format_packet_info(packet, verbose))
        print('-' * 80)

    sniff(iface=interface if interface else None, filter=bpf_filter or None, prn=process, count=count or 0)


def sniff_with_socket(interface: str, count: int, verbose: bool) -> None:
    if interface:
        print("Warning: raw socket interface binding may not work on all OSes.")
    print("Starting capture using raw sockets. Try running as administrator/root.")
    with socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_IP) as sock:
        if interface:
            sock.bind((interface, 0))
        sock.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
        try:
            sock.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)
        except AttributeError:
            pass

        seen = 0
        while count == 0 or seen < count:
            chunk = sock.recv(65535)
            print(format_packet_info(chunk, verbose))
            print('-' * 80)
            seen += 1

        try:
            sock.ioctl(socket.SIO_RCVALL, socket.RCVALL_OFF)
        except AttributeError:
            pass


def main() -> int:
    args = parse_args()
    if not SCAPY_AVAILABLE:
        print("scapy is not installed. Falling back to raw sockets if possible.")
        print("Install scapy for richer packet analysis: pip install scapy")

    try:
        if SCAPY_AVAILABLE:
            sniff_with_scapy(args.interface, args.count, args.filter, args.verbose)
        else:
            sniff_with_socket(args.interface, args.count, args.verbose)
    except KeyboardInterrupt:
        print("\nCapture stopped by user.")
    except PermissionError:
        print("Permission denied: run the script as administrator/root.")
        return 1
    except Exception as exc:
        print(f"Error during capture: {exc}")
        return 1
    return 0


if __name__ == '__main__':
    sys.exit(main())
