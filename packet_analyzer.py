#!/usr/bin/env python3
"""
Advanced Packet Capture and Analysis Module
Handles wireless packet capture, analysis, and processing
"""

import subprocess
import threading
import time
import os
import platform
from datetime import datetime
from typing import List, Dict, Optional, Callable
import json
import re
from scapy.all import *  # For advanced packet analysis
import psutil


class PacketCapture:
    """Handles packet capture operations"""

    def __init__(self):
        self.capturing = False
        self.capture_thread: Optional[threading.Thread] = None
        self.current_capture_file = ""
        self.interface = ""
        self.filter = ""
        self.on_packet_captured: Optional[Callable] = None
        self.packets_captured = 0

    def start_capture(self, interface: str, output_file: str = "",
                     duration: Optional[int] = None, packet_filter: str = "",
                     channels: Optional[List[int]] = None) -> bool:
        """Start packet capture"""
        if self.capturing:
            return False

        self.interface = interface
        self.filter = packet_filter
        self.packets_captured = 0

        if not output_file:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            self.current_capture_file = f"capture_{timestamp}.cap"
        else:
            self.current_capture_file = output_file

        self.capturing = True
        self.capture_thread = threading.Thread(
            target=self._capture_worker,
            args=(duration, channels)
        )
        self.capture_thread.daemon = True
        self.capture_thread.start()

        return True

    def stop_capture(self) -> bool:
        """Stop current capture"""
        if not self.capturing:
            return False

        self.capturing = False
        if self.capture_thread and self.capture_thread.is_alive():
            self.capture_thread.join(timeout=10)

        return True

    def _capture_worker(self, duration: Optional[int] = None,
                       channels: Optional[List[int]] = None):
        """Background capture worker"""
        try:
            if platform.system() == "Linux":
                self._linux_capture(duration, channels)
            elif platform.system() == "Windows":
                self._windows_capture(duration)
            else:
                print("Packet capture not supported on this platform")

        except Exception as e:
            print(f"Capture error: {e}")
        finally:
            self.capturing = False

    def _linux_capture(self, duration: Optional[int] = None,
                      channels: Optional[List[int]] = None):
        """Linux packet capture using tcpdump or airodump-ng"""
        try:
            if channels and len(channels) == 1:
                # Single channel capture with airodump-ng
                cmd = ['sudo', 'airodump-ng', '-c', str(channels[0]), '-w', 'channel_capture',
                      '--output-format', 'pcap']

                if self.filter:
                    # Add BSSID filter if specified
                    if 'ether host' in self.filter:
                        bssid = re.search(r'ether host ([0-9a-f:]+)', self.filter, re.IGNORECASE)
                        if bssid:
                            cmd.extend(['--bssid', bssid.group(1)])

                cmd.append(self.interface)

                process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)

                start_time = time.time()
                while self.capturing and (not duration or time.time() - start_time < duration):
                    time.sleep(1)

                process.terminate()
                process.wait()

                # Rename output file
                airodump_file = 'channel_capture-01.cap'
                if os.path.exists(airodump_file):
                    os.rename(airodump_file, self.current_capture_file)

            else:
                # General capture with tcpdump
                cmd = ['sudo', 'tcpdump', '-i', self.interface, '-w', self.current_capture_file]

                if self.filter:
                    cmd.extend(['-f', self.filter])

                if duration:
                    cmd.extend(['-G', str(duration), '-W', '1'])

                process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)

                if duration:
                    # Wait for duration
                    time.sleep(duration)
                    self.capturing = False
                else:
                    # Manual stop required
                    while self.capturing:
                        time.sleep(0.1)

                if process.poll() is None:
                    process.terminate()
                    process.wait(timeout=5)

        except Exception as e:
            print(f"Linux capture error: {e}")

    def _windows_capture(self, duration: Optional[int] = None):
        """Windows packet capture (limited functionality)"""
        try:
            # Use windump if available, otherwise fallback
            cmd = ['windump', '-i', self.interface, '-w', self.current_capture_file]

            if self.filter:
                cmd.extend([self.filter])

            process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)

            start_time = time.time()
            while self.capturing and (not duration or time.time() - start_time < duration):
                time.sleep(1)

            if process.poll() is None:
                process.terminate()

        except Exception as e:
            print(f"Windows capture error: {e}")

    def capture_handshake(self, interface: str, bssid: str, channel: int,
                         output_file: str = "", timeout: int = 60) -> bool:
        """Capture WPA handshake"""
        try:
            if not output_file:
                timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
                output_file = f"handshake_{bssid.replace(':', '')}_{timestamp}.cap"

            # Start airodump-ng to capture
            cmd = ['sudo', 'airodump-ng', '-c', str(channel), '--bssid', bssid,
                  '-w', 'handshake_capture', '--output-format', 'pcap', interface]

            process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)

            # Wait a bit for airodump to start
            time.sleep(3)

            # Send deauth to force handshake
            deauth_cmd = ['sudo', 'aireplay-ng', '--deauth', '5', '-a', bssid, interface]
            subprocess.run(deauth_cmd, timeout=10, capture_output=True)

            # Wait for handshake or timeout
            start_time = time.time()
            handshake_found = False

            while self.capturing and time.time() - start_time < timeout:
                time.sleep(2)

                # Check if handshake was captured
                if self._check_for_handshake('handshake_capture-01.cap'):
                    handshake_found = True
                    break

            process.terminate()
            process.wait()

            # Rename file if handshake found
            if handshake_found and os.path.exists('handshake_capture-01.cap'):
                os.rename('handshake_capture-01.cap', output_file)
                self.current_capture_file = output_file
                return True

            return False

        except Exception as e:
            print(f"Handshake capture error: {e}")
            return False

    def _check_for_handshake(self, capture_file: str) -> bool:
        """Check if capture file contains WPA handshake"""
        if not os.path.exists(capture_file):
            return False

        try:
            # Use aircrack-ng to check for handshake
            result = subprocess.run(['aircrack-ng', capture_file],
                                  capture_output=True, text=True, timeout=10)

            return 'WPA handshake' in result.stdout or 'handshake' in result.stdout.lower()

        except Exception as e:
            print(f"Handshake check error: {e}")
            return False


class PacketAnalyzer:
    """Analyzes captured packets"""

    def __init__(self):
        self.capture_file = ""
        self.packets = []
        self.analysis_results = {}

    def load_capture(self, filename: str) -> bool:
        """Load capture file for analysis"""
        if not os.path.exists(filename):
            return False

        self.capture_file = filename

        try:
            # Load packets using Scapy
            self.packets = rdpcap(filename)
            return True
        except Exception as e:
            print(f"Error loading capture: {e}")
            return False

    def analyze_capture(self) -> Dict:
        """Perform comprehensive analysis of capture file"""
        if not self.packets:
            return {}

        results = {
            'total_packets': len(self.packets),
            'packet_types': {},
            'networks': {},
            'clients': {},
            'handshakes': [],
            'deauth_packets': [],
            'encryption_types': set(),
            'channels': set(),
            'time_range': {}
        }

        # Get time range
        if self.packets:
            timestamps = [pkt.time for pkt in self.packets if hasattr(pkt, 'time')]
            if timestamps:
                results['time_range'] = {
                    'start': datetime.fromtimestamp(min(timestamps)).isoformat(),
                    'end': datetime.fromtimestamp(max(timestamps)).isoformat(),
                    'duration': max(timestamps) - min(timestamps)
                }

        # Analyze each packet
        for pkt in self.packets:
            self._analyze_packet(pkt, results)

        # Convert sets to lists for JSON serialization
        results['encryption_types'] = list(results['encryption_types'])
        results['channels'] = list(results['channels'])

        self.analysis_results = results
        return results

    def _analyze_packet(self, pkt, results: Dict):
        """Analyze individual packet"""
        try:
            # Packet type analysis
            pkt_type = self._get_packet_type(pkt)
            results['packet_types'][pkt_type] = results['packet_types'].get(pkt_type, 0) + 1

            # Wireless analysis
            if pkt.haslayer(Dot11):
                self._analyze_dot11_packet(pkt, results)

            # IP analysis
            if pkt.haslayer(IP):
                self._analyze_ip_packet(pkt, results)

        except Exception as e:
            # Skip malformed packets
            pass

    def _get_packet_type(self, pkt) -> str:
        """Get packet type description"""
        if pkt.haslayer(Dot11):
            if pkt.haslayer(Dot11Beacon):
                return "802.11 Beacon"
            elif pkt.haslayer(Dot11ProbeReq):
                return "802.11 Probe Request"
            elif pkt.haslayer(Dot11ProbeResp):
                return "802.11 Probe Response"
            elif pkt.haslayer(Dot11AssoReq):
                return "802.11 Association Request"
            elif pkt.haslayer(Dot11AssoResp):
                return "802.11 Association Response"
            elif pkt.haslayer(Dot11Deauth):
                return "802.11 Deauthentication"
            elif pkt.haslayer(Dot11Auth):
                return "802.11 Authentication"
            elif pkt.haslayer(Dot11Data):
                return "802.11 Data"
            else:
                return "802.11 Other"
        elif pkt.haslayer(IP):
            if pkt.haslayer(TCP):
                return "TCP"
            elif pkt.haslayer(UDP):
                return "UDP"
            else:
                return "IP"
        else:
            return "Other"

    def _analyze_dot11_packet(self, pkt, results: Dict):
        """Analyze 802.11 wireless packet"""
        dot11 = pkt.getlayer(Dot11)

        # Extract addresses
        addr1 = dot11.addr1
        addr2 = dot11.addr2
        addr3 = dot11.addr3

        # Get BSSID (usually addr3 for management frames)
        bssid = addr3 if addr3 else "Unknown"

        # Track networks
        if pkt.haslayer(Dot11Beacon) or pkt.haslayer(Dot11ProbeResp):
            essid = ""
            channel = ""
            encryption = ""

            # Extract ESSID
            if pkt.haslayer(Dot11Elt):
                elts = pkt.getlayer(Dot11Elt)
                while elts:
                    if elts.ID == 0:  # ESSID
                        essid = elts.info.decode('utf-8', errors='ignore')
                    elif elts.ID == 3:  # Channel
                        channel = str(elts.info[0])
                    elif elts.ID == 48:  # RSN (WPA2)
                        encryption = "WPA2"
                    elif elts.ID == 221:  # WPA
                        if b"WPA" in elts.info:
                            encryption = "WPA"

                    elts = elts.payload.getlayer(Dot11Elt) if elts.payload else None

            if essid:
                if bssid not in results['networks']:
                    results['networks'][bssid] = {
                        'essid': essid,
                        'channel': channel,
                        'encryption': encryption or "Open",
                        'clients': set()
                    }
                else:
                    # Update info if missing
                    if not results['networks'][bssid]['channel']:
                        results['networks'][bssid]['channel'] = channel
                    if not results['networks'][bssid]['encryption'] or results['networks'][bssid]['encryption'] == "Open":
                        results['networks'][bssid]['encryption'] = encryption or "Open"

                results['channels'].add(channel)

        # Track clients
        if pkt.haslayer(Dot11Data):
            # Data frames have source and destination
            src = addr2
            dst = addr1

            if src and src != bssid:
                if bssid not in results['clients']:
                    results['clients'][bssid] = set()
                results['clients'][bssid].add(src)

            if dst and dst != bssid and dst != "ff:ff:ff:ff:ff:ff":
                if bssid not in results['clients']:
                    results['clients'][bssid] = set()
                results['clients'][bssid].add(dst)

        # Track deauthentication packets
        if pkt.haslayer(Dot11Deauth):
            deauth_info = {
                'src': addr2,
                'dst': addr1,
                'bssid': bssid,
                'reason': pkt.getlayer(Dot11Deauth).reason if hasattr(pkt.getlayer(Dot11Deauth), 'reason') else 0
            }
            results['deauth_packets'].append(deauth_info)

        # Check for WPA handshakes
        if self._is_wpa_handshake(pkt):
            handshake_info = {
                'bssid': bssid,
                'client': addr2 if addr2 != bssid else addr1,
                'packet_type': 'EAPOL' if pkt.haslayer(EAPOL) else 'Unknown'
            }
            results['handshakes'].append(handshake_info)

    def _is_wpa_handshake(self, pkt) -> bool:
        """Check if packet is part of WPA handshake"""
        if pkt.haslayer(EAPOL):
            eapol = pkt.getlayer(EAPOL)
            return hasattr(eapol, 'type') and eapol.type == 3  # Key exchange
        return False

    def _analyze_ip_packet(self, pkt, results: Dict):
        """Analyze IP packet"""
        # Basic IP analysis - could be expanded
        pass

    def extract_handshakes(self, output_dir: str = "handshakes") -> List[str]:
        """Extract WPA handshakes to separate files"""
        if not os.path.exists(output_dir):
            os.makedirs(output_dir)

        extracted_files = []

        try:
            # Use aircrack-ng to extract handshakes
            result = subprocess.run(['aircrack-ng', self.capture_file],
                                  capture_output=True, text=True, timeout=30)

            # Parse output to find networks with handshakes
            networks_with_handshakes = []
            current_network = None

            for line in result.stdout.split('\n'):
                if '[' in line and 'handshake' in line.lower():
                    # Found network with handshake
                    bssid_match = re.search(r'([0-9A-F:]{17})', line, re.IGNORECASE)
                    if bssid_match:
                        bssid = bssid_match.group(1)
                        networks_with_handshakes.append(bssid)

            # Extract each handshake
            for i, bssid in enumerate(networks_with_handshakes):
                output_file = os.path.join(output_dir, f"handshake_{bssid.replace(':', '')}.cap")

                # Use aircrack-ng to extract specific handshake
                cmd = ['aircrack-ng', '-b', bssid, '-R', bssid, '-w', '/dev/null',
                      '-o', output_file, self.capture_file]

                subprocess.run(cmd, capture_output=True, timeout=30)
                extracted_files.append(output_file)

        except Exception as e:
            print(f"Handshake extraction error: {e}")

        return extracted_files

    def convert_capture_format(self, input_file: str, output_file: str,
                              output_format: str = "pcapng") -> bool:
        """Convert capture file to different format"""
        try:
            if output_format.lower() == "pcapng":
                # Convert to pcapng using editcap or similar
                result = subprocess.run(['editcap', '-F', 'pcapng', input_file, output_file],
                                      capture_output=True, timeout=30)
                return result.returncode == 0
            elif output_format.lower() == "csv":
                # Convert to CSV using tshark
                result = subprocess.run(['tshark', '-r', input_file, '-T', 'fields',
                                       '-e', 'frame.time', '-e', 'wlan.sa', '-e', 'wlan.da',
                                       '-e', 'wlan.bssid', '-E', 'separator=,',
                                       '-E', 'header=y', '-w', output_file],
                                      capture_output=True, timeout=30)
                return result.returncode == 0
            else:
                return False

        except Exception as e:
            print(f"Format conversion error: {e}")
            return False

    def filter_packets(self, filter_expr: str, output_file: str = "") -> List:
        """Filter packets using display filter"""
        try:
            if not output_file:
                timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
                output_file = f"filtered_{timestamp}.cap"

            # Use tshark to filter
            result = subprocess.run(['tshark', '-r', self.capture_file, '-w', output_file,
                                   '-Y', filter_expr], capture_output=True, timeout=60)

            if result.returncode == 0:
                # Load filtered packets
                filtered_packets = rdpcap(output_file)
                return filtered_packets
            else:
                return []

        except Exception as e:
            print(f"Packet filtering error: {e}")
            return []

    def get_packet_summary(self, limit: int = 100) -> List[Dict]:
        """Get summary of first N packets"""
        summary = []

        for i, pkt in enumerate(self.packets[:limit]):
            pkt_info = {
                'index': i + 1,
                'time': datetime.fromtimestamp(pkt.time).strftime("%H:%M:%S.%f")[:-3] if hasattr(pkt, 'time') else "Unknown",
                'length': len(pkt),
                'type': self._get_packet_type(pkt),
                'src': 'Unknown',
                'dst': 'Unknown'
            }

            # Extract addresses for wireless packets
            if pkt.haslayer(Dot11):
                dot11 = pkt.getlayer(Dot11)
                if dot11.addr1:
                    pkt_info['dst'] = dot11.addr1
                if dot11.addr2:
                    pkt_info['src'] = dot11.addr2

            # Extract addresses for IP packets
            elif pkt.haslayer(IP):
                pkt_info['src'] = pkt[IP].src
                pkt_info['dst'] = pkt[IP].dst

            summary.append(pkt_info)

        return summary

    def export_analysis(self, filename: str):
        """Export analysis results to JSON"""
        try:
            # Convert sets to lists for JSON serialization
            export_data = self.analysis_results.copy()

            for network in export_data.get('networks', {}).values():
                if 'clients' in network and isinstance(network['clients'], set):
                    network['clients'] = list(network['clients'])

            for bssid, clients in export_data.get('clients', {}).items():
                if isinstance(clients, set):
                    export_data['clients'][bssid] = list(clients)

            with open(filename, 'w') as f:
                json.dump(export_data, f, indent=2, default=str)

        except Exception as e:
            print(f"Export error: {e}")


class CaptureManager:
    """Manages multiple capture sessions and files"""

    def __init__(self):
        self.captures = {}
        self.active_captures = {}

    def create_capture(self, name: str) -> PacketCapture:
        """Create a new capture session"""
        capture = PacketCapture()
        self.captures[name] = capture
        return capture

    def get_capture(self, name: str) -> Optional[PacketCapture]:
        """Get capture by name"""
        return self.captures.get(name)

    def list_captures(self) -> List[str]:
        """List all capture sessions"""
        return list(self.captures.keys())

    def delete_capture(self, name: str):
        """Delete capture session"""
        if name in self.captures:
            # Stop if active
            if name in self.active_captures:
                self.captures[name].stop_capture()
                del self.active_captures[name]

            del self.captures[name]

    def cleanup_old_captures(self, days: int = 7):
        """Clean up old capture files"""
        import glob

        # Find old capture files
        capture_files = glob.glob("*.cap") + glob.glob("*.pcap") + glob.glob("*.pcapng")

        cutoff_time = time.time() - (days * 24 * 60 * 60)

        for file in capture_files:
            try:
                if os.path.getmtime(file) < cutoff_time:
                    os.remove(file)
                    print(f"Removed old capture file: {file}")
            except Exception as e:
                print(f"Error removing {file}: {e}")


# Utility functions
def merge_captures(input_files: List[str], output_file: str) -> bool:
    """Merge multiple capture files"""
    try:
        result = subprocess.run(['mergecap', '-w', output_file] + input_files,
                              capture_output=True, timeout=60)
        return result.returncode == 0
    except Exception as e:
        print(f"Merge error: {e}")
        return False


def split_capture(input_file: str, output_prefix: str, max_packets: int = 10000):
    """Split capture file into smaller chunks"""
    try:
        result = subprocess.run(['editcap', '-c', str(max_packets), input_file,
                               f"{output_prefix}_chunk.cap"], capture_output=True, timeout=60)
        return result.returncode == 0
    except Exception as e:
        print(f"Split error: {e}")
        return False


def check_capture_integrity(filename: str) -> Dict:
    """Check capture file integrity"""
    result = {
        'valid': False,
        'packets': 0,
        'errors': []
    }

    try:
        # Use capinfos to check file
        capinfos = subprocess.run(['capinfos', filename], capture_output=True, text=True, timeout=30)

        if capinfos.returncode == 0:
            result['valid'] = True

            # Parse output
            for line in capinfos.stdout.split('\n'):
                if 'Number of packets' in line:
                    packets_match = re.search(r'(\d+)', line)
                    if packets_match:
                        result['packets'] = int(packets_match.group(1))

        else:
            result['errors'].append("capinfos check failed")

    except Exception as e:
        result['errors'].append(str(e))

    return result


if __name__ == "__main__":
    # Test packet analyzer
    analyzer = PacketAnalyzer()

    # Test with sample capture file (if exists)
    test_files = ["test.cap", "capture.cap", "sample.cap"]
    for test_file in test_files:
        if os.path.exists(test_file):
            print(f"Testing with {test_file}")
            if analyzer.load_capture(test_file):
                results = analyzer.analyze_capture()
                print(f"Analysis complete: {results['total_packets']} packets")
                analyzer.export_analysis("analysis_results.json")
            break
    else:
        print("No test capture files found")

