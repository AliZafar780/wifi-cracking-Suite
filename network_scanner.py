#!/usr/bin/env python3
"""
Advanced Network Scanner Module
Handles wireless network discovery and analysis
"""

import subprocess
import threading
import time
import platform
import os
import re
from datetime import datetime
import psutil
from typing import List, Dict, Optional
import json


class NetworkInfo:
    """Represents a wireless network"""
    def __init__(self, bssid: str = "", essid: str = "", channel: str = "",
                 encryption: str = "", signal: str = "", clients: int = 0):
        self.bssid = bssid
        self.essid = essid
        self.channel = channel
        self.encryption = encryption
        self.signal = signal
        self.clients = clients
        self.first_seen = datetime.now()
        self.last_seen = datetime.now()
        self.vendor = self._get_vendor_from_bssid(bssid)
        self.wps = False
        self.wps_locked = False

    def _get_vendor_from_bssid(self, bssid: str) -> str:
        """Get vendor information from BSSID (MAC address)"""
        if not bssid or len(bssid) < 8:
            return "Unknown"

        # Simple vendor lookup (in real implementation, use a proper database)
        mac_prefix = bssid.upper()[:8]
        vendors = {
            "00:00:0C": "Cisco",
            "00:01:42": "Parallels",
            "00:03:FF": "Microsoft",
            "00:05:69": "VMware",
            "00:0C:29": "VMware",
            "00:0F:4B": "Virtual Iron Software",
            "00:13:07": "Parallels",
            "00:15:5D": "Microsoft",
            "00:16:3E": "Xensource",
            "00:17:42": "Virtual Iron Software",
            "00:1C:14": "VMware",
            "00:1C:42": "Parallels",
            "00:21:F6": "Virtual Iron Software",
            "00:24:0E": "Apple",
            "00:50:56": "VMware",
            "08:00:27": "Oracle",
            "0A:00:27": "Unknown Device",
            "52:54:00": "QEMU",
            "B8:27:EB": "Raspberry Pi Foundation",
            "DC:A6:32": "Raspberry Pi Foundation",
        }

        return vendors.get(mac_prefix, "Unknown")

    def to_dict(self) -> dict:
        """Convert to dictionary for serialization"""
        return {
            'bssid': self.bssid,
            'essid': self.essid,
            'channel': self.channel,
            'encryption': self.encryption,
            'signal': self.signal,
            'clients': self.clients,
            'vendor': self.vendor,
            'wps': self.wps,
            'wps_locked': self.wps_locked,
            'first_seen': self.first_seen.isoformat(),
            'last_seen': self.last_seen.isoformat()
        }


class WirelessInterface:
    """Represents a wireless network interface"""
    def __init__(self, name: str):
        self.name = name
        self.supports_monitor = False
        self.monitor_name = ""
        self.mac_address = ""
        self.mode = "managed"
        self.channel = ""
        self.frequency = ""
        self.tx_power = ""

    def check_monitor_support(self) -> bool:
        """Check if interface supports monitor mode"""
        try:
            if platform.system() == "Linux":
                result = subprocess.run(['iw', 'list'], capture_output=True, text=True)
                if self.name in result.stdout:
                    self.supports_monitor = "monitor" in result.stdout
                    return self.supports_monitor
        except:
            pass
        return False


class NetworkScanner:
    """Advanced wireless network scanner"""

    def __init__(self):
        self.networks: Dict[str, NetworkInfo] = {}
        self.interfaces: List[WirelessInterface] = []
        self.scanning = False
        self.scan_thread: Optional[threading.Thread] = None
        self.on_network_found = None  # Callback function
        self.on_scan_progress = None  # Progress callback

    def get_wireless_interfaces(self) -> List[str]:
        """Get list of wireless interfaces"""
        interfaces = []

        try:
            if platform.system() == "Windows":
                # Windows implementation
                result = subprocess.run(['netsh', 'wlan', 'show', 'interfaces'],
                                      capture_output=True, text=True, timeout=10)
                for line in result.stdout.split('\n'):
                    if 'Name' in line and ':' in line:
                        name = line.split(':', 1)[1].strip()
                        interfaces.append(name)

            elif platform.system() == "Linux":
                # Linux implementation
                result = subprocess.run(['iwconfig'], capture_output=True, text=True, timeout=10)
                for line in result.stdout.split('\n'):
                    if line.strip() and not line.startswith(' ') and not line.startswith('lo'):
                        interface = line.split()[0]
                        # Check if it's wireless
                        try:
                            iw_result = subprocess.run(['iw', 'dev', interface, 'info'],
                                                     capture_output=True, text=True, timeout=5)
                            if iw_result.returncode == 0:
                                interfaces.append(interface)
                        except:
                            # Fallback: check iwconfig output for wireless indicators
                            if 'IEEE 802.11' in line or 'ESSID' in line:
                                interfaces.append(interface)

        except Exception as e:
            print(f"Error getting wireless interfaces: {e}")
            # Fallback interfaces
            interfaces = ["wlan0", "wlan1", "wlp2s0", "wlp3s0"]

        return interfaces

    def get_interface_info(self, interface_name: str) -> WirelessInterface:
        """Get detailed information about a wireless interface"""
        interface = WirelessInterface(interface_name)

        try:
            if platform.system() == "Linux":
                # Get interface info using iw
                result = subprocess.run(['iw', 'dev', interface_name, 'info'],
                                      capture_output=True, text=True, timeout=5)

                if result.returncode == 0:
                    output = result.stdout
                    interface.supports_monitor = "monitor" in output

                    # Parse MAC address
                    for line in output.split('\n'):
                        if 'addr' in line and ':' in line:
                            parts = line.split()
                            if len(parts) >= 2:
                                interface.mac_address = parts[1]
                                break

                # Get current mode and channel
                result = subprocess.run(['iwconfig', interface_name],
                                      capture_output=True, text=True, timeout=5)

                if result.returncode == 0:
                    output = result.stdout
                    # Parse mode
                    if 'Mode:' in output:
                        mode_match = re.search(r'Mode:(\w+)', output)
                        if mode_match:
                            interface.mode = mode_match.group(1).lower()

                    # Parse frequency/channel
                    if 'Frequency:' in output:
                        freq_match = re.search(r'Frequency:([\d\.]+)', output)
                        if freq_match:
                            freq = float(freq_match.group(1))
                            interface.frequency = f"{freq} GHz"
                            # Convert frequency to channel
                            if 2.4 <= freq <= 2.5:
                                interface.channel = str(int((freq - 2.4) * 10 + 1))
                            elif 5.0 <= freq <= 6.0:
                                interface.channel = str(int((freq - 5.0) * 4 + 34))

        except Exception as e:
            print(f"Error getting interface info for {interface_name}: {e}")

        return interface

    def enable_monitor_mode(self, interface: str) -> tuple[bool, str]:
        """Enable monitor mode on interface"""
        try:
            if platform.system() == "Linux":
                # Use airmon-ng if available
                result = subprocess.run(['which', 'airmon-ng'], capture_output=True, timeout=5)
                if result.returncode == 0:
                    # Use airmon-ng
                    result = subprocess.run(['sudo', 'airmon-ng', 'start', interface],
                                          capture_output=True, text=True, timeout=15)

                    if result.returncode == 0:
                        # Parse monitor interface name
                        monitor_interface = f"{interface}mon"
                        return True, monitor_interface
                    else:
                        return False, f"airmon-ng failed: {result.stderr}"
                else:
                    # Manual method using iw
                    # First, bring interface down
                    subprocess.run(['sudo', 'ip', 'link', 'set', interface, 'down'],
                                 capture_output=True, timeout=10)

                    # Set monitor mode
                    result = subprocess.run(['sudo', 'iw', interface, 'set', 'monitor', 'none'],
                                          capture_output=True, timeout=10)

                    if result.returncode == 0:
                        # Bring interface up
                        subprocess.run(['sudo', 'ip', 'link', 'set', interface, 'up'],
                                     capture_output=True, timeout=10)
                        return True, interface
                    else:
                        return False, f"iw set monitor failed: {result.stderr}"

            else:
                return False, "Monitor mode not supported on this platform"

        except Exception as e:
            return False, f"Error enabling monitor mode: {e}"

    def disable_monitor_mode(self, interface: str) -> tuple[bool, str]:
        """Disable monitor mode on interface"""
        try:
            if platform.system() == "Linux":
                # Check if airmon-ng was used
                if interface.endswith('mon'):
                    result = subprocess.run(['sudo', 'airmon-ng', 'stop', interface],
                                          capture_output=True, text=True, timeout=15)

                    if result.returncode == 0:
                        return True, "Monitor mode disabled"
                    else:
                        return False, f"airmon-ng stop failed: {result.stderr}"
                else:
                    # Manual method
                    subprocess.run(['sudo', 'ip', 'link', 'set', interface, 'down'],
                                 capture_output=True, timeout=10)

                    result = subprocess.run(['sudo', 'iw', interface, 'set', 'type', 'managed'],
                                          capture_output=True, timeout=10)

                    if result.returncode == 0:
                        subprocess.run(['sudo', 'ip', 'link', 'set', interface, 'up'],
                                     capture_output=True, timeout=10)
                        return True, "Monitor mode disabled"
                    else:
                        return False, f"iw set type managed failed: {result.stderr}"

            else:
                return False, "Monitor mode not supported on this platform"

        except Exception as e:
            return False, f"Error disabling monitor mode: {e}"

    def start_scan(self, interface: str, duration: int = 30,
                   channels: Optional[List[int]] = None) -> bool:
        """Start network scanning"""
        if self.scanning:
            return False

        self.scanning = True
        self.scan_thread = threading.Thread(
            target=self._scan_worker,
            args=(interface, duration, channels)
        )
        self.scan_thread.daemon = True
        self.scan_thread.start()

        return True

    def stop_scan(self):
        """Stop current scan"""
        self.scanning = False
        if self.scan_thread and self.scan_thread.is_alive():
            self.scan_thread.join(timeout=5)

    def _scan_worker(self, interface: str, duration: int,
                    channels: Optional[List[int]] = None):
        """Background scanning worker"""
        try:
            start_time = time.time()

            if platform.system() == "Linux":
                self._linux_scan(interface, duration, channels)
            elif platform.system() == "Windows":
                self._windows_scan(interface, duration)
            else:
                self._generic_scan(interface, duration)

            # Update last seen times
            for network in self.networks.values():
                network.last_seen = datetime.now()

        except Exception as e:
            print(f"Scan error: {e}")
        finally:
            self.scanning = False

    def _linux_scan(self, interface: str, duration: int,
                   channels: Optional[List[int]] = None):
        """Linux-specific scanning using airodump-ng"""
        process = None
        temp_files = ['scan_temp-01.csv', 'scan_temp-01.cap',
                      'scan_temp-01.kismet.csv', 'scan_temp-01.kismet.netxml']
        try:
            # Check if airodump-ng is available
            result = subprocess.run(['which', 'airodump-ng'], capture_output=True, timeout=5)
            if result.returncode != 0:
                print("airodump-ng not found, falling back to iw scan")
                self._iw_scan(interface, duration, channels)
                return

            # Use airodump-ng for comprehensive scanning
            cmd = ['sudo', 'airodump-ng', '-w', 'scan_temp', '--output-format', 'csv',
                  '--write-interval', '1']

            if channels:
                cmd.extend(['-c', ','.join(map(str, channels))])

            cmd.append(interface)

            process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)

            start_time = time.time()
            last_parse = 0

            while self.scanning and time.time() - start_time < duration:
                time.sleep(1)

                # Parse results every few seconds
                if time.time() - last_parse > 2:
                    self._parse_airodump_csv('scan_temp-01.csv')
                    last_parse = time.time()

                # Update progress
                if self.on_scan_progress:
                    progress = min(100, int((time.time() - start_time) / duration * 100))
                    self.on_scan_progress(progress)

            # Final parse
            self._parse_airodump_csv('scan_temp-01.csv')

        except Exception as e:
            print(f"Linux scan error: {e}")
        finally:
            # Terminate process if still running
            if process is not None and process.poll() is None:
                try:
                    process.terminate()
                    process.wait(timeout=5)
                except Exception as term_err:
                    print(f"Error terminating airodump-ng process: {term_err}")

            # Clean up temp files
            self._cleanup_temp_files(temp_files)

    def _iw_scan(self, interface: str, duration: int, channels: Optional[List[int]] = None):
        """Scan using iw command"""
        try:
            # Set interface up if needed
            subprocess.run(['sudo', 'ip', 'link', 'set', interface, 'up'],
                         capture_output=True, timeout=5)

            start_time = time.time()

            while self.scanning and time.time() - start_time < duration:
                # Scan on specific channels if provided
                if channels:
                    for channel in channels:
                        if not self.scanning:
                            break

                        # Set channel
                        subprocess.run(['sudo', 'iw', interface, 'set', 'channel', str(channel)],
                                     capture_output=True, timeout=5)

                        # Perform scan
                        result = subprocess.run(['sudo', 'iw', interface, 'scan'],
                                              capture_output=True, text=True, timeout=10)

                        if result.returncode == 0:
                            self._parse_iw_scan(result.stdout)

                        time.sleep(0.5)
                else:
                    # Scan all channels
                    result = subprocess.run(['sudo', 'iw', interface, 'scan'],
                                          capture_output=True, text=True, timeout=15)

                    if result.returncode == 0:
                        self._parse_iw_scan(result.stdout)

                time.sleep(2)

                # Update progress
                if self.on_scan_progress:
                    progress = min(100, int((time.time() - start_time) / duration * 100))
                    self.on_scan_progress(progress)

        except Exception as e:
            print(f"iw scan error: {e}")

    def _windows_scan(self, interface: str, duration: int):
        """Windows-specific scanning"""
        try:
            start_time = time.time()

            while self.scanning and time.time() - start_time < duration:
                result = subprocess.run(['netsh', 'wlan', 'show', 'networks', 'mode=bssid'],
                                      capture_output=True, text=True, timeout=15)

                if result.returncode == 0:
                    self._parse_windows_scan(result.stdout)

                time.sleep(5)  # Windows scan interval

                # Update progress
                if self.on_scan_progress:
                    progress = min(100, int((time.time() - start_time) / duration * 100))
                    self.on_scan_progress(progress)

        except Exception as e:
            print(f"Windows scan error: {e}")

    def _generic_scan(self, interface: str, duration: int):
        """Generic scanning method (limited functionality)"""
        # This is a fallback for unsupported platforms
        print(f"Generic scan on {interface} for {duration} seconds")
        time.sleep(duration)

    def _parse_airodump_csv(self, csv_file: str):
        """Parse airodump-ng CSV output"""
        if not os.path.exists(csv_file):
            return

        try:
            with open(csv_file, 'r', encoding='utf-8', errors='ignore') as f:
                lines = f.readlines()

            # Skip header lines
            data_started = False
            for line in lines:
                line = line.strip()
                if not line:
                    continue
                if line.startswith('BSSID'):
                    data_started = True
                    continue
                if data_started and ',' in line:
                    parts = line.split(',')
                    if len(parts) >= 14:
                        bssid = parts[0].strip()
                        essid = parts[13].strip()

                        if bssid and essid and essid != 'ESSID':
                            network = NetworkInfo(
                                bssid=bssid,
                                essid=essid,
                                channel=parts[3].strip(),
                                encryption=parts[5].strip() + parts[6].strip(),
                                signal=parts[8].strip(),
                                clients=int(parts[10].strip()) if parts[10].strip().isdigit() else 0
                            )

                            self.networks[bssid] = network

                            # Notify callback
                            if self.on_network_found:
                                self.on_network_found(network)

        except Exception as e:
            print(f"Error parsing airodump CSV: {e}")

    def _parse_iw_scan(self, output: str):
        """Parse iw scan output"""
        current_bssid = None
        current_network = None

        for line in output.split('\n'):
            line = line.strip()

            if line.startswith('BSS ') and '(' in line:
                # New BSS entry
                bssid_match = re.search(r'BSS ([0-9a-f:]+)', line)
                if bssid_match:
                    current_bssid = bssid_match.group(1)
                    current_network = NetworkInfo(bssid=current_bssid)

            elif current_network and line.startswith('SSID:'):
                essid = line.split(':', 1)[1].strip()
                current_network.essid = essid

            elif current_network and line.startswith('freq:'):
                freq_match = re.search(r'freq: (\d+)', line)
                if freq_match:
                    freq = int(freq_match.group(1))
                    current_network.channel = self._freq_to_channel(freq)

            elif current_network and line.startswith('signal:'):
                signal_match = re.search(r'signal: (-?\d+)', line)
                if signal_match:
                    current_network.signal = signal_match.group(1)

            elif current_network and 'WPA' in line:
                current_network.encryption = 'WPA'

            elif current_network and 'WEP' in line:
                current_network.encryption = 'WEP'

            elif current_network and 'RSN' in line:
                current_network.encryption = 'WPA2'

            elif current_network and line.startswith('WPS:'):
                current_network.wps = True

            elif current_network and line == '':  # End of BSS entry
                if current_network.essid and current_bssid:
                    self.networks[current_bssid] = current_network

                    # Notify callback
                    if self.on_network_found:
                        self.on_network_found(current_network)

                current_bssid = None
                current_network = None

    def _parse_windows_scan(self, output: str):
        """Parse Windows netsh wlan show networks output"""
        current_ssid = None
        current_network = None

        for line in output.split('\n'):
            line = line.strip()

            if line.startswith('SSID'):
                ssid_match = re.search(r'SSID\s+\d+\s*:\s*(.+)', line)
                if ssid_match:
                    current_ssid = ssid_match.group(1).strip()
                    current_network = NetworkInfo(essid=current_ssid)

            elif current_network and line.startswith('BSSID'):
                bssid_match = re.search(r'BSSID\s+\d+\s*:\s*([0-9a-f:]+)', line, re.IGNORECASE)
                if bssid_match:
                    current_network.bssid = bssid_match.group(1).upper()

            elif current_network and 'Signal' in line:
                signal_match = re.search(r'Signal\s*:\s*(\d+)', line)
                if signal_match:
                    current_network.signal = signal_match.group(1)

            elif current_network and 'Channel' in line:
                channel_match = re.search(r'Channel\s*:\s*(\d+)', line)
                if channel_match:
                    current_network.channel = channel_match.group(1)

            elif current_network and ('WPA' in line or 'WPA2' in line):
                current_network.encryption = 'WPA2'

            elif current_network and line.startswith('SSID') and current_network.bssid:
                # End of current network entry
                if current_network.bssid and current_network.essid:
                    self.networks[current_network.bssid] = current_network

                    # Notify callback
                    if self.on_network_found:
                        self.on_network_found(current_network)

                current_ssid = None
                current_network = None

    def _freq_to_channel(self, freq: int) -> str:
        """Convert frequency to channel number"""
        if 2412 <= freq <= 2484:
            return str(int((freq - 2412) / 5 + 1))
        elif 5170 <= freq <= 5825:
            return str(int((freq - 5170) / 5 + 34))
        else:
            return str(freq)

    def _cleanup_temp_files(self, files: List[str]):
        """Clean up temporary scan files"""
        for file in files:
            try:
                if os.path.exists(file):
                    os.remove(file)
            except:
                pass

    def get_networks(self) -> List[NetworkInfo]:
        """Get list of discovered networks"""
        return list(self.networks.values())

    def get_network_by_bssid(self, bssid: str) -> Optional[NetworkInfo]:
        """Get network by BSSID"""
        return self.networks.get(bssid.upper())

    def clear_networks(self):
        """Clear discovered networks"""
        self.networks.clear()

    def export_networks(self, filename: str):
        """Export networks to JSON file"""
        try:
            data = {
                'scan_time': datetime.now().isoformat(),
                'networks': [net.to_dict() for net in self.networks.values()]
            }

            with open(filename, 'w') as f:
                json.dump(data, f, indent=2)

        except Exception as e:
            print(f"Error exporting networks: {e}")

    def import_networks(self, filename: str):
        """Import networks from JSON file"""
        try:
            with open(filename, 'r') as f:
                data = json.load(f)

            for net_data in data.get('networks', []):
                network = NetworkInfo(
                    bssid=net_data['bssid'],
                    essid=net_data['essid'],
                    channel=net_data['channel'],
                    encryption=net_data['encryption'],
                    signal=net_data['signal'],
                    clients=net_data['clients']
                )

                if 'vendor' in net_data:
                    network.vendor = net_data['vendor']
                if 'wps' in net_data:
                    network.wps = net_data['wps']

                self.networks[network.bssid] = network

        except Exception as e:
            print(f"Error importing networks: {e}")


# Utility functions
def check_system_capabilities() -> Dict[str, bool]:
    """Check system capabilities for wireless operations"""
    capabilities = {
        'aircrack_ng': False,
        'hashcat': False,
        'wireshark': False,
        'monitor_mode': False,
        'packet_injection': False
    }

    # Check for tools
    tools = ['aircrack-ng', 'airodump-ng', 'aireplay-ng', 'hashcat', 'tshark']

    for tool in tools:
        try:
            result = subprocess.run(['which', tool], capture_output=True, timeout=5)
            if tool == 'aircrack-ng':
                capabilities['aircrack_ng'] = result.returncode == 0
            elif tool == 'hashcat':
                capabilities['hashcat'] = result.returncode == 0
            elif tool == 'tshark':
                capabilities['wireshark'] = result.returncode == 0
        except:
            pass

    # Check monitor mode capability
    try:
        interfaces = subprocess.run(['iwconfig'], capture_output=True, text=True, timeout=10)
        capabilities['monitor_mode'] = 'monitor' in interfaces.stdout.lower()
    except:
        pass

    return capabilities


if __name__ == "__main__":
    # Test the scanner
    scanner = NetworkScanner()

    print("Wireless interfaces:", scanner.get_wireless_interfaces())

    # Test scanning (uncomment to test)
    # def on_network_found(network):
    #     print(f"Found: {network.essid} ({network.bssid}) - Channel: {network.channel}")

    # scanner.on_network_found = on_network_found
    # scanner.start_scan("wlan0", 10)

    # while scanner.scanning:
    #     time.sleep(1)

    # print(f"Discovered {len(scanner.get_networks())} networks")

