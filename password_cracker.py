#!/usr/bin/env python3
"""
Advanced Password Cracking Module
Handles WPA/WPA2/WPA3 password cracking using various methods
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
import hashlib
import itertools
import string
from concurrent.futures import ThreadPoolExecutor, as_completed


class CrackResult:
    """Represents a password cracking result"""

    def __init__(self, bssid: str = "", essid: str = "", password: str = "",
                 method: str = "", time_taken: float = 0, found: bool = False):
        self.bssid = bssid
        self.essid = essid
        self.password = password
        self.method = method
        self.time_taken = time_taken
        self.found = found
        self.timestamp = datetime.now()

    def to_dict(self) -> dict:
        """Convert to dictionary"""
        return {
            'bssid': self.bssid,
            'essid': self.essid,
            'password': self.password,
            'method': self.method,
            'time_taken': self.time_taken,
            'found': self.found,
            'timestamp': self.timestamp.isoformat()
        }


class PasswordCracker:
    """Advanced password cracking engine"""

    def __init__(self):
        self.cracking = False
        self.crack_thread: Optional[threading.Thread] = None
        self.on_progress: Optional[Callable] = None
        self.on_found: Optional[Callable] = None
        self.results: List[CrackResult] = []

    def crack_wpa_handshake(self, capture_file: str, wordlist: str = "",
                           method: str = "dictionary", bssid: str = "",
                           essid: str = "") -> Optional[CrackResult]:
        """Crack WPA handshake using specified method"""
        if self.cracking:
            return None

        self.cracking = True
        result = None

        try:
            if method == "dictionary":
                result = self._dictionary_attack(capture_file, wordlist, bssid, essid)
            elif method == "brute_force":
                result = self._brute_force_attack(capture_file, bssid, essid)
            elif method == "hashcat":
                result = self._hashcat_attack(capture_file, wordlist, bssid, essid)
            elif method == "mask_attack":
                result = self._mask_attack(capture_file, bssid, essid)
            else:
                print(f"Unknown method: {method}")

        except Exception as e:
            print(f"Cracking error: {e}")
        finally:
            self.cracking = False

        if result:
            self.results.append(result)

        return result

    def _dictionary_attack(self, capture_file: str, wordlist: str,
                          bssid: str, essid: str) -> Optional[CrackResult]:
        """Perform dictionary attack using aircrack-ng"""
        if not os.path.exists(wordlist):
            raise FileNotFoundError(f"Wordlist not found: {wordlist}")

        start_time = time.time()

        try:
            # Use aircrack-ng for dictionary attack
            cmd = ['aircrack-ng', '-w', wordlist, '-b', bssid, capture_file]

            process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                     universal_newlines=True)

            password_found = None
            progress = 0

            while self.cracking and process.poll() is None:
                time.sleep(0.1)

                # Check for completion or password found
                if process.poll() is not None:
                    output, error = process.communicate()

                    # Check if password was found
                    if "KEY FOUND" in output:
                        # Extract password
                        lines = output.split('\n')
                        for line in lines:
                            if "KEY FOUND" in line:
                                # Look for password in following lines
                                idx = lines.index(line)
                                for i in range(idx + 1, min(idx + 5, len(lines))):
                                    if '[' in lines[i] and ']' in lines[i]:
                                        password_match = re.search(r'\[ ([^\]]+) \]', lines[i])
                                        if password_match:
                                            password_found = password_match.group(1).strip()
                                            break
                                break

                    break

                # Update progress (estimate)
                elapsed = time.time() - start_time
                progress = min(95, int(elapsed / 300 * 100))  # Assume 5 min max

                if self.on_progress:
                    self.on_progress(progress)

            time_taken = time.time() - start_time

            result = CrackResult(
                bssid=bssid,
                essid=essid,
                password=password_found or "",
                method="Dictionary Attack",
                time_taken=time_taken,
                found=password_found is not None
            )

            if password_found and self.on_found:
                self.on_found(result)

            return result

        except Exception as e:
            print(f"Dictionary attack error: {e}")
            return None

    def _hashcat_attack(self, capture_file: str, wordlist: str = "",
                       bssid: str = "", essid: str = "") -> Optional[CrackResult]:
        """Perform cracking using hashcat"""
        start_time = time.time()

        try:
            # First convert capture to hccapx format
            hccapx_file = f"hashcat_{bssid.replace(':', '')}.hccapx"

            convert_cmd = ['hcxpcapngtool', '-o', hccapx_file, capture_file]
            convert_result = subprocess.run(convert_cmd, capture_output=True, timeout=30)

            if convert_result.returncode != 0:
                # Try alternative conversion
                convert_cmd = ['wpaclean', 'temp.cap', capture_file]
                convert_result = subprocess.run(convert_cmd, capture_output=True, timeout=30)

                if convert_result.returncode == 0:
                    convert_cmd = ['aircrack-ng', 'temp.cap', '-J', 'hashcat_hash']
                    subprocess.run(convert_cmd, capture_output=True, timeout=30)
                    hccapx_file = 'hashcat_hash.hccapx'

            if not os.path.exists(hccapx_file):
                print("Failed to convert capture file")
                return None

            # Run hashcat
            cmd = ['hashcat', '-m', '2500', hccapx_file]

            if wordlist and os.path.exists(wordlist):
                cmd.append(wordlist)

            process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                     universal_newlines=True)

            password_found = None
            progress = 0

            while self.cracking and process.poll() is None:
                time.sleep(0.5)

                # Check hashcat output for progress and results
                if process.poll() is not None:
                    output, error = process.communicate()

                    # Check if password was found
                    if "STATUS" in output and "Cracked" in output:
                        # Parse hashcat output for found passwords
                        lines = output.split('\n')
                        for line in lines:
                            if ':' in line and len(line.split(':')) >= 6:
                                parts = line.split(':')
                                if len(parts) >= 6:
                                    password_found = ':'.join(parts[5:])  # Password is after hash
                                    break

                    break

                # Update progress (hashcat shows progress in output)
                try:
                    # Try to get progress from hashcat status
                    status_cmd = ['hashcat', '--status']
                    status_result = subprocess.run(status_cmd, capture_output=True, text=True, timeout=5)
                    if status_result.returncode == 0:
                        progress_match = re.search(r'Progress\.+:\s*(\d+)%', status_result.stdout)
                        if progress_match:
                            progress = int(progress_match.group(1))
                    else:
                        elapsed = time.time() - start_time
                        progress = min(95, int(elapsed / 600 * 100))  # Assume 10 min max
                except:
                    pass

                if self.on_progress:
                    self.on_progress(progress)

            time_taken = time.time() - start_time

            # Clean up
            try:
                os.remove(hccapx_file)
            except:
                pass

            result = CrackResult(
                bssid=bssid,
                essid=essid,
                password=password_found or "",
                method="Hashcat",
                time_taken=time_taken,
                found=password_found is not None
            )

            if password_found and self.on_found:
                self.on_found(result)

            return result

        except Exception as e:
            print(f"Hashcat attack error: {e}")
            return None

    def _brute_force_attack(self, capture_file: str, bssid: str, essid: str,
                           min_length: int = 8, max_length: int = 12,
                           charset: str = "ascii_lowercase") -> Optional[CrackResult]:
        """Perform brute force attack"""
        start_time = time.time()

        try:
            # Generate character set
            if charset == "numeric":
                chars = string.digits
            elif charset == "lowercase":
                chars = string.ascii_lowercase
            elif charset == "uppercase":
                chars = string.ascii_uppercase
            elif charset == "letters":
                chars = string.ascii_letters
            elif charset == "alphanumeric":
                chars = string.ascii_letters + string.digits
            else:  # ascii_lowercase
                chars = string.ascii_lowercase

            # Convert capture to hash format first
            hash_file = self._convert_to_hash(capture_file, bssid)
            if not hash_file:
                return None

            total_combinations = sum(len(chars) ** i for i in range(min_length, max_length + 1))
            tested = 0
            password_found = None

            # Try passwords of increasing length
            for length in range(min_length, max_length + 1):
                if not self.cracking:
                    break

                for password_tuple in itertools.product(chars, repeat=length):
                    if not self.cracking:
                        break

                    password = ''.join(password_tuple)
                    tested += 1

                    # Test password (this is very slow, just for demonstration)
                    if self._test_password(hash_file, password):
                        password_found = password
                        break

                    # Update progress
                    progress = min(95, int(tested / total_combinations * 100))
                    if self.on_progress:
                        self.on_progress(progress)

                if password_found:
                    break

            time_taken = time.time() - start_time

            result = CrackResult(
                bssid=bssid,
                essid=essid,
                password=password_found or "",
                method="Brute Force",
                time_taken=time_taken,
                found=password_found is not None
            )

            if password_found and self.on_found:
                self.on_found(result)

            # Clean up
            try:
                os.remove(hash_file)
            except:
                pass

            return result

        except Exception as e:
            print(f"Brute force attack error: {e}")
            return None

    def _mask_attack(self, capture_file: str, bssid: str, essid: str,
                    mask: str = "?a?a?a?a?a?a?a?a") -> Optional[CrackResult]:
        """Perform mask attack using hashcat"""
        start_time = time.time()

        try:
            # Convert capture to hccapx format
            hccapx_file = f"mask_{bssid.replace(':', '')}.hccapx"

            convert_cmd = ['hcxpcapngtool', '-o', hccapx_file, capture_file]
            subprocess.run(convert_cmd, capture_output=True, timeout=30)

            if not os.path.exists(hccapx_file):
                return None

            # Run hashcat with mask
            cmd = ['hashcat', '-m', '2500', '-a', '3', hccapx_file, mask]

            process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                     universal_newlines=True)

            password_found = None
            progress = 0

            while self.cracking and process.poll() is None:
                time.sleep(1)

                if process.poll() is not None:
                    output, error = process.communicate()

                    # Check for found password
                    if "STATUS" in output and "Cracked" in output:
                        lines = output.split('\n')
                        for line in lines:
                            if ':' in line and len(line.split(':')) >= 6:
                                parts = line.split(':')
                                password_found = ':'.join(parts[5:])
                                break

                    break

                # Update progress
                elapsed = time.time() - start_time
                progress = min(95, int(elapsed / 300 * 100))  # Estimate

                if self.on_progress:
                    self.on_progress(progress)

            time_taken = time.time() - start_time

            # Clean up
            try:
                os.remove(hccapx_file)
            except:
                pass

            result = CrackResult(
                bssid=bssid,
                essid=essid,
                password=password_found or "",
                method="Mask Attack",
                time_taken=time_taken,
                found=password_found is not None
            )

            if password_found and self.on_found:
                self.on_found(result)

            return result

        except Exception as e:
            print(f"Mask attack error: {e}")
            return None

    def _convert_to_hash(self, capture_file: str, bssid: str) -> Optional[str]:
        """Convert capture file to hash format for testing"""
        # This is a simplified version - in practice, you'd extract the actual PMK
        hash_file = f"temp_hash_{bssid.replace(':', '')}.txt"

        try:
            # Use aircrack-ng to extract hash
            cmd = ['aircrack-ng', capture_file, '-J', hash_file.replace('.txt', '')]
            result = subprocess.run(cmd, capture_output=True, timeout=30)

            if result.returncode == 0:
                return hash_file
            else:
                return None

        except Exception as e:
            print(f"Hash conversion error: {e}")
            return None

    def _test_password(self, hash_file: str, password: str) -> bool:
        """Test a single password against hash"""
        # This is a placeholder - actual implementation would test against WPA hash
        # In practice, this would be very slow without GPU acceleration
        time.sleep(0.001)  # Simulate testing time
        return False  # Always return false for demo

    def crack_pmkid(self, pmkid_file: str, wordlist: str = "",
                   bssid: str = "", essid: str = "") -> Optional[CrackResult]:
        """Crack PMKID using hashcat"""
        start_time = time.time()

        try:
            # PMKID files are usually in 16800 format for hashcat
            cmd = ['hashcat', '-m', '16800', pmkid_file]

            if wordlist and os.path.exists(wordlist):
                cmd.append(wordlist)

            process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                     universal_newlines=True)

            password_found = None
            progress = 0

            while self.cracking and process.poll() is None:
                time.sleep(1)

                if process.poll() is not None:
                    output, error = process.communicate()

                    # Check for found password
                    if "STATUS" in output and "Cracked" in output:
                        lines = output.split('\n')
                        for line in lines:
                            if ':' in line:
                                parts = line.split(':')
                                if len(parts) >= 2:
                                    password_found = parts[1]
                                    break

                    break

                # Update progress
                elapsed = time.time() - start_time
                progress = min(95, int(elapsed / 300 * 100))

                if self.on_progress:
                    self.on_progress(progress)

            time_taken = time.time() - start_time

            result = CrackResult(
                bssid=bssid,
                essid=essid,
                password=password_found or "",
                method="PMKID Attack",
                time_taken=time_taken,
                found=password_found is not None
            )

            if password_found and self.on_found:
                self.on_found(result)

            return result

        except Exception as e:
            print(f"PMKID cracking error: {e}")
            return None

    def stop_cracking(self):
        """Stop current cracking operation"""
        self.cracking = False
        if self.crack_thread and self.crack_thread.is_alive():
            self.crack_thread.join(timeout=5)

    def get_results(self) -> List[CrackResult]:
        """Get all cracking results"""
        return self.results.copy()

    def save_results(self, filename: str):
        """Save results to JSON file"""
        try:
            data = {
                'timestamp': datetime.now().isoformat(),
                'results': [r.to_dict() for r in self.results]
            }

            with open(filename, 'w') as f:
                json.dump(data, f, indent=2)

        except Exception as e:
            print(f"Error saving results: {e}")

    def load_results(self, filename: str):
        """Load results from JSON file"""
        try:
            with open(filename, 'r') as f:
                data = json.load(f)

            self.results = []
            for r_data in data.get('results', []):
                result = CrackResult(
                    bssid=r_data['bssid'],
                    essid=r_data['essid'],
                    password=r_data['password'],
                    method=r_data['method'],
                    time_taken=r_data['time_taken'],
                    found=r_data['found']
                )
                result.timestamp = datetime.fromisoformat(r_data['timestamp'])
                self.results.append(result)

        except Exception as e:
            print(f"Error loading results: {e}")


class WordlistManager:
    """Manages password wordlists"""

    def __init__(self):
        self.wordlists = {}
        self.custom_lists = []

    def load_wordlist(self, filename: str, name: str = "") -> bool:
        """Load a wordlist file"""
        if not os.path.exists(filename):
            return False

        if not name:
            name = os.path.basename(filename)

        try:
            with open(filename, 'r', encoding='utf-8', errors='ignore') as f:
                words = [line.strip() for line in f if line.strip()]

            self.wordlists[name] = {
                'filename': filename,
                'words': words,
                'count': len(words)
            }

            return True

        except Exception as e:
            print(f"Error loading wordlist {filename}: {e}")
            return False

    def create_custom_wordlist(self, name: str, base_words: List[str] = None,
                              rules: List[str] = None) -> bool:
        """Create a custom wordlist with transformations"""
        if not base_words:
            base_words = ["password", "admin", "123456", "welcome"]

        if not rules:
            rules = ["", "123", "!", "@", "2019", "2020", "2021"]

        transformed_words = set()

        for word in base_words:
            transformed_words.add(word)
            transformed_words.add(word.upper())
            transformed_words.add(word.lower())
            transformed_words.add(word.capitalize())

            # Apply rules
            for rule in rules:
                transformed_words.add(word + rule)
                transformed_words.add(rule + word)

        # Leet speak transformations
        leet_map = {'a': '4', 'e': '3', 'i': '1', 'o': '0', 's': '5', 't': '7'}
        for word in list(transformed_words):
            leet_word = ''.join(leet_map.get(c.lower(), c) for c in word)
            transformed_words.add(leet_word)

        wordlist_data = {
            'filename': f"{name}.txt",
            'words': list(transformed_words),
            'count': len(transformed_words)
        }

        self.wordlists[name] = wordlist_data
        self.custom_lists.append(name)

        # Save to file
        try:
            with open(wordlist_data['filename'], 'w') as f:
                for word in transformed_words:
                    f.write(word + '\n')
            return True
        except Exception as e:
            print(f"Error saving custom wordlist: {e}")
            return False

    def combine_wordlists(self, names: List[str], output_name: str) -> bool:
        """Combine multiple wordlists"""
        combined_words = set()

        for name in names:
            if name in self.wordlists:
                combined_words.update(self.wordlists[name]['words'])

        if not combined_words:
            return False

        combined_data = {
            'filename': f"{output_name}.txt",
            'words': list(combined_words),
            'count': len(combined_words)
        }

        self.wordlists[output_name] = combined_data

        # Save to file
        try:
            with open(combined_data['filename'], 'w') as f:
                for word in combined_words:
                    f.write(word + '\n')
            return True
        except Exception as e:
            print(f"Error saving combined wordlist: {e}")
            return False

    def filter_wordlist(self, input_name: str, output_name: str,
                       min_length: int = 0, max_length: int = 0,
                       contains: str = "", pattern: str = "") -> bool:
        """Filter wordlist based on criteria"""
        if input_name not in self.wordlists:
            return False

        words = self.wordlists[input_name]['words']
        filtered_words = []

        for word in words:
            # Length filter
            if min_length and len(word) < min_length:
                continue
            if max_length and len(word) > max_length:
                continue

            # Contains filter
            if contains and contains not in word:
                continue

            # Pattern filter (regex)
            if pattern:
                try:
                    if not re.search(pattern, word):
                        continue
                except:
                    continue

            filtered_words.append(word)

        if not filtered_words:
            return False

        filtered_data = {
            'filename': f"{output_name}.txt",
            'words': filtered_words,
            'count': len(filtered_words)
        }

        self.wordlists[output_name] = filtered_data

        # Save to file
        try:
            with open(filtered_data['filename'], 'w') as f:
                for word in filtered_words:
                    f.write(word + '\n')
            return True
        except Exception as e:
            print(f"Error saving filtered wordlist: {e}")
            return False

    def get_wordlist_info(self, name: str) -> Optional[Dict]:
        """Get information about a wordlist"""
        return self.wordlists.get(name)

    def list_wordlists(self) -> List[str]:
        """List all loaded wordlists"""
        return list(self.wordlists.keys())

    def clean_wordlists(self):
        """Remove temporary/custom wordlists"""
        for name in self.custom_lists:
            if name in self.wordlists:
                filename = self.wordlists[name]['filename']
                try:
                    if os.path.exists(filename):
                        os.remove(filename)
                except:
                    pass
                del self.wordlists[name]

        self.custom_lists.clear()


# Utility functions
def generate_brute_force_list(min_length: int = 8, max_length: int = 10,
                             charset: str = "alphanumeric", output_file: str = "") -> List[str]:
    """Generate a brute force wordlist"""
    if charset == "numeric":
        chars = string.digits
    elif charset == "lowercase":
        chars = string.ascii_lowercase
    elif charset == "uppercase":
        chars = string.ascii_uppercase
    elif charset == "letters":
        chars = string.ascii_letters
    else:  # alphanumeric
        chars = string.ascii_letters + string.digits

    words = []

    for length in range(min_length, max_length + 1):
        for combo in itertools.product(chars, repeat=length):
            word = ''.join(combo)
            words.append(word)

            # Limit size for practicality
            if len(words) >= 1000000:  # 1M combinations max
                break
        if len(words) >= 1000000:
            break

    if output_file:
        try:
            with open(output_file, 'w') as f:
                for word in words:
                    f.write(word + '\n')
        except Exception as e:
            print(f"Error saving brute force list: {e}")

    return words


def check_cracking_capabilities() -> Dict[str, bool]:
    """Check available cracking tools"""
    capabilities = {
        'aircrack_ng': False,
        'hashcat': False,
        'john': False,
        'pyrit': False,
        'cowpatty': False
    }

    tools = ['aircrack-ng', 'hashcat', 'john', 'pyrit', 'cowpatty']

    for tool in tools:
        try:
            result = subprocess.run([tool, '--help'], capture_output=True, timeout=5)
            capabilities[tool.replace('-', '_')] = result.returncode == 0
        except:
            pass

    return capabilities


if __name__ == "__main__":
    # Test password cracker
    cracker = PasswordCracker()

    # Check capabilities
    caps = check_cracking_capabilities()
    print("Available tools:", caps)

    # Test wordlist manager
    manager = WordlistManager()
    manager.create_custom_wordlist("test_list", ["password", "admin", "welcome"])
    print(f"Created wordlist with {manager.get_wordlist_info('test_list')['count']} words")

