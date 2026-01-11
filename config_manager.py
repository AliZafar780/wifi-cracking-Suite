#!/usr/bin/env python3
"""
Configuration Management Module
Handles application settings, preferences, and state persistence
"""

import json
import os
from typing import Dict, Any, Optional
from datetime import datetime
import platform


class ConfigManager:
    """Manages application configuration"""

    def __init__(self, config_file: str = "wifi_cracker_config.json"):
        self.config_file = config_file
        self.defaults = self._get_defaults()
        self.config = self.load_config()

    def _get_defaults(self) -> Dict[str, Any]:
        """Get default configuration values"""
        return {
            # Interface settings
            'default_interface': '',
            'auto_monitor_mode': True,
            'monitor_interface_suffix': 'mon',

            # Scanning settings
            'scan_timeout': 30,
            'scan_channels': [],
            'auto_scan_on_start': False,
            'scan_output_format': 'csv',

            # Attack settings
            'default_attack_interface': '',
            'deauth_count': 10,
            'deauth_delay': 0.1,
            'evil_twin_channel': 6,
            'wps_timeout': 300,
            'pmkid_timeout': 60,

            # Cracking settings
            'default_wordlist': 'rockyou.txt',
            'hashcat_mode': 'dictionary',
            'brute_force_min_length': 8,
            'brute_force_max_length': 12,
            'brute_force_charset': 'alphanumeric',
            'auto_save_results': True,

            # UI settings
            'theme': 'dark',
            'window_size': '1200x800',
            'auto_save_logs': True,
            'log_level': 'INFO',
            'max_log_entries': 1000,

            # System settings
            'temp_directory': '/tmp/wifi_cracker',
            'cleanup_temp_files': True,
            'max_temp_age_days': 7,
            'auto_update': True,

            # Advanced settings
            'experimental_features': False,
            'debug_mode': False,
            'performance_mode': 'balanced',  # balanced, speed, compatibility

            # Tool paths (auto-detected)
            'tool_paths': {
                'aircrack_ng': '',
                'aireplay_ng': '',
                'airodump_ng': '',
                'hostapd': '',
                'dnsmasq': '',
                'reaver': '',
                'pixiewps': '',
                'hcxdumptool': '',
                'hcxpcapngtool': '',
                'hashcat': '',
                'john': '',
                'mdk4': ''
            },

            # Network filters
            'network_filters': {
                'show_wps_only': False,
                'show_wpa_only': True,
                'hide_weak_signals': False,
                'min_signal_threshold': -80,
                'preferred_channels': []
            },

            # Session management
            'last_session': {
                'timestamp': None,
                'networks_scanned': 0,
                'attacks_performed': 0,
                'passwords_cracked': 0
            }
        }

    def load_config(self) -> Dict[str, Any]:
        """Load configuration from file"""
        if not os.path.exists(self.config_file):
            return self.defaults.copy()

        try:
            with open(self.config_file, 'r', encoding='utf-8') as f:
                loaded_config = json.load(f)

            # Merge with defaults to ensure all keys exist
            config = self.defaults.copy()
            self._deep_update(config, loaded_config)

            return config

        except Exception as e:
            print(f"Error loading config: {e}")
            return self.defaults.copy()

    def save_config(self) -> bool:
        """Save configuration to file"""
        try:
            # Create directory if it doesn't exist
            os.makedirs(os.path.dirname(self.config_file) if os.path.dirname(self.config_file) else '.', exist_ok=True)

            with open(self.config_file, 'w', encoding='utf-8') as f:
                json.dump(self.config, f, indent=2, ensure_ascii=False)

            return True

        except Exception as e:
            print(f"Error saving config: {e}")
            return False

    def _deep_update(self, base_dict: Dict, update_dict: Dict):
        """Deep update dictionary"""
        for key, value in update_dict.items():
            if isinstance(value, dict) and key in base_dict and isinstance(base_dict[key], dict):
                self._deep_update(base_dict[key], value)
            else:
                base_dict[key] = value

    def get(self, key: str, default: Any = None) -> Any:
        """Get configuration value"""
        keys = key.split('.')
        value = self.config

        for k in keys:
            if isinstance(value, dict) and k in value:
                value = value[k]
            else:
                return default

        return value

    def set(self, key: str, value: Any) -> bool:
        """Set configuration value"""
        keys = key.split('.')
        config = self.config

        # Navigate to the parent of the target key
        for k in keys[:-1]:
            if k not in config or not isinstance(config[k], dict):
                config[k] = {}
            config = config[k]

        # Set the value
        config[keys[-1]] = value
        return self.save_config()

    def reset_to_defaults(self) -> bool:
        """Reset configuration to defaults"""
        self.config = self.defaults.copy()
        return self.save_config()

    def export_config(self, filename: str) -> bool:
        """Export configuration to file"""
        try:
            with open(filename, 'w', encoding='utf-8') as f:
                json.dump(self.config, f, indent=2, ensure_ascii=False)
            return True
        except Exception as e:
            print(f"Error exporting config: {e}")
            return False

    def import_config(self, filename: str) -> bool:
        """Import configuration from file"""
        try:
            with open(filename, 'r', encoding='utf-8') as f:
                imported_config = json.load(f)

            self._deep_update(self.config, imported_config)
            return self.save_config()

        except Exception as e:
            print(f"Error importing config: {e}")
            return False

    def detect_tool_paths(self) -> Dict[str, str]:
        """Auto-detect tool paths"""
        import subprocess

        tools = [
            'aircrack-ng', 'aireplay-ng', 'airodump-ng', 'hostapd', 'dnsmasq',
            'reaver', 'pixiewps', 'hcxdumptool', 'hcxpcapngtool', 'hashcat',
            'john', 'mdk4'
        ]

        detected_paths = {}

        for tool in tools:
            try:
                result = subprocess.run(['which', tool], capture_output=True,
                                      text=True, timeout=5)
                if result.returncode == 0:
                    detected_paths[tool] = result.stdout.strip()
                else:
                    detected_paths[tool] = ''
            except:
                detected_paths[tool] = ''

        self.config['tool_paths'] = detected_paths
        self.save_config()

        return detected_paths

    def validate_tools(self) -> Dict[str, bool]:
        """Validate that configured tools exist and are executable"""
        import subprocess

        validation = {}
        tool_paths = self.config.get('tool_paths', {})

        for tool, path in tool_paths.items():
            if path and os.path.exists(path) and os.access(path, os.X_OK):
                validation[tool] = True
            elif path:  # Path configured but invalid
                validation[tool] = False
            else:
                # Try to find in PATH
                try:
                    result = subprocess.run(['which', tool], capture_output=True, timeout=5)
                    validation[tool] = result.returncode == 0
                except:
                    validation[tool] = False

        return validation

    def get_system_info(self) -> Dict[str, Any]:
        """Get system information for configuration context"""
        return {
            'platform': platform.system(),
            'platform_version': platform.release(),
            'architecture': platform.machine(),
            'python_version': platform.python_version(),
            'hostname': platform.node()
        }

    def update_session_stats(self, networks_scanned: int = 0, attacks_performed: int = 0,
                           passwords_cracked: int = 0):
        """Update session statistics"""
        session = self.config.get('last_session', {})
        session.update({
            'timestamp': datetime.now().isoformat(),
            'networks_scanned': networks_scanned,
            'attacks_performed': attacks_performed,
            'passwords_cracked': passwords_cracked
        })
        self.config['last_session'] = session
        self.save_config()

    def get_session_stats(self) -> Dict[str, Any]:
        """Get last session statistics"""
        return self.config.get('last_session', {})

    def add_recent_network(self, bssid: str, essid: str, encryption: str):
        """Add network to recently seen list"""
        recent_networks = self.config.get('recent_networks', [])

        # Check if network already exists
        for network in recent_networks:
            if network['bssid'] == bssid:
                network['last_seen'] = datetime.now().isoformat()
                break
        else:
            # Add new network
            network_info = {
                'bssid': bssid,
                'essid': essid,
                'encryption': encryption,
                'first_seen': datetime.now().isoformat(),
                'last_seen': datetime.now().isoformat()
            }
            recent_networks.append(network_info)

        # Keep only recent networks (limit to 100)
        if len(recent_networks) > 100:
            recent_networks = recent_networks[-100:]

        self.config['recent_networks'] = recent_networks
        self.save_config()

    def get_recent_networks(self) -> list:
        """Get recently seen networks"""
        return self.config.get('recent_networks', [])

    def clear_recent_networks(self):
        """Clear recent networks list"""
        self.config['recent_networks'] = []
        self.save_config()

    def add_favorite_wordlist(self, path: str, name: str = ""):
        """Add wordlist to favorites"""
        if not name:
            name = os.path.basename(path)

        favorites = self.config.get('favorite_wordlists', [])

        # Check if already exists
        for fav in favorites:
            if fav['path'] == path:
                return

        favorites.append({
            'name': name,
            'path': path,
            'added': datetime.now().isoformat()
        })

        self.config['favorite_wordlists'] = favorites
        self.save_config()

    def get_favorite_wordlists(self) -> list:
        """Get favorite wordlists"""
        return self.config.get('favorite_wordlists', [])

    def remove_favorite_wordlist(self, path: str):
        """Remove wordlist from favorites"""
        favorites = self.config.get('favorite_wordlists', [])
        self.config['favorite_wordlists'] = [f for f in favorites if f['path'] != path]
        self.save_config()

    def get_performance_settings(self) -> Dict[str, Any]:
        """Get performance-related settings"""
        return {
            'performance_mode': self.get('performance_mode', 'balanced'),
            'max_threads': self.get('max_threads', 4),
            'memory_limit': self.get('memory_limit', 512),  # MB
            'temp_cleanup_interval': self.get('temp_cleanup_interval', 3600)  # seconds
        }

    def set_performance_settings(self, mode: str = 'balanced', max_threads: int = 4,
                               memory_limit: int = 512):
        """Set performance settings"""
        self.set('performance_mode', mode)
        self.set('max_threads', max_threads)
        self.set('memory_limit', memory_limit)

    def get_network_filters(self) -> Dict[str, Any]:
        """Get network filtering settings"""
        return self.config.get('network_filters', self.defaults['network_filters'])

    def set_network_filters(self, filters: Dict[str, Any]):
        """Set network filtering settings"""
        current_filters = self.config.get('network_filters', {})
        current_filters.update(filters)
        self.config['network_filters'] = current_filters
        self.save_config()

    def backup_config(self, backup_file: str = "") -> bool:
        """Create configuration backup"""
        if not backup_file:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            backup_file = f"wifi_cracker_config_backup_{timestamp}.json"

        return self.export_config(backup_file)

    def restore_config(self, backup_file: str) -> bool:
        """Restore configuration from backup"""
        return self.import_config(backup_file)

    def get_config_summary(self) -> Dict[str, Any]:
        """Get configuration summary for display"""
        return {
            'config_file': self.config_file,
            'last_modified': datetime.fromtimestamp(os.path.getmtime(self.config_file)).isoformat() if os.path.exists(self.config_file) else None,
            'tool_validation': self.validate_tools(),
            'system_info': self.get_system_info(),
            'session_stats': self.get_session_stats(),
            'favorite_wordlists_count': len(self.get_favorite_wordlists()),
            'recent_networks_count': len(self.get_recent_networks())
        }


class ProfileManager:
    """Manages configuration profiles for different use cases"""

    def __init__(self, config_dir: str = "profiles"):
        self.config_dir = config_dir
        self.current_profile = "default"
        os.makedirs(config_dir, exist_ok=True)

    def create_profile(self, name: str, base_config: Optional[Dict] = None) -> bool:
        """Create a new configuration profile"""
        if not base_config:
            base_config = {}

        profile_file = os.path.join(self.config_dir, f"{name}.json")

        try:
            with open(profile_file, 'w', encoding='utf-8') as f:
                json.dump(base_config, f, indent=2, ensure_ascii=False)
            return True
        except Exception as e:
            print(f"Error creating profile {name}: {e}")
            return False

    def load_profile(self, name: str) -> Optional[Dict]:
        """Load a configuration profile"""
        profile_file = os.path.join(self.config_dir, f"{name}.json")

        if not os.path.exists(profile_file):
            return None

        try:
            with open(profile_file, 'r', encoding='utf-8') as f:
                return json.load(f)
        except Exception as e:
            print(f"Error loading profile {name}: {e}")
            return None

    def save_profile(self, name: str, config: Dict) -> bool:
        """Save configuration to profile"""
        profile_file = os.path.join(self.config_dir, f"{name}.json")

        try:
            with open(profile_file, 'w', encoding='utf-8') as f:
                json.dump(config, f, indent=2, ensure_ascii=False)
            return True
        except Exception as e:
            print(f"Error saving profile {name}: {e}")
            return False

    def delete_profile(self, name: str) -> bool:
        """Delete a configuration profile"""
        profile_file = os.path.join(self.config_dir, f"{name}.json")

        try:
            if os.path.exists(profile_file):
                os.remove(profile_file)
            return True
        except Exception as e:
            print(f"Error deleting profile {name}: {e}")
            return False

    def list_profiles(self) -> list:
        """List available profiles"""
        profiles = []
        if os.path.exists(self.config_dir):
            for file in os.listdir(self.config_dir):
                if file.endswith('.json'):
                    profiles.append(file[:-5])  # Remove .json extension
        return profiles

    def get_current_profile(self) -> str:
        """Get current profile name"""
        return self.current_profile

    def set_current_profile(self, name: str):
        """Set current profile name"""
        self.current_profile = name


# Utility functions
def create_default_wordlists():
    """Create some default wordlists if they don't exist"""
    default_wordlists = {
        'common_passwords.txt': [
            'password', '123456', '123456789', 'admin', 'welcome', 'qwerty',
            'abc123', 'password123', 'admin123', 'root', 'user', 'guest'
        ],
        'numeric_4digit.txt': [f"{i:04d}" for i in range(10000)],
        'numeric_6digit.txt': [f"{i:06d}" for i in range(1000000)]
    }

    for filename, words in default_wordlists.items():
        if not os.path.exists(filename):
            try:
                with open(filename, 'w') as f:
                    for word in words:
                        f.write(word + '\n')
                print(f"Created default wordlist: {filename}")
            except Exception as e:
                print(f"Error creating {filename}: {e}")


def migrate_old_config(old_config_file: str, new_config: ConfigManager):
    """Migrate configuration from old format"""
    if not os.path.exists(old_config_file):
        return False

    try:
        with open(old_config_file, 'r') as f:
            old_config = json.load(f)

        # Apply migrations based on old format
        # This would be customized based on actual old format

        print(f"Migrated config from {old_config_file}")
        return True

    except Exception as e:
        print(f"Error migrating config: {e}")
        return False


if __name__ == "__main__":
    # Test configuration manager
    config = ConfigManager()

    print("Default interface:", config.get('default_interface'))
    print("Scan timeout:", config.get('scan_timeout'))

    # Test setting values
    config.set('test_key', 'test_value')
    print("Test value:", config.get('test_key'))

    # Test tool detection
    tools = config.detect_tool_paths()
    print("Detected tools:", tools)

    # Test validation
    validation = config.validate_tools()
    print("Tool validation:", validation)

    # Create default wordlists
    create_default_wordlists()

