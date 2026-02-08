# Advanced Cross-Platform WiFi Cracking Suite v1.0

Created by Ali Zafar

A comprehensive wireless network security testing toolkit built in Python. This suite provides advanced capabilities for network discovery, packet analysis, authentication cracking, and various attack techniques used in wireless security assessments. Supports both Windows and Linux platforms.

## ⚠️ Legal Disclaimer

**This tool is intended for educational and authorized security testing purposes only.** Unauthorized use of this software to access or attack wireless networks without explicit permission is illegal and unethical. Users are responsible for complying with all applicable laws and regulations. The developers assume no liability for misuse of this software.

## Features

### 🔍 Network Discovery & Scanning
- **Advanced Network Scanner**: Comprehensive wireless network discovery using multiple methods
- **Multi-platform Support**: Linux, Windows, and macOS compatibility
- **Real-time Monitoring**: Live network statistics and interface monitoring
- **Network Filtering**: Advanced filtering by encryption type, signal strength, and WPS support
- **Vendor Identification**: MAC address to vendor lookup
- **Channel Analysis**: Detailed channel utilization and interference detection

### 📡 Packet Capture & Analysis
- **Multi-format Capture**: Support for pcap, pcapng, and various capture formats
- **Advanced Packet Analysis**: Deep inspection of wireless packets
- **Protocol Decoding**: WPA/WPA2/WPA3, WPS, EAPOL, and more
- **Traffic Statistics**: Comprehensive network traffic analysis
- **Handshake Extraction**: Automated WPA handshake capture and processing
- **PMKID Detection**: Advanced PMKID attack support

### 🔐 Authentication Cracking
- **Dictionary Attacks**: High-performance wordlist-based cracking
- **Hashcat Integration**: GPU-accelerated password cracking
- **Brute Force**: Configurable brute force attacks
- **Mask Attacks**: Advanced pattern-based attacks
- **Hybrid Methods**: Combined dictionary and brute force approaches
- **Progress Tracking**: Real-time cracking progress and ETA

### ⚔️ Attack Tools
- **Deauthentication Attacks**: Targeted and broadcast deauth floods
- **Evil Twin Attacks**: Advanced AP impersonation with captive portal
- **WPS Attacks**: Pixie Dust and PIN brute force attacks
- **PMKID Attacks**: Client-less PMKID capture and cracking
- **Multi-interface Support**: Simultaneous attacks on multiple interfaces

### 🧠 Intelligence & Reporting (New)
- **Target Intelligence Engine**: Automatically scores discovered networks by encryption posture, signal quality, and client activity
- **Smart Prioritization**: Ranks top networks to focus assessment time on the highest-value targets
- **Session Report Export**: Generates portable JSON operation reports with ranked targets and environment metadata

### 🛠️ Utilities & Tools
- **Wordlist Management**: Custom wordlist creation and management
- **Capture File Processing**: Convert, merge, and analyze capture files
- **System Diagnostics**: Comprehensive tool and system capability checking
- **Configuration Management**: Advanced settings and profile management
- **Session Logging**: Detailed attack and cracking logs

## System Requirements

### Minimum Requirements
- **OS**: Windows 10+ or Linux (Ubuntu/Debian recommended)
- **Python**: 3.8 or higher
- **RAM**: 2GB minimum, 4GB recommended
- **Storage**: 500MB free space
- **Network**: Wireless adapter supporting monitor mode (Linux) or compatible WiFi adapter (Windows)

### Recommended Hardware
- **CPU**: Multi-core processor (4+ cores)
- **RAM**: 8GB or more
- **GPU**: NVIDIA/AMD GPU for hashcat acceleration
- **Wireless Adapters**:
  - Atheros AR9271 (recommended)
  - Ralink RT3070/RT3572
  - Realtek RTL8812AU/RTL8821AU

## Installation

### 1. Clone the Repository
```bash
git clone https://github.com/AliZafar780/wifi-cracking-suite.git
cd wifi-cracking-suite
```

### 2. Install Python Dependencies
```bash
pip install -r requirements.txt
```

### 3. Install System Dependencies

#### Linux (Ubuntu/Debian)
```bash
sudo apt update
sudo apt install aircrack-ng hashcat hostapd dnsmasq reaver pixiewps hcxdumptool hcxtools mdk4
```

#### Linux (Arch/Manjaro)
```bash
sudo pacman -S aircrack-ng hashcat hostapd dnsmasq reaver pixiewps hcxdumptool hcxtools mdk4
```

#### Windows
1. Install [Npcap](https://nmap.org/npcap/) (WinPcap replacement)
2. Install [Hashcat](https://hashcat.net/hashcat/)
3. Install [Aircrack-ng for Windows](https://www.aircrack-ng.org/downloads.html)
4. Install [Python for Windows](https://python.org) if not already installed

### 4. Configure Wireless Adapters

#### Linux Monitor Mode Setup
```bash
# Enable monitor mode
sudo airmon-ng start wlan0

# Check interface
iwconfig
```

## Usage

### Basic Usage
```bash
# Run the main application
python main.py

# Or run with specific configuration
python main.py --config my_config.json
```

### Command Line Options
```bash
python main.py [options]

Options:
  --config FILE      Use specific configuration file
  --interface IFACE  Specify default wireless interface
  --verbose          Enable verbose logging
  --debug           Enable debug mode
  --help            Show help message
```

## GUI Overview

### Main Interface
The application features a tabbed interface with the following sections:

1. **Network Discovery**: Scan and analyze wireless networks
2. **Attack Tools**: Execute various wireless attacks
3. **Password Cracking**: Crack captured WPA handshakes
4. **Monitoring**: Real-time network monitoring
5. **Tools**: Utilities and system diagnostics
6. **Settings**: Configuration and preferences

### Network Scanning
1. Select your wireless interface
2. Enable monitor mode if required
3. Click "Scan Networks" to discover nearby networks
4. View detailed network information and client lists

### Deauthentication Attack
1. Select target network from discovered networks
2. Choose attack parameters (count, delay, client MAC)
3. Execute attack and monitor results

### Password Cracking
1. Load capture file containing WPA handshake
2. Select wordlist or configure brute force parameters
3. Choose cracking method (dictionary, hashcat, brute force)
4. Monitor cracking progress and results

## Configuration

### Configuration File
The application uses JSON-based configuration stored in `wifi_cracker_config.json`:

```json
{
  "default_interface": "wlan0",
  "scan_timeout": 30,
  "auto_monitor_mode": true,
  "default_wordlist": "rockyou.txt",
  "theme": "dark"
}
```

### Profiles
Create different configuration profiles for various scenarios:
- **Reconnaissance**: Passive scanning focused
- **Aggressive**: Active attacks enabled
- **Stealth**: Minimal detection footprint

## Advanced Features

### Custom Wordlist Generation
```python
from password_cracker import WordlistManager

manager = WordlistManager()
manager.create_custom_wordlist("corporate", ["Company2023", "Employee", "Admin"])
```

### Automated Attack Chains
Combine multiple attacks for comprehensive testing:
1. Network discovery
2. Deauthentication to capture handshake
3. Evil twin for additional capture methods
4. Password cracking with multiple methods

### Session Management
- **Session Logging**: All activities logged with timestamps
- **Result Export**: Save findings in multiple formats
- **Session Resume**: Continue interrupted operations

## Security Best Practices

### During Use
1. **Obtain Permission**: Always get written authorization
2. **Use Isolated Networks**: Test in controlled environments
3. **Monitor Impact**: Be aware of effects on other users
4. **Secure Storage**: Encrypt sensitive data and results

### Operational Security
1. **Anonymity**: Consider VPN/Tor for sensitive operations
2. **Clean Up**: Remove temporary files and logs
3. **Secure Configs**: Don't store sensitive data in configs
4. **Regular Updates**: Keep tools and system updated

## Troubleshooting

### Common Issues

#### Monitor Mode Not Working
```bash
# Check interface capabilities
iw list

# Try alternative driver
sudo modprobe -r rtl8xxxu
sudo modprobe rtl8xxxu
```

#### Tools Not Found
```bash
# Update PATH or specify full paths in config
which aircrack-ng
export PATH=$PATH:/usr/local/sbin
```

#### Permission Errors
```bash
# Run with sudo or configure permissions
sudo python main.py

# Or add user to wireless group
sudo usermod -a -G wireshark $USER
```

#### GPU Not Detected (Hashcat)
```bash
# Install GPU drivers
nvidia-smi  # Check NVIDIA GPU
hashcat --benchmark  # Test hashcat
```

## Development

### Project Structure
```
wifi-cracking-suite/
├── main.py                 # Main application GUI
├── network_scanner.py      # Network discovery module
├── packet_analyzer.py      # Packet capture and analysis
├── password_cracker.py     # Authentication cracking
├── attack_tools.py         # Attack implementations
├── config_manager.py       # Configuration management
├── requirements.txt        # Python dependencies
├── README.md              # This file
└── profiles/              # Configuration profiles
```

### Contributing
1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests if applicable
5. Submit a pull request

### Code Standards
- Follow PEP 8 style guidelines
- Use type hints for function parameters
- Add docstrings to all functions
- Test on multiple platforms when possible

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Acknowledgments

- Aircrack-ng team for the foundation tools
- Hashcat developers for GPU acceleration
- Scapy developers for packet manipulation
- Open source wireless security community

## Support

For support, bug reports, and feature requests:
- Create an issue on GitHub
- Check the troubleshooting section
- Review the documentation

---

**Remember: With great power comes great responsibility. Use this tool ethically and legally.**

