#!/usr/bin/env python3
"""
Advanced Cross-Platform WiFi Cracking Suite v1.0
Created by Ali Zafar
"""

import tkinter as tk
from tkinter import ttk, messagebox, scrolledtext, filedialog
import threading
import subprocess
import os
import sys
import json
import time
from datetime import datetime
import platform
import psutil

from network_scanner import NetworkScanner
from packet_analyzer import PacketCapture, PacketAnalyzer
from password_cracker import PasswordCracker, WordlistManager
from attack_tools import AttackManager
from config_manager import ConfigManager

class WiFiCrackingSuite:
    def __init__(self):
        self.root = tk.Tk()
        self.root.title("Advanced Cross-Platform WiFi Cracking Suite v1.0 - By Ali Zafar")
        self.root.geometry("1400x900")
        self.root.configure(bg='#1a1a1a')

        self.config = ConfigManager()
        self.scanner = NetworkScanner()
        self.capture = PacketCapture()
        self.cracker = PasswordCracker()
        self.attacks = AttackManager()
        self.wordlists = WordlistManager()

        self.current_interface = None
        self.monitor_mode = False
        self.is_scanning = False
        self.is_attacking = False
        self.is_cracking = False
        self.is_monitoring = False

        self.setup_ui()
        self.load_config()
        self.check_requirements()

    def setup_ui(self):
        style = ttk.Style()
        style.configure("TNotebook.Tab", padding=[10, 5])

        self.notebook = ttk.Notebook(self.root)
        self.notebook.pack(fill='both', expand=True, padx=10, pady=10)

        tabs = [
            ("Network Discovery", self.setup_network_tab),
            ("Attack Tools", self.setup_attack_tab),
            ("Password Cracking", self.setup_crack_tab),
            ("Monitoring", self.setup_monitor_tab),
            ("Tools", self.setup_tools_tab),
            ("Settings", self.setup_settings_tab)
        ]

        for name, setup_func in tabs:
            frame = ttk.Frame(self.notebook)
            self.notebook.add(frame, text=name)
            setattr(self, f"{name.lower().replace(' ', '_')}_tab", frame)
            setup_func()

        self.status_var = tk.StringVar(value="Ready")
        status_bar = ttk.Label(self.root, textvariable=self.status_var, relief=tk.SUNKEN)
        status_bar.pack(side=tk.BOTTOM, fill=tk.X)

    def setup_network_tab(self):
        tab = getattr(self, 'network_discovery_tab')

        interface_frame = ttk.LabelFrame(tab, text="Wireless Interface")
        interface_frame.pack(fill='x', padx=10, pady=5)

        ttk.Label(interface_frame, text="Interface:").grid(row=0, column=0, padx=5, pady=5)
        self.interface_combo = ttk.Combobox(interface_frame, values=self.scanner.get_wireless_interfaces())
        self.interface_combo.grid(row=0, column=1, padx=5, pady=5)

        self.monitor_btn = ttk.Button(interface_frame, text="Enable Monitor Mode", command=self.toggle_monitor_mode)
        self.monitor_btn.grid(row=0, column=2, padx=5, pady=5)

        scan_frame = ttk.LabelFrame(tab, text="Network Scanning")
        scan_frame.pack(fill='x', padx=10, pady=5)

        self.scan_btn = ttk.Button(scan_frame, text="Scan Networks", command=self.scan_networks)
        self.scan_btn.pack(side=tk.LEFT, padx=5, pady=5)

        self.stop_scan_btn = ttk.Button(scan_frame, text="Stop Scan", command=self.stop_scan, state='disabled')
        self.stop_scan_btn.pack(side=tk.LEFT, padx=5, pady=5)

        self.scan_progress = ttk.Progressbar(scan_frame, mode='indeterminate')
        self.scan_progress.pack(side=tk.LEFT, fill='x', expand=True, padx=5, pady=5)

        list_frame = ttk.LabelFrame(tab, text="Discovered Networks")
        list_frame.pack(fill='both', expand=True, padx=10, pady=5)

        columns = ('BSSID', 'ESSID', 'Channel', 'Encryption', 'Signal', 'Clients')
        self.network_tree = ttk.Treeview(list_frame, columns=columns, show='headings', height=15)

        for col in columns:
            self.network_tree.heading(col, text=col, command=lambda c=col: self.sort_networks(c))
            self.network_tree.column(col, width=120 if col in ['BSSID', 'ESSID'] else 80)

        scrollbar = ttk.Scrollbar(list_frame, orient=tk.VERTICAL, command=self.network_tree.yview)
        self.network_tree.configure(yscrollcommand=scrollbar.set)

        self.network_tree.pack(side=tk.LEFT, fill='both', expand=True)
        scrollbar.pack(side=tk.RIGHT, fill='y')

        details_frame = ttk.LabelFrame(tab, text="Network Details")
        details_frame.pack(fill='x', padx=10, pady=5)

        self.details_text = scrolledtext.ScrolledText(details_frame, height=6, wrap=tk.WORD)
        self.details_text.pack(fill='both', expand=True, padx=5, pady=5)

        self.network_tree.bind('<<TreeviewSelect>>', self.on_network_select)

    def setup_attack_tab(self):
        tab = getattr(self, 'attack_tools_tab')

        attack_frame = ttk.LabelFrame(tab, text="Attack Type")
        attack_frame.pack(fill='x', padx=10, pady=5)

        self.attack_var = tk.StringVar(value="deauth")
        attacks = [("Deauth", "deauth"), ("Evil Twin", "evil_twin"), ("PMKID", "pmkid"), ("WPS", "wps"), ("Handshake", "handshake")]

        for text, value in attacks:
            ttk.Radiobutton(attack_frame, text=text, variable=self.attack_var, value=value).pack(side=tk.LEFT, padx=10, pady=5)

        target_frame = ttk.LabelFrame(tab, text="Target Network")
        target_frame.pack(fill='x', padx=10, pady=5)

        ttk.Label(target_frame, text="BSSID:").grid(row=0, column=0, padx=5, pady=5)
        self.target_bssid = ttk.Entry(target_frame, width=20)
        self.target_bssid.grid(row=0, column=1, padx=5, pady=5)

        ttk.Label(target_frame, text="ESSID:").grid(row=0, column=2, padx=5, pady=5)
        self.target_essid = ttk.Entry(target_frame, width=20)
        self.target_essid.grid(row=0, column=3, padx=5, pady=5)

        ttk.Label(target_frame, text="Channel:").grid(row=0, column=4, padx=5, pady=5)
        self.target_channel = ttk.Entry(target_frame, width=5)
        self.target_channel.grid(row=0, column=5, padx=5, pady=5)

        control_frame = ttk.LabelFrame(tab, text="Attack Controls")
        control_frame.pack(fill='x', padx=10, pady=5)

        self.start_attack_btn = ttk.Button(control_frame, text="Start Attack", command=self.start_attack)
        self.start_attack_btn.pack(side=tk.LEFT, padx=5, pady=5)

        self.stop_attack_btn = ttk.Button(control_frame, text="Stop Attack", command=self.stop_attack, state='disabled')
        self.stop_attack_btn.pack(side=tk.LEFT, padx=5, pady=5)

        log_frame = ttk.LabelFrame(tab, text="Attack Log")
        log_frame.pack(fill='both', expand=True, padx=10, pady=5)

        self.attack_log = scrolledtext.ScrolledText(log_frame, wrap=tk.WORD, height=15)
        self.attack_log.pack(fill='both', expand=True, padx=5, pady=5)

    def setup_crack_tab(self):
        tab = getattr(self, 'password_cracking_tab')

        method_frame = ttk.LabelFrame(tab, text="Cracking Method")
        method_frame.pack(fill='x', padx=10, pady=5)

        self.crack_method = tk.StringVar(value="dictionary")
        methods = [("Dictionary", "dictionary"), ("Brute Force", "brute_force"), ("Hashcat", "hashcat")]

        for text, value in methods:
            ttk.Radiobutton(method_frame, text=text, variable=self.crack_method, value=value).pack(side=tk.LEFT, padx=10, pady=5)

        file_frame = ttk.LabelFrame(tab, text="Input Files")
        file_frame.pack(fill='x', padx=10, pady=5)

        ttk.Label(file_frame, text="Capture File:").grid(row=0, column=0, padx=5, pady=5)
        self.capture_file = ttk.Entry(file_frame, width=50)
        self.capture_file.grid(row=0, column=1, padx=5, pady=5)
        ttk.Button(file_frame, text="Browse", command=self.browse_capture).grid(row=0, column=2, padx=5, pady=5)

        ttk.Label(file_frame, text="Wordlist:").grid(row=1, column=0, padx=5, pady=5)
        self.wordlist_file = ttk.Entry(file_frame, width=50)
        self.wordlist_file.grid(row=1, column=1, padx=5, pady=5)
        ttk.Button(file_frame, text="Browse", command=self.browse_wordlist).grid(row=1, column=2, padx=5, pady=5)

        control_frame = ttk.LabelFrame(tab, text="Cracking Controls")
        control_frame.pack(fill='x', padx=10, pady=5)

        self.start_crack_btn = ttk.Button(control_frame, text="Start Cracking", command=self.start_cracking)
        self.start_crack_btn.pack(side=tk.LEFT, padx=5, pady=5)

        self.stop_crack_btn = ttk.Button(control_frame, text="Stop Cracking", command=self.stop_cracking, state='disabled')
        self.stop_crack_btn.pack(side=tk.LEFT, padx=5, pady=5)

        self.crack_progress = ttk.Progressbar(control_frame, mode='determinate')
        self.crack_progress.pack(side=tk.LEFT, fill='x', expand=True, padx=5, pady=5)

        results_frame = ttk.LabelFrame(tab, text="Results")
        results_frame.pack(fill='both', expand=True, padx=10, pady=5)

        self.crack_results = scrolledtext.ScrolledText(results_frame, wrap=tk.WORD, height=10)
        self.crack_results.pack(fill='both', expand=True, padx=5, pady=5)

    def setup_monitor_tab(self):
        tab = getattr(self, 'monitoring_tab')

        control_frame = ttk.LabelFrame(tab, text="Monitor Controls")
        control_frame.pack(fill='x', padx=10, pady=5)

        self.start_monitor_btn = ttk.Button(control_frame, text="Start Monitoring", command=self.start_monitoring)
        self.start_monitor_btn.pack(side=tk.LEFT, padx=5, pady=5)

        self.stop_monitor_btn = ttk.Button(control_frame, text="Stop Monitoring", command=self.stop_monitoring, state='disabled')
        self.stop_monitor_btn.pack(side=tk.LEFT, padx=5, pady=5)

        data_frame = ttk.LabelFrame(tab, text="Real-time Data")
        data_frame.pack(fill='both', expand=True, padx=10, pady=5)

        self.monitor_text = scrolledtext.ScrolledText(data_frame, wrap=tk.WORD, height=20)
        self.monitor_text.pack(fill='both', expand=True, padx=5, pady=5)

    def setup_tools_tab(self):
        tab = getattr(self, 'tools_tab')

        tools_frame = ttk.LabelFrame(tab, text="Available Tools")
        tools_frame.pack(fill='x', padx=10, pady=5)

        tools = [
            ("Generate Wordlist", self.generate_wordlist),
            ("Convert Capture", self.convert_capture),
            ("Analyze Traffic", self.analyze_traffic),
            ("System Status", self.check_system),
            ("Clean Temp Files", self.clean_temp)
        ]

        for i, (text, command) in enumerate(tools):
            ttk.Button(tools_frame, text=text, command=command).grid(row=i//3, column=i%3, padx=5, pady=5, sticky='ew')

        output_frame = ttk.LabelFrame(tab, text="Tool Output")
        output_frame.pack(fill='both', expand=True, padx=10, pady=5)

        self.tools_output = scrolledtext.ScrolledText(output_frame, wrap=tk.WORD, height=15)
        self.tools_output.pack(fill='both', expand=True, padx=5, pady=5)

    def setup_settings_tab(self):
        tab = getattr(self, 'settings_tab')

        general_frame = ttk.LabelFrame(tab, text="General Settings")
        general_frame.pack(fill='x', padx=10, pady=5)

        ttk.Label(general_frame, text="Default Interface:").grid(row=0, column=0, padx=5, pady=5)
        self.default_interface = ttk.Combobox(general_frame, values=self.scanner.get_wireless_interfaces())
        self.default_interface.grid(row=0, column=1, padx=5, pady=5)

        ttk.Label(general_frame, text="Scan Timeout (sec):").grid(row=1, column=0, padx=5, pady=5)
        self.scan_timeout = ttk.Entry(general_frame, width=10)
        self.scan_timeout.insert(0, "30")
        self.scan_timeout.grid(row=1, column=1, padx=5, pady=5)

        advanced_frame = ttk.LabelFrame(tab, text="Advanced Settings")
        advanced_frame.pack(fill='x', padx=10, pady=5)

        self.auto_monitor = tk.BooleanVar()
        ttk.Checkbutton(advanced_frame, text="Auto-enable monitor mode", variable=self.auto_monitor).pack(anchor='w', padx=5, pady=5)

        self.save_logs = tk.BooleanVar(value=True)
        ttk.Checkbutton(advanced_frame, text="Save attack logs", variable=self.save_logs).pack(anchor='w', padx=5, pady=5)

        ttk.Button(tab, text="Save Settings", command=self.save_settings).pack(pady=10)

    # Core functionality methods
    def get_wireless_interfaces(self):
        return self.scanner.get_wireless_interfaces()

    def toggle_monitor_mode(self):
        interface = self.interface_combo.get()
        if not interface:
            messagebox.showerror("Error", "Please select an interface")
            return

        try:
            if not self.monitor_mode:
                success, monitor_iface = self.scanner.enable_monitor_mode(interface)
                if success:
                    self.monitor_mode = True
                    self.monitor_btn.config(text="Disable Monitor Mode")
                    self.status_var.set(f"Monitor mode enabled on {interface}")
                    if monitor_iface != interface:
                        self.interface_combo.set(monitor_iface)
                else:
                    messagebox.showerror("Error", f"Failed to enable monitor mode: {monitor_iface}")
            else:
                success, msg = self.scanner.disable_monitor_mode(interface)
                if success:
                    self.monitor_mode = False
                    self.monitor_btn.config(text="Enable Monitor Mode")
                    self.status_var.set(f"Monitor mode disabled on {interface}")
                else:
                    messagebox.showerror("Error", f"Failed to disable monitor mode: {msg}")
        except Exception as e:
            messagebox.showerror("Error", f"Monitor mode error: {e}")

    def scan_networks(self):
        interface = self.interface_combo.get()
        if not interface:
            messagebox.showerror("Error", "Please select an interface")
            return

        # Validate interface name
        if not self._validate_interface_name(interface):
            return

        if not self.monitor_mode and platform.system() == "Linux":
            messagebox.showwarning("Warning", "Monitor mode recommended for full scanning.")

        # Validate scan timeout
        timeout_str = self.scan_timeout.get()
        if timeout_str:
            try:
                timeout = int(timeout_str)
                if timeout < 1 or timeout > 3600:
                    messagebox.showerror("Validation Error",
                        "Scan timeout must be between 1 and 3600 seconds")
                    return
            except ValueError:
                messagebox.showerror("Validation Error",
                    "Scan timeout must be a valid number")
                return

        self.is_scanning = True
        self.scan_btn.config(state='disabled')
        self.stop_scan_btn.config(state='normal')
        self.scan_progress.start()

        for item in self.network_tree.get_children():
            self.network_tree.delete(item)

        def on_network_found(network):
            self.root.after(0, lambda: self.network_tree.insert('', 'end', values=(
                network.bssid, network.essid, network.channel, network.encryption,
                network.signal, network.clients
            )))

        def on_progress(progress):
            pass

        self.scanner.on_network_found = on_network_found
        self.scanner.on_scan_progress = on_progress

        thread = threading.Thread(target=self._scan_worker, args=(interface,))
        thread.daemon = True
        thread.start()

    def _validate_interface_name(self, interface):
        """Validate that interface name is safe and reasonable"""
        import re
        if not interface or not interface.strip():
            messagebox.showerror("Validation Error", "Interface name cannot be empty")
            return False
        # Basic safety: only allow alphanumeric, colons, dots, hyphens, underscores
        if not re.match(r'^[\w\-\.:]+$', interface.strip()):
            messagebox.showerror("Validation Error",
                "Interface name contains invalid characters")
            return False
        return True

    def _scan_worker(self, interface):
        try:
            self.status_var.set("Scanning networks...")
            timeout = int(self.scan_timeout.get()) if self.scan_timeout.get().isdigit() else 30

            success = self.scanner.start_scan(interface, timeout)
            if not success:
                self.root.after(0, lambda: messagebox.showerror("Error", "Failed to start scan"))

            while self.scanner.scanning and self.is_scanning:
                time.sleep(0.5)

        except Exception as e:
            self.root.after(0, lambda: messagebox.showerror("Error", f"Scan failed: {e}"))
        finally:
            self.root.after(0, self._scan_complete)

    def _scan_complete(self):
        self.is_scanning = False
        self.scan_btn.config(state='normal')
        self.stop_scan_btn.config(state='disabled')
        self.scan_progress.stop()
        self.status_var.set(f"Scan complete - {len(self.scanner.get_networks())} networks found")

    def stop_scan(self):
        self.scanner.stop_scan()
        self.is_scanning = False

    def on_network_select(self, event):
        selection = self.network_tree.selection()
        if selection:
            item = self.network_tree.item(selection[0])
            values = item['values']

            self.target_bssid.delete(0, tk.END)
            self.target_bssid.insert(0, values[0])

            self.target_essid.delete(0, tk.END)
            self.target_essid.insert(0, values[1])

            self.target_channel.delete(0, tk.END)
            self.target_channel.insert(0, values[2])

            details = f"BSSID: {values[0]}\nESSID: {values[1]}\nChannel: {values[2]}\nEncryption: {values[3]}\nSignal: {values[4]}\nClients: {values[5]}"
            self.details_text.delete(1.0, tk.END)
            self.details_text.insert(1.0, details)

    def sort_networks(self, col):
        pass

    def start_attack(self):
        attack_type = self.attack_var.get()
        bssid = self.target_bssid.get()
        essid = self.target_essid.get()
        channel = self.target_channel.get()

        if not bssid or not essid:
            messagebox.showerror("Error", "Please select a target network")
            return

        # Validate inputs
        if not self._validate_attack_inputs(attack_type, bssid, essid, channel):
            return

        # Confirm deauth attacks before proceeding
        if attack_type == "deauth":
            confirm = messagebox.askyesno(
                "Confirm Deauth Attack",
                f"This will disconnect clients from '{essid}' ({bssid}).\n\n"
                "This may be illegal without proper authorization.\n"
                "Only use on networks you own or have explicit permission to test.\n\n"
                "Continue?"
            )
            if not confirm:
                return

        self.is_attacking = True
        self.start_attack_btn.config(state='disabled')
        self.stop_attack_btn.config(state='normal')

        thread = threading.Thread(target=self._attack_worker, args=(attack_type, bssid, essid, channel))
        thread.daemon = True
        thread.start()

    def _validate_attack_inputs(self, attack_type, bssid, essid, channel):
        """Validate attack inputs for security and correctness"""
        import re

        # Validate BSSID format (MAC address)
        if attack_type in ('deauth', 'evil_twin', 'pmkid', 'wps'):
            bssid_pattern = re.compile(r'^([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})$')
            if not bssid_pattern.match(bssid.strip()):
                messagebox.showerror("Validation Error",
                    "Invalid BSSID format. Expected format: XX:XX:XX:XX:XX:XX")
                return False

        # Validate ESSID is not empty
        if attack_type in ('evil_twin',) and not essid.strip():
            messagebox.showerror("Validation Error",
                "ESSID cannot be empty for Evil Twin attack")
            return False

        # Validate channel if provided
        if channel and channel.strip():
            try:
                ch = int(channel)
                if ch < 1 or ch > 165:
                    messagebox.showerror("Validation Error",
                        "Channel must be between 1 and 165")
                    return False
            except ValueError:
                messagebox.showerror("Validation Error",
                    "Channel must be a valid number")
                return False

        return True

    def _attack_worker(self, attack_type, bssid, essid, channel):
        try:
            interface = self.interface_combo.get()
            if not interface:
                self.root.after(0, lambda: messagebox.showerror("Error", "No interface selected"))
                return

            self.log_attack(f"Starting {attack_type} attack on {essid} ({bssid})")

            if attack_type == "deauth":
                attack = self.attacks.create_deauth_attack("deauth")
                result = attack.start_deauth(interface, bssid)
            elif attack_type == "evil_twin":
                attack = self.attacks.create_evil_twin_attack("evil_twin")
                result = attack.start_evil_twin(interface, essid, bssid, int(channel) if channel.isdigit() else 6)
            elif attack_type == "pmkid":
                attack = self.attacks.create_pmkid_attack("pmkid")
                result = attack.start_pmkid_attack(interface, bssid, int(channel) if channel.isdigit() else 0)
            elif attack_type == "wps":
                attack = self.attacks.create_wps_attack("wps")
                result = attack.start_wps_attack(interface, bssid, essid)
            elif attack_type == "handshake":
                self._handshake_capture(interface, bssid, channel)

            if attack_type != "handshake":
                self.log_attack(f"Attack completed: {result.details}")

        except Exception as e:
            self.log_attack(f"Attack failed: {e}")
        finally:
            self.root.after(0, self._attack_complete)

    def _handshake_capture(self, interface, bssid, channel):
        try:
            success = self.capture.capture_handshake(interface, bssid, int(channel) if channel.isdigit() else 1,
                                                   f"handshake_{bssid.replace(':', '')}_{datetime.now().strftime('%H%M%S')}.cap")
            self.log_attack(f"Handshake capture {'successful' if success else 'failed'}")
        except Exception as e:
            self.log_attack(f"Handshake capture error: {e}")

    def log_attack(self, message):
        timestamp = datetime.now().strftime("%H:%M:%S")
        self.root.after(0, lambda: self.attack_log.insert(tk.END, f"[{timestamp}] {message}\n"))
        self.root.after(0, lambda: self.attack_log.see(tk.END))

    def stop_attack(self):
        self.attacks.stop_all_attacks()
        self.is_attacking = False

    def _attack_complete(self):
        self.is_attacking = False
        self.start_attack_btn.config(state='normal')
        self.stop_attack_btn.config(state='disabled')

    def start_cracking(self):
        capture_file = self.capture_file.get()
        wordlist = self.wordlist_file.get()
        method = self.crack_method.get()

        if not capture_file:
            messagebox.showerror("Error", "Please select a capture file")
            return

        if method == "dictionary" and not wordlist:
            messagebox.showerror("Error", "Please select a wordlist for dictionary attack")
            return

        self.is_cracking = True
        self.start_crack_btn.config(state='disabled')
        self.stop_crack_btn.config(state='normal')
        self.crack_progress['value'] = 0

        thread = threading.Thread(target=self._crack_worker, args=(capture_file, wordlist, method))
        thread.daemon = True
        thread.start()

    def _crack_worker(self, capture_file, wordlist, method):
        try:
            bssid = self.target_bssid.get()
            essid = self.target_essid.get()

            result = self.cracker.crack_wpa_handshake(capture_file, wordlist if method == "dictionary" else "", method, bssid, essid)

            if result:
                self.root.after(0, lambda: self.crack_results.insert(tk.END, f"Password found: {result.password}\n" if result.found else "Password not found\n"))
                self.root.after(0, lambda: self.crack_results.insert(tk.END, f"Time taken: {result.time_taken:.1f}s\n"))

        except Exception as e:
            self.root.after(0, lambda: self.crack_results.insert(tk.END, f"Cracking failed: {e}\n"))
        finally:
            self.root.after(0, self._crack_complete)

    def stop_cracking(self):
        self.cracker.stop_cracking()
        self.is_cracking = False

    def _crack_complete(self):
        self.is_cracking = False
        self.start_crack_btn.config(state='normal')
        self.stop_crack_btn.config(state='disabled')

    def browse_capture(self):
        """Browse for capture file"""
        from tkinter import filedialog
        filename = filedialog.askopenfilename(
            title="Select Capture File",
            filetypes=[("Capture files", "*.cap *.pcap *.pcapng"), ("All files", "*.*")]
        )
        if filename:
            self.capture_file.delete(0, tk.END)
            self.capture_file.insert(0, filename)

    def browse_wordlist(self):
        """Browse for wordlist file"""
        from tkinter import filedialog
        filename = filedialog.askopenfilename(
            title="Select Wordlist",
            filetypes=[("Text files", "*.txt"), ("All files", "*.*")]
        )
        if filename:
            self.wordlist_file.delete(0, tk.END)
            self.wordlist_file.insert(0, filename)

    def start_monitoring(self):
        interface = self.interface_combo.get()
        if not interface:
            messagebox.showerror("Error", "Please select an interface")
            return

        self.is_monitoring = True
        self.start_monitor_btn.config(state='disabled')
        self.stop_monitor_btn.config(state='normal')

        thread = threading.Thread(target=self._monitor_worker, args=(interface,))
        thread.daemon = True
        thread.start()

    def _monitor_worker(self, interface):
        try:
            self.root.after(0, lambda: self.monitor_text.insert(tk.END, f"[{datetime.now()}] Starting monitoring on {interface}\n"))

            while self.is_monitoring:
                if platform.system() == "Linux":
                    try:
                        result = subprocess.run(['iwconfig', interface], capture_output=True, text=True, timeout=5)
                        cpu = psutil.cpu_percent()
                        mem = psutil.virtual_memory().percent

                        data = f"[{datetime.now()}]\nInterface: {interface}\nCPU: {cpu}%\nMemory: {mem}%\n\nWiFi Stats:\n{result.stdout}\n{'='*50}\n"
                        self.root.after(0, lambda: self.monitor_text.insert(tk.END, data))
                        self.root.after(0, lambda: self.monitor_text.see(tk.END))
                    except:
                        pass

                time.sleep(2)

        except Exception as e:
            self.root.after(0, lambda: self.monitor_text.insert(tk.END, f"Monitoring error: {e}\n"))
        finally:
            self.root.after(0, self._monitor_complete)

    def stop_monitoring(self):
        self.is_monitoring = False

    def _monitor_complete(self):
        self.is_monitoring = False
        self.start_monitor_btn.config(state='normal')
        self.stop_monitor_btn.config(state='disabled')

    def generate_wordlist(self):
        self.wordlists.create_custom_wordlist("generated", ["password", "admin", "welcome", "123456"])
        self.tools_output.insert(tk.END, "Custom wordlist generated\n")

    def convert_capture(self):
        self.tools_output.insert(tk.END, "Capture conversion - select file to convert\n")

    def analyze_traffic(self):
        capture_file = self.capture_file.get()
        if capture_file:
            analyzer = PacketAnalyzer()
            if analyzer.load_capture(capture_file):
                results = analyzer.analyze_capture()
                self.tools_output.insert(tk.END, f"Analysis: {results['total_packets']} packets found\n")
            else:
                self.tools_output.insert(tk.END, "Failed to load capture file\n")
        else:
            self.tools_output.insert(tk.END, "No capture file selected\n")

    def check_system(self):
        from attack_tools import check_attack_capabilities
        caps = check_attack_capabilities()

        info = f"OS: {platform.system()} {platform.release()}\nPython: {sys.version.split()[0]}\n\nTools Status:\n"
        for tool, available in caps.items():
            status = "✓" if available else "✗"
            info += f"{tool}: {status}\n"

        self.tools_output.insert(tk.END, info)

    def clean_temp(self):
        import glob
        patterns = ['scan*.csv', 'scan*.cap', 'handshake*.cap', 'pmkid*.pcapng', 'hash*.hccapx']
        cleaned = 0

        for pattern in patterns:
            files = glob.glob(pattern)
            for file in files:
                try:
                    os.remove(file)
                    cleaned += 1
                except:
                    pass

        self.tools_output.insert(tk.END, f"Cleaned {cleaned} temporary files\n")

    def load_config(self):
        if 'default_interface' in self.config.config:
            self.default_interface.set(self.config.get('default_interface'))
        if 'scan_timeout' in self.config.config:
            self.scan_timeout.delete(0, tk.END)
            self.scan_timeout.insert(0, str(self.config.get('scan_timeout', 30)))
        self.auto_monitor.set(self.config.get('auto_monitor', False))
        self.save_logs.set(self.config.get('save_logs', True))

    def save_settings(self):
        self.config.set('default_interface', self.default_interface.get())
        self.config.set('scan_timeout', int(self.scan_timeout.get()) if self.scan_timeout.get().isdigit() else 30)
        self.config.set('auto_monitor', self.auto_monitor.get())
        self.config.set('save_logs', self.save_logs.get())

        if self.config.save_config():
            messagebox.showinfo("Success", "Settings saved")
        else:
            messagebox.showerror("Error", "Failed to save settings")

    def check_requirements(self):
        from attack_tools import check_attack_capabilities
        caps = check_attack_capabilities()

        missing = [tool for tool, available in caps.items() if not available and tool in ['aircrack_ng', 'airodump_ng', 'aireplay_ng']]

        if missing:
            msg = f"Missing tools: {', '.join(missing)}\n\nInstall on Linux: sudo apt install aircrack-ng"
            messagebox.showwarning("Requirements", msg)

    def run(self):
        """Start the application"""
        self.root.mainloop()

    def run(self):
        """Start the application"""
        self.root.mainloop()

def main():
    """Main entry point for the WiFi Cracking Suite"""
    app = WiFiCrackingSuite()
    app.run()

if __name__ == "__main__":
    main()
