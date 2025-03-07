# monitor.py (Updated)
import tkinter as tk
from tkinter import ttk, messagebox
import random
import threading
import time

 

class MonitorTab(ttk.Frame):
    def __init__(self, parent):
        super().__init__(parent)
        self.alert_tab = None  # Will be set by main app
        self.process_list = tk.Listbox(self, width=100, height=20)
        self.process_list.pack(pady=10, padx=10, fill=tk.BOTH, expand=True)
        
        # Simulated malicious processes (for demonstration)
        self.malicious_processes = {
            'malware.exe': 'High risk: Data exfiltration',
            'ransomware.dll': 'Critical: File encryption detected',
            'spyware.bin': 'Medium: Keystroke logging'
        }
        
        self.start_button = ttk.Button(self, text="Start Monitoring", command=self.start_monitoring)
        self.start_button.pack(pady=5)
        
        self.stop_button = ttk.Button(self, text="Stop Monitoring", command=self.stop_monitoring)
        self.stop_button.pack(pady=5)
        self.monitoring = False

    def start_monitoring(self):
        if not self.monitoring:
            self.monitoring = True
            threading.Thread(target=self.simulate_activity, daemon=True).start()
            messagebox.showinfo("Info", "Monitoring started")

    def stop_monitoring(self):
        self.monitoring = False
        messagebox.showinfo("Info", "Monitoring stopped")

    def simulate_activity(self):
        while self.monitoring:
            # Simulate random process activity
            if random.random() < 0.3:  # 30% chance of malicious activity
                process_name, description = random.choice(list(self.malicious_processes.items()))
                pid = random.randint(1000, 9999)  # Simulated PID
                self.process_list.insert(tk.END, f"{process_name} (PID: {pid}) - {description}")
                self.process_list.itemconfig(tk.END, {'fg': 'red'})
                if self.alert_tab:
                    self.alert_tab.add_alert(process_name, pid)
            else:
                self.process_list.insert(tk.END, f"Normal process: svchost.exe (PID: {random.randint(1000, 9999)})")
                self.process_list.itemconfig(tk.END, {'fg': 'black'})
            
            self.process_list.yview(tk.END)
            time.sleep(2)