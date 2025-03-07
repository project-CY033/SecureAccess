import tkinter as tk
from tkinter import ttk
from data_processor import DataSanitizer  # Add this import

class SettingsTab(ttk.Frame):
    def __init__(self, parent):
        super().__init__(parent)
        self.create_widgets()
        
    def create_widgets(self):
        ttk.Label(self, text="Data Sanitization Settings").pack(pady=10)
        
        self.auto_redact = tk.BooleanVar()
        ttk.Checkbutton(self, text="Auto-redact sensitive data", 
                       variable=self.auto_redact).pack(anchor=tk.W)
        
        ttk.Label(self, text="Sensitive Patterns:").pack(anchor=tk.W)
        self.pattern_list = tk.Listbox(self, height=5)
        for pattern in DataSanitizer.SENSITIVE_PATTERNS:
            self.pattern_list.insert(tk.END, pattern)
        self.pattern_list.pack(fill=tk.X)