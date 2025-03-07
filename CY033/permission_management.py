import tkinter as tk
from tkinter import ttk, filedialog
from data_processor import DataSanitizer

class PermissionManagementTab(ttk.Frame):
    def __init__(self, parent):
        super().__init__(parent)
        self.sanitizer = DataSanitizer()
        self.create_widgets()
        
    def create_widgets(self):
        ttk.Label(self, text="File Data Extraction & Redaction").pack(pady=10)
        
        self.file_list = tk.Listbox(self, width=80, height=15)
        self.file_list.pack(pady=5)
        
        btn_frame = ttk.Frame(self)
        btn_frame.pack(pady=5)
        
        ttk.Button(btn_frame, text="Add Files", 
                  command=self.add_files).pack(side=tk.LEFT, padx=5)
        ttk.Button(btn_frame, text="Process Files", 
                  command=self.process_files).pack(side=tk.LEFT, padx=5)
        
        self.result_text = tk.Text(self, height=10)
        self.result_text.pack(fill=tk.X)
        
    def add_files(self):
        files = filedialog.askopenfiles(mode='rb', 
            filetypes=[("All Files", "*.*"), 
                      ("PDF", "*.pdf"),
                      ("Images", "*.jpg *.jpeg *.png"),
                      ("Documents", "*.docx")])
        for f in files:
            self.file_list.insert(tk.END, f.name)
            
    def process_files(self):
        for file_path in self.file_list.get(0, tk.END):
            clean_path = self.sanitizer.process_file(file_path)
            self.result_text.insert(tk.END, f"Processed: {clean_path}\n")