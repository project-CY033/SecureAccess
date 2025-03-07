import tkinter as tk
from tkinter import ttk

class AccessTab(ttk.Frame):
    def __init__(self, parent):
        super().__init__(parent)
        label = ttk.Label(self, text="Access Control")
        label.pack(pady=20)