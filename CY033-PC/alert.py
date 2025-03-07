# alert.py (Updated)
import tkinter as tk
from tkinter import ttk, messagebox
import psutil

 

class AlertTab(ttk.Frame):
    def __init__(self, parent):
        super().__init__(parent)
        self.alert_list = tk.Listbox(self, width=100, height=20)
        self.alert_list.pack(pady=10, padx=10, fill=tk.BOTH, expand=True)
        self.context_menu = tk.Menu(self, tearoff=0)
        self.context_menu.add_command(label="Terminate Process", command=self.terminate_process)
        self.context_menu.add_command(label="Ignore", command=self.ignore_alert)
        
        self.alert_list.bind("<Button-3>", self.show_context_menu)
        self.alerts = {}  # Store process info: {listbox_index: (pid, name)}

    def add_alert(self, process_name, pid):
        entry = f"Malicious activity detected: {process_name} (PID: {pid})"
        self.alert_list.insert(tk.END, entry)
        self.alert_list.itemconfig(tk.END, {'fg': 'red'})
        self.alerts[self.alert_list.size()-1] = (pid, process_name)

    def show_context_menu(self, event):
        try:
            index = self.alert_list.nearest(event.y)
            self.alert_list.selection_clear(0, tk.END)
            self.alert_list.selection_set(index)
            self.context_menu.post(event.x_root, event.y_root)
        except tk.TclError:
            pass

    def terminate_process(self):
        selection = self.alert_list.curselection()
        if selection:
            index = selection[0]
            pid, name = self.alerts.get(index, (None, None))
            if pid:
                try:
                    process = psutil.Process(pid)
                    process.terminate()
                    messagebox.showinfo("Success", f"Process {name} (PID: {pid}) terminated")
                    self.remove_alert(index)
                except Exception as e:
                    messagebox.showerror("Error", f"Failed to terminate process: {str(e)}")

    def ignore_alert(self):
        selection = self.alert_list.curselection()
        if selection:
            index = selection[0]
            self.remove_alert(index)

    def remove_alert(self, index):
        self.alert_list.delete(index)
        # Update alert indices
        new_alerts = {}
        for i in range(self.alert_list.size()):
            if i < index:
                new_alerts[i] = self.alerts[i]
            elif i > index:
                new_alerts[i-1] = self.alerts[i]
        self.alerts = new_alerts