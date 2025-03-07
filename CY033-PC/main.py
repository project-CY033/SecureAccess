import tkinter as tk
from tkinter import ttk
from monitor import MonitorTab
from access import AccessTab
from alert import AlertTab
from application import ApplicationTab
from settings import SettingsTab
from permission_management import PermissionManagementTab

class CY033PCApp(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("CY033-PC")
        self.geometry("1200x800")
        
        # Create notebook first
        self.tab_control = ttk.Notebook(self)
        
        # Initialize all tabs first
        self.monitor_tab = MonitorTab(self.tab_control)
        self.perm_mgmt_tab = PermissionManagementTab(self.tab_control)
        self.access_tab = AccessTab(self.tab_control)
        self.alert_tab = AlertTab(self.tab_control)
        self.application_tab = ApplicationTab(self.tab_control)
        self.settings_tab = SettingsTab(self.tab_control)

        # Set up cross-tab communication
        self.monitor_tab.alert_tab = self.alert_tab
        
        # Add tabs to notebook in order
        self.tab_control.add(self.monitor_tab, text='Monitor')
        self.tab_control.add(self.perm_mgmt_tab, text='Data Protection')
        self.tab_control.add(self.access_tab, text='Accessption')
        self.tab_control.add(self.alert_tab, text='Alerts')
        self.tab_control.add(self.application_tab, text='Applications')
        self.tab_control.add(self.settings_tab , text='Settings')

        # Pack the notebook to fill the main window
        self.tab_control.pack(expand=1, fill='both')

if __name__ == "__main__":
    app = CY033PCApp()
    app.mainloop()