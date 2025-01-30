import sys
from PyQt5.QtWidgets import QMainWindow, QTabWidget
from ui.monitor_tab import MonitorTab
from ui.exception_tab import ExceptionTab
from ui.alert_tab import AlertTab
from ui.application_tab import ApplicationTab
from ui.settings_tab import SettingsTab
from ui.permission_tab import PermissionTab
from ui.networking_tab import NetworkingTab # import networking Tab
from PyQt5 import QtGui
from core.packet_monitor import PacketMonitor
from core.activity_tracker import ActivityTracker
from core.app_list_manager import AppListManager


class MainWindow(QMainWindow):
    def __init__(self, config):
        super().__init__()

        self.config = config
        self.setWindowTitle("project-SecureAccess")
        self.setGeometry(100, 100, 800, 600)
        self.setWindowIcon(QtGui.QIcon('assets/icon.png'))

        self.tabs = QTabWidget()
        self.setCentralWidget(self.tabs)

        self.monitor_tab = MonitorTab(self)
        self.exception_tab = ExceptionTab(config, self)
        self.alert_tab = AlertTab()
        self.application_tab = ApplicationTab()
        self.settings_tab = SettingsTab(config,self)
        self.permission_tab = PermissionTab()
        self.networking_tab = NetworkingTab(self)

        self.tabs.addTab(self.monitor_tab, "Monitor")
        self.tabs.addTab(self.exception_tab, "Exception")
        self.tabs.addTab(self.alert_tab, "Alert")
        self.tabs.addTab(self.application_tab, "Application")
        self.tabs.addTab(self.settings_tab, "Settings")
        self.tabs.addTab(self.permission_tab, "Permission Management")
        self.tabs.addTab(self.networking_tab, "Networking")

        #Initialize PacketMonitor and ActivityTracker here
        self.packet_monitor = PacketMonitor(self, self.config)
        self.activity_tracker = ActivityTracker(self,self.config)
        self.app_list_manager = AppListManager()

        # Start Monitoring
        self.start_monitoring()
        self.update_app_list()

    def start_monitoring(self):
        self.packet_monitor.start_monitoring()
        self.activity_tracker.start_tracking()

    def closeEvent(self, event):
         self.packet_monitor.stop_monitoring()
         self.activity_tracker.stop_tracking()
         event.accept()

    def update_app_list(self):
         self.permission_tab.update_app_list(self.app_list_manager.get_installed_apps())