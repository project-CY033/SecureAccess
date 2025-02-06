```


build a tool  to monitor all the permissions also hidden permissions and user can change this permissions , add ne tab give name "Monitor" in this  monitor all incoming and outgoing packets monitor all activities of all the application if the applications send or receive malicious data user can terminate or stop  that , also tract application what are they access.

add new tab and give name "Accesption"  where user can select application that selected application are not tract by our tool

add new tab name "Alert" where user can receive notification like send notification if malicious application is accessing data , if applications send or brack the privacy or if the application are send data without permission or if the application are leack data

add new tab give name "Application" , list out all applications include hidden or system application that are install in system

add new tab  give name "Setting" or add icon, where user can customize setting of the tools

please add any new feature in my tool

given name this tools as "CY033-PC"

give full code with file structure

give all file code

```



---
---
---
---

#    improve 1




<details>
  <summary>Click to see Improvment</summary>

---
---

</details>

---

















---
---
---
---
##  improve : enhanced alerting system that highlights malicious processes in red, provides terminate/ignore options, and allows for right-click context menus. 
```
now when any malicious activity  processes executed and  run monitors this high-light with "red color  and send to alert tab  in this tab when user click to the process show two option 1 is  terminate this process and 2nd is ignore , when user select terminate then terminate that process completely and when user select ignore then ignored and remove from the alert tab 

this also show when user  right click to the process   
```


<details>
  <summary>Click to see Improvment</summary>

---
---

Okay, let's implement this enhanced alerting system that highlights malicious processes in red, provides terminate/ignore options, and allows for right-click context menus. This involves changes to the `activity_tracker.py`, `alert_tab.py`, and potentially the `main_window.py` or a shared utility file.

**High-Level Strategy:**

1.  **Modify `activity_tracker.py`:**
    *   Add logic to identify malicious processes (using a placeholder for AI, as before).
    *   Emit a signal when a malicious process is detected, passing the process information.

2.  **Modify `alert_tab.py`:**
    *   Use a `QListWidget` to display alerts with colored entries for malicious processes.
    *   Create context menu (right-click) options for terminate and ignore.
    *   Implement the terminate and ignore actions.

**Updated Code:**

**1. `core/activity_tracker.py` (Modified):**

```python
import psutil
import time
import threading
import platform
from PyQt5.QtCore import pyqtSignal, QObject

class ActivityTrackerSignals(QObject):
    malicious_process = pyqtSignal(dict)

class ActivityTracker:
    def __init__(self, main_window, config):
        self.main_window = main_window
        self.config = config
        self.stop_tracker = False
        self.data = {}
        self.signals = ActivityTrackerSignals()  # Initialize signals


    def start_tracking(self):
         self.stop_tracker = False
         threading.Thread(target=self.track_activities,daemon=True).start()

    def stop_tracking(self):
        self.stop_tracker = True

    def track_activities(self):
        while not self.stop_tracker:
            for process in psutil.process_iter(['pid', 'name', 'exe', 'username', 'cpu_percent', 'memory_info']):
                process_info = process.info
                if process_info['name'] not in self.config['excluded_apps']:
                    if process_info['name'] not in self.data:
                        self.data[process_info['name']] = []
                    if process_info not in self.data[process_info['name']]:
                           self.data[process_info['name']].append(process_info)
                           self.main_window.monitor_tab.update_monitor_data(f"Activity: {process_info['name']} start at {time.ctime()}\n")
                           if self.is_malicious(process_info):
                                self.signals.malicious_process.emit(process_info)

                    # Track Resource Usage Example: CPU, Memory.
                    cpu_percent = process_info['cpu_percent']
                    memory_info = process_info['memory_info']
                    memory_usage_mb = memory_info.rss / 1024 / 1024 if memory_info else "N/A"
                    self.main_window.monitor_tab.update_monitor_data(f"Process {process_info['name']} CPU {cpu_percent}% Memory:{memory_usage_mb}MB \n")
                    if platform.system() == "Linux":
                        open_files = process.open_files()
                        for file in open_files:
                            self.main_window.monitor_tab.update_monitor_data(f"Process {process_info['name']} File accessed: {file.path}\n")

            time.sleep(2)  # Check every 2 seconds


    def get_app_activities(self, app_name):
        # Implement actual activity tracking
        if app_name in self.data:
            return self.data[app_name]
        return []

    def is_malicious(self, process_info):
        # Implement your actual AI-based malicious detection logic here.
        # This is a placeholder for demonstration.

        if "malware" in process_info['name'].lower():
            return True  # Example: detect based on process name.
        return False
```

**2. `ui/alert_tab.py` (Modified):**

```python
from PyQt5.QtWidgets import QWidget, QVBoxLayout, QListWidget, QMenu, QAction, QAbstractItemView
from PyQt5.QtGui import QColor
import psutil

class AlertTab(QWidget):
    def __init__(self):
        super().__init__()
        layout = QVBoxLayout()
        self.alert_list = QListWidget()
        self.alert_list.setContextMenuPolicy(Qt.CustomContextMenu)
        self.alert_list.customContextMenuRequested.connect(self.open_menu)
        self.alert_list.setSelectionMode(QAbstractItemView.SingleSelection)
        layout.addWidget(self.alert_list)
        self.setLayout(layout)
        self.ignored_processes = set()


    def add_alert(self, process_info, is_malicious=False):
        item_text = f"Process: {process_info['name']} (PID: {process_info['pid']})"
        item = QListWidgetItem(item_text)

        if is_malicious:
            item.setForeground(QColor("red"))

        item.setData(Qt.UserRole, process_info)  # Store process info.
        self.alert_list.addItem(item)

    def open_menu(self, position):
        selected_item = self.alert_list.itemAt(position)
        if selected_item:
            process_info = selected_item.data(Qt.UserRole)
            menu = QMenu()
            terminate_action = QAction("Terminate Process", self)
            ignore_action = QAction("Ignore Process", self)

            terminate_action.triggered.connect(lambda: self.terminate_process(process_info, selected_item))
            ignore_action.triggered.connect(lambda: self.ignore_process(process_info, selected_item))

            menu.addAction(terminate_action)
            menu.addAction(ignore_action)
            menu.exec_(self.alert_list.mapToGlobal(position))

    def terminate_process(self, process_info, selected_item):
        try:
            process = psutil.Process(process_info['pid'])
            process.terminate()
            self.alert_list.takeItem(self.alert_list.row(selected_item))  # Remove from list.
        except psutil.NoSuchProcess:
            print("Process already terminated.")
        except Exception as e:
            print(f"Error terminating process: {e}")

    def ignore_process(self, process_info, selected_item):
        self.ignored_processes.add(process_info['pid'])
        self.alert_list.takeItem(self.alert_list.row(selected_item))  # Remove from list.

```

**3. `ui/main_window.py` (Modified):**

```python
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
from PyQt5.QtWidgets import QListWidgetItem
from PyQt5.QtGui import QColor
from PyQt5.QtCore import Qt


class MainWindow(QMainWindow):
    def __init__(self, config):
        super().__init__()

        self.config = config
        self.setWindowTitle("CY033-PC")
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

        # Connect malicious process signal to alert tab
        self.activity_tracker.signals.malicious_process.connect(self.alert_tab.add_alert)

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

```

**4. All other files remain unchanged**

**Key Changes:**

*   **`core/activity_tracker.py`:**
    *   Added `ActivityTrackerSignals` class with `malicious_process` signal to communicate with the GUI thread.
    *   `track_activities()` now calls `is_malicious()` and emits `signals.malicious_process.emit(process_info)` if a malicious process is detected.
    *   Added a `is_malicious` function for detecting malicious processes, you must implement logic to detect malicious process.
*   **`ui/alert_tab.py`:**
    *   Replaced `QTextEdit` with a `QListWidget` for managing alerts as individual items.
    *   `add_alert()` adds an alert to the list, coloring it red if `is_malicious` is True.
    *   `open_menu()` creates a context menu with "Terminate Process" and "Ignore Process" actions.
    *   `terminate_process()` terminates the process and removes it from the alert list.
    *   `ignore_process()` adds the PID to a set of ignored processes and removes it from the alert list.
*   **`ui/main_window.py`:**
    *   Connect the `malicious_process` signal from the activity tracker to the `add_alert` method in the alert tab:
        *   `self.activity_tracker.signals.malicious_process.connect(self.alert_tab.add_alert)`

**How to Run:**

1.  **Save Files:** Make sure all code snippets are saved in the correct files in the directory structure.
2.  **Install:** `pip install PyQt5 scapy psutil`
3.  **Run:** Execute `python main.py`.

**Verification:**

1.  Run the application.
2.  The program should start monitoring processes, and if the `activity_tracker` find malicious process it emit the signal.
3.  Go to the alert tab, the `add_alert` connect with the signal, and the `add_alert` method add the malicious process in the list with red color.
4.  Right-click on an alert in the list. You should see a context menu with "Terminate Process" and "Ignore Process" options.
5.  Click "Terminate Process" to terminate it.
6.  Click "Ignore Process" to remove it from alert list.

**Important Considerations:**

*   **Permissions:** Terminating processes requires appropriate permissions. On some systems, you might need administrator/root privileges.
*   **AI Integration:**  The `is_malicious()` function is a placeholder. You need to implement AI-based malicious detection logic for it to be effective.
*   **Error Handling:**  Add more robust error handling, especially when terminating processes.
*   **User Experience:** Improve the user experience with more informative alerts, progress indicators for termination, and better visual cues.

This enhanced alerting system should provide a much more interactive and functional experience. Let me know if you have any other questions.



</details>

---



























---
---
---
---

#   # improve last




<details>
  <summary>Click to see Improvment</summary>

---
---

</details>

---




