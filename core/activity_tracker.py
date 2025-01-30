import psutil
import time
import threading
import platform

class ActivityTracker:
    def __init__(self, main_window, config):
        self.main_window = main_window
        self.config = config
        self.stop_tracker = False
        self.data = {}

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