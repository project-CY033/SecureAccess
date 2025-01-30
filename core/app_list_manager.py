import subprocess
import platform

class AppListManager:
    def __init__(self):
        pass

    def get_installed_apps(self):
          if platform.system() == "Windows":
                return self.get_windows_apps()
          elif platform.system() == "Linux":
              return self.get_linux_apps()
          elif platform.system() == "Darwin":
              return self.get_macos_apps()
          else:
              return ["Unknow os"]

    def get_windows_apps(self):
        try:
            output = subprocess.check_output(['powershell', 'Get-AppxPackage | Select Name'], text=True, encoding='utf-8')
            app_list = []
            for line in output.strip().split('\n')[2:]:
                if line.strip():
                    app_list.append(line.strip())
            return app_list
        except subprocess.CalledProcessError:
            return ["Error fetching apps"]

    def get_linux_apps(self):
        try:
                output = subprocess.check_output(["apt", "list", "--installed"], text=True, encoding='utf-8')
                app_list = []
                for line in output.strip().split('\n')[1:]:
                    if line.strip() and line.strip().startswith("listing"):
                       continue
                    if line.strip():
                       app_list.append(line.strip().split("/")[0])
                return app_list
        except subprocess.CalledProcessError:
             return ["Error fetching apps"]

    def get_macos_apps(self):
        try:
            output = subprocess.check_output(['ls', '/Applications'], text=True, encoding='utf-8')
            app_list = []
            for line in output.strip().split('\n'):
                 if line.strip() and line.strip().endswith(".app"):
                    app_list.append(line.strip())
            return app_list
        except subprocess.CalledProcessError:
            return ["Error fetching apps"]