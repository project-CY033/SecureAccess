import platform
import subprocess


class PermissionManager:
    def __init__(self):
       pass

    def get_permissions(self, app_name):
        if platform.system() == "Windows":
            return self.get_windows_permissions(app_name)
        elif platform.system() == "Linux":
            return self.get_linux_permissions(app_name)
        elif platform.system() == "Darwin":
            return self.get_macos_permissions(app_name)
        else:
            return ["Unknow OS"]
    def change_permission(self, app_name, permission, action, category):
         if platform.system() == "Windows":
            return self.change_windows_permission(app_name,permission,action)
         elif platform.system() == "Linux":
            return self.change_linux_permission(app_name,permission,action)
         elif platform.system() == "Darwin":
            return self.change_macos_permission(app_name,permission,action)
         else:
           print ("Unknow os")

    def get_windows_permissions(self, app_name):
          # placeholder
        return [
            ("location", "General", "enable"),
            ("Access Media", "General", "enable"),
            ("microphone", "General","disable"),
             ("Camera", "Hidden","disable"),
            ("Background Activity", "Hidden", "enable")

        ]

    def get_linux_permissions(self, app_name):
        try:
            result = subprocess.run(['ls', '-l', app_name],capture_output=True, text=True, check=True)
            permissions = result.stdout.strip().split()[0]
            if 'x' in permissions:
                return [('execute', 'General', 'enable')]
            return [('execute', 'General','disable')]
        except subprocess.CalledProcessError:
            return ["Error fetching permission"]

    def get_macos_permissions(self, app_name):
        #place holder
        return [
            ("location", "General", "enable"),
            ("Access Media", "General", "enable"),
            ("microphone", "General","disable"),
             ("Camera", "Hidden","disable"),
            ("Background Activity", "Hidden", "enable")

        ]
    def change_windows_permission(self, app_name, permission, action):
        #place holder
        print(f"Changing permission {permission} for {app_name} to {action}")

    def change_linux_permission(self, app_name, permission, action, category):
        try:
            if permission == 'execute':
                 if action == 'disable':
                       subprocess.run(['chmod', '-x', app_name], check=True)
                 elif action == 'enable':
                        subprocess.run(['chmod', '+x', app_name], check=True)
                 print(f"Changing permission {permission} for {app_name} to {action}")

        except subprocess.CalledProcessError:
            print(f"Error while Changing permission {permission} for {app_name} to {action}")

    def change_macos_permission(self, app_name, permission, action):
       #place holder
        print(f"Changing permission {permission} for {app_name} to {action}")