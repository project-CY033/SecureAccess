import sys
import json
from PyQt5.QtWidgets import QApplication, QMainWindow, QTabWidget
from ui.main_window import MainWindow
def load_config():
    try:
        with open('config.json', 'r') as f:
            return json.load(f)
    except FileNotFoundError:
        return {"excluded_apps": [], "alert_level": "high"}


def save_config(config):
    with open('config.json', 'w') as f:
        json.dump(config, f, indent=2)


if __name__ == '__main__':
    app = QApplication(sys.argv)
    config = load_config()
    window = MainWindow(config)
    window.show()

    app.exec_()
    save_config(window.config)