from PyQt5.QtWidgets import QWidget, QVBoxLayout, QListWidget, QAbstractItemView, QPushButton, QHBoxLayout
from core.app_list_manager import AppListManager
from PyQt5.QtCore import Qt

class ApplicationTab(QWidget):
    def __init__(self):
        super().__init__()
        layout = QVBoxLayout()
        self.app_list = QListWidget()
        self.app_list.setSelectionMode(QAbstractItemView.ExtendedSelection)
        layout.addWidget(self.app_list)


        button_layout = QHBoxLayout()
        permission_button = QPushButton("See Permission")
        permission_button.clicked.connect(self.see_permission)
        button_layout.addWidget(permission_button)
        layout.addLayout(button_layout)

        self.setLayout(layout)
        self.app_list_manager = AppListManager()
        self.update_list()


    def update_list(self):
        self.app_list.clear()
        for app in self.app_list_manager.get_installed_apps():
                self.app_list.addItem(app)

    def see_permission(self):
          selected_items = self.app_list.selectedItems()
          for item in selected_items:
             print(f"You select this app: {item.text()}")
             #Here I place placeholder for calling method for view and disable permission of the app
             