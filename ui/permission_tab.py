from PyQt5.QtWidgets import QWidget, QVBoxLayout, QTableWidget, QLabel, QPushButton, QHBoxLayout, QComboBox, QHeaderView, QAbstractItemView, QTableWidgetItem
from PyQt5.QtCore import Qt
from core.permission_manager import PermissionManager

class PermissionTab(QWidget):
    def __init__(self):
        super().__init__()
        layout = QVBoxLayout()

        self.app_list = QComboBox()
        layout.addWidget(QLabel("Select Application"))
        layout.addWidget(self.app_list)
        self.app_list.currentIndexChanged.connect(self.app_selected)

        self.permission_table = QTableWidget()
        self.permission_table.setColumnCount(4)
        self.permission_table.setHorizontalHeaderLabels(["Permission", "Category", "Condition", "Action"])
        self.permission_table.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        layout.addWidget(self.permission_table)
        self.permission_table.setEditTriggers(QAbstractItemView.NoEditTriggers)
        self.setLayout(layout)


        self.permission_manager = PermissionManager()
        self.selected_app = None

    def update_app_list(self, apps):
        self.app_list.clear()
        self.app_list.addItems(apps)


    def app_selected(self, index):
        self.selected_app = self.app_list.currentText()
        self.update_permission_table()


    def update_permission_table(self):
       self.permission_table.clearContents()
       self.permission_table.setRowCount(0)

       if self.selected_app:
            permissions = self.permission_manager.get_permissions(self.selected_app)
            if permissions:
                row = 0
                for permission_data in permissions:
                        permission, category, condition = permission_data
                        self.permission_table.insertRow(row)

                        self.permission_table.setItem(row, 0, QTableWidgetItem(permission))
                        self.permission_table.setItem(row, 1, QTableWidgetItem(category))
                        self.permission_table.setItem(row, 2, QTableWidgetItem(condition))

                        action_combo = QComboBox()
                        action_combo.addItems(['enable', 'disable'])
                        action_combo.setCurrentText(condition)

                        update_button = QPushButton("Update")
                        update_button.setProperty("row", row)
                        update_button.setProperty("permission", permission)
                        update_button.setProperty("category", category)
                        update_button.clicked.connect(self.update_permission)

                        hbox = QHBoxLayout()
                        hbox.addWidget(action_combo)
                        hbox.addWidget(update_button)
                        widget = QWidget()
                        widget.setLayout(hbox)
                        self.permission_table.setCellWidget(row, 3, widget)

                        row+=1


    def update_permission(self):
        sender = self.sender()
        row = sender.property("row")
        permission = sender.property("permission")
        category = sender.property("category")
        combo_box = self.permission_table.cellWidget(row, 3).layout().itemAt(0).widget()
        selected_action = combo_box.currentText()

        if self.selected_app:
             self.permission_manager.change_permission(self.selected_app, permission, selected_action, category)
             self.update_permission_table()