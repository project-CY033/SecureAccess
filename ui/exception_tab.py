from PyQt5.QtWidgets import QWidget, QVBoxLayout, QLabel, QListWidget, QPushButton, QHBoxLayout, QInputDialog, QAbstractItemView
from PyQt5.QtCore import Qt

class ExceptionTab(QWidget):
    def __init__(self, config, main_window):
        super().__init__()
        self.config = config
        self.main_window = main_window
        layout = QVBoxLayout()

        self.list_widget = QListWidget()
        self.list_widget.setSelectionMode(QAbstractItemView.ExtendedSelection)
        self.update_list()
        layout.addWidget(self.list_widget)

        button_layout = QHBoxLayout()
        add_button = QPushButton("Add Exception")
        add_button.clicked.connect(self.add_exception)

        remove_button = QPushButton("Remove Exceptions")
        remove_button.clicked.connect(self.remove_exception)

        button_layout.addWidget(add_button)
        button_layout.addWidget(remove_button)

        layout.addLayout(button_layout)
        self.setLayout(layout)
        self.main_window.exception_tab = self

    def update_list(self):
        self.list_widget.clear()
        for app in self.config['excluded_apps']:
            self.list_widget.addItem(app)


    def add_exception(self):
        text, ok = QInputDialog.getText(self, 'Add Exception', 'Enter Application Name:')
        if ok and text:
           if text not in self.config['excluded_apps']:
                self.config['excluded_apps'].append(text)
                self.update_list()

    def remove_exception(self):
        selected_items = self.list_widget.selectedItems()
        for item in selected_items:
             self.config['excluded_apps'].remove(item.text())
        self.update_list()