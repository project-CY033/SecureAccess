from PyQt5.QtWidgets import QWidget, QVBoxLayout, QTextEdit, QPushButton, QHBoxLayout, QInputDialog
from core.rules import RuleManager

class MonitorTab(QWidget):
    def __init__(self, main_window):
        super().__init__()
        self.main_window = main_window
        layout = QVBoxLayout()

        self.monitor_label = QTextEdit()
        self.monitor_label.setReadOnly(True)
        layout.addWidget(self.monitor_label)

        button_layout = QHBoxLayout()
        add_rule_button = QPushButton("Add Custom Rule")
        add_rule_button.clicked.connect(self.add_rule)
        remove_rule_button = QPushButton("Remove Rule")
        remove_rule_button.clicked.connect(self.remove_rule)
        button_layout.addWidget(add_rule_button)
        button_layout.addWidget(remove_rule_button)

        layout.addLayout(button_layout)
        self.setLayout(layout)

        self.rule_manager = RuleManager(main_window.config, self)

    def update_monitor_data(self,data):
        self.monitor_label.append(data)

    def add_rule(self):
        text, ok = QInputDialog.getText(self, 'Add Rule', 'Enter rule details: (e.g, src_ip=192.168.1.1 and dst_port=80):')
        if ok and text:
            self.rule_manager.add_rule(text)

    def remove_rule(self):
        text, ok = QInputDialog.getText(self, 'Remove Rule', 'Enter rule details to remove (e.g, src_ip=192.168.1.1 and dst_port=80):')
        if ok and text:
            self.rule_manager.remove_rule(text)