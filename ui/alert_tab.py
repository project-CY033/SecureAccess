from PyQt5.QtWidgets import QWidget, QVBoxLayout, QLabel, QTextEdit

class AlertTab(QWidget):
    def __init__(self):
        super().__init__()
        layout = QVBoxLayout()
        self.alert_label = QTextEdit()
        self.alert_label.setReadOnly(True)
        layout.addWidget(self.alert_label)

        self.setLayout(layout)

    def show_alert(self, message):
        self.alert_label.append(message)