from PyQt5.QtWidgets import QWidget, QVBoxLayout, QLabel, QComboBox

class SettingsTab(QWidget):
    def __init__(self, config, main_window):
        super().__init__()
        self.config = config
        self.main_window = main_window

        layout = QVBoxLayout()
        alert_label = QLabel("Alert Level")
        self.alert_combo = QComboBox()
        self.alert_combo.addItems(['Low', 'Medium', 'High'])
        self.alert_combo.setCurrentText(self.config['alert_level'])
        self.alert_combo.currentIndexChanged.connect(self.update_alert_level)

        layout.addWidget(alert_label)
        layout.addWidget(self.alert_combo)
        self.setLayout(layout)


    def update_alert_level(self,index):
        self.config['alert_level'] = self.alert_combo.currentText()