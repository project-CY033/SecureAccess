from PyQt5.QtWidgets import QWidget, QVBoxLayout, QTextEdit, QPushButton, QComboBox, QLabel, QHBoxLayout
from PyQt5.QtCore import QThread, pyqtSignal
import scapy.all as scapy
from scapy.config import conf

class PacketCaptureThread(QThread):
    packet_signal = pyqtSignal(str)

    def __init__(self, main_window, iface):
        super().__init__()
        self.main_window = main_window
        self.stop_capture = False
        conf.L3socket = scapy.L3RawSocket  # ✅ Correct L3 socket for Windows (no Npcap)
        self.iface = iface

    def run(self):
        try:
            scapy.sniff(
                iface=self.iface,
                prn=self.process_packet,
                store=0,
                stop_filter=self.should_stop,  
                filter="ip"  # ✅ Only capture IP packets (avoids errors)
            )
        except Exception as e:
            self.packet_signal.emit(f"Error: {str(e)}")  # ✅ Notify UI if sniffing fails

    def process_packet(self, packet):
        self.packet_signal.emit(packet.summary())

    def should_stop(self, _):
        return self.stop_capture  # ✅ Thread-safe stop check

    def stop(self):
        self.stop_capture = True


class NetworkingTab(QWidget):
    def __init__(self, main_window):
        super().__init__()
        self.main_window = main_window
        layout = QVBoxLayout()

        self.packet_log = QTextEdit()
        self.packet_log.setReadOnly(True)
        layout.addWidget(self.packet_log)

        interface_layout = QHBoxLayout()
        interface_label = QLabel("Select Interface")
        self.interface_combo = QComboBox()
        self.update_interfaces()
        interface_layout.addWidget(interface_label)
        interface_layout.addWidget(self.interface_combo)
        layout.addLayout(interface_layout)

        self.start_button = QPushButton("Start Capture")
        self.start_button.clicked.connect(self.start_capture)
        layout.addWidget(self.start_button)

        self.stop_button = QPushButton("Stop Capture")
        self.stop_button.clicked.connect(self.stop_capture)
        self.stop_button.setEnabled(False)
        layout.addWidget(self.stop_button)

        self.setLayout(layout)

        self.capture_thread = None

    def update_interfaces(self):
        self.interface_combo.clear()
        self.interface_combo.addItems(scapy.get_if_list())

    def start_capture(self):
        self.start_button.setEnabled(False)
        self.stop_button.setEnabled(True)
        selected_interface = self.interface_combo.currentText()

        self.packet_log.clear()
        self.capture_thread = PacketCaptureThread(self.main_window, selected_interface)
        self.capture_thread.packet_signal.connect(self.update_packet_log)
        self.capture_thread.start()

    def stop_capture(self):
        if self.capture_thread:
            self.capture_thread.stop()
            self.capture_thread.wait()
            self.capture_thread = None  # ✅ Correctly placed

        self.start_button.setEnabled(True)
        self.stop_button.setEnabled(False)

    def update_packet_log(self, packet_summary):
        self.packet_log.append(packet_summary)
