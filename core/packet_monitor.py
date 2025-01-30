import scapy.all as scapy
import threading
from core.data_analyzer import DataAnalyzer
from core.rules import RuleManager
from scapy.config import conf
from scapy.sendrecv import socket


class PacketMonitor:
    def __init__(self, main_window, config):
        conf.L3socket = conf.L3socket6 = socket
        self.main_window = main_window
        self.analyzer = DataAnalyzer()
        self.stop_monitor = False
        self.rule_manager = RuleManager(config, self)


    def start_monitoring(self):
        self.stop_monitor = False
        threading.Thread(target=self.capture_packets,daemon=True).start()

    def stop_monitoring(self):
        self.stop_monitor = True

    def capture_packets(self):
        scapy.sniff(prn=self.process_packet, store=0, stop_filter= lambda x: self.stop_monitor)

    def process_packet(self, packet):
        summary = packet.summary()
        if self.rule_manager.match_rules(packet):
                self.main_window.monitor_tab.update_monitor_data(f"Packet Matched: {summary}\n")
        else:
               self.main_window.monitor_tab.update_monitor_data(f"Packet: {summary}\n")

        if self.analyzer.is_malicious(packet):
              self.main_window.alert_tab.show_alert(f"Malicious packet detected: {summary}")