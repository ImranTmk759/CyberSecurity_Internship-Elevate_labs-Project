import sys
import os
import sqlite3
import threading
import time
import json
import subprocess
from dataclasses import dataclass, asdict
from typing import Optional, List, Dict, Any

from PyQt5.QtWidgets import (
    QApplication, QWidget, QVBoxLayout, QPushButton, QLabel,
    QTableWidget, QTableWidgetItem, QHBoxLayout, QLineEdit, QMessageBox,
    QComboBox, QCheckBox, QHeaderView
)
from PyQt5.QtCore import pyqtSignal, QObject, Qt

from scapy.all import sniff, IP, TCP, UDP, Raw, Ether

DB_PATH = "packet_audit.db"
RULES_PATH = "rules.json"
MAX_DISPLAY_PACKETS = 200  

class Rule:
    id: int
    action: str  
    src_ip: Optional[str] = None
    dst_ip: Optional[str] = None
    src_port: Optional[int] = None
    dst_port: Optional[int] = None
    protocol: Optional[str] = None  
    description: Optional[str] = None
    enabled: bool = True
    enforce_iptables: bool = False

    def matches_packet(self, pkt: Dict[str, Any]) -> bool:
        """Given a packet dict, return True if rule matches it."""
        if not self.enabled:
            return False
        # protocol
        if self.protocol and self.protocol.lower() != 'any':
            if pkt['proto'].lower() != self.protocol.lower():
                return False
        if self.src_ip and self.src_ip != pkt['src']:
            return False
        if self.dst_ip and self.dst_ip != pkt['dst']:
            return False
        if self.src_port and pkt['sport'] is not None:
            if int(self.src_port) != int(pkt['sport']):
                return False
        if self.dst_port and pkt['dport'] is not None:
            if int(self.dst_port) != int(pkt['dport']):
                return False
        return True
# DB & rules
def init_db():
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("""
        CREATE TABLE IF NOT EXISTS packets (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ts REAL,
            src TEXT,
            dst TEXT,
            sport INTEGER,
            dport INTEGER,
            proto TEXT,
            summary TEXT,
            raw BLOB
        )
    """)
    conn.commit()
    conn.close()

def log_packet(pkt: Dict[str, Any]):
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("""
        INSERT INTO packets (ts, src, dst, sport, dport, proto, summary, raw)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
    """, (pkt['ts'], pkt['src'], pkt['dst'], pkt['sport'], pkt['dport'], pkt['proto'], pkt['summary'], pkt['raw'] or b''))
    conn.commit()
    conn.close()

def load_rules() -> List[Rule]:
    if not os.path.exists(RULES_PATH):
        return []
    with open(RULES_PATH, 'r') as f:
        data = json.load(f)
    rules = [Rule(**r) for r in data]
    return rules

def save_rules(rules: List[Rule]):
    with open(RULES_PATH, 'w') as f:
        json.dump([asdict(r) for r in rules], f, indent=2)
# iptables
def iptables_add_block_rule(rule: Rule) -> bool:
    # Build basic command: iptables -I INPUT -s <ip> -p tcp --dport <port> -j DROP
    cmd = ["iptables", "-I", "INPUT", "1"]
    if rule.src_ip:
        cmd += ["-s", rule.src_ip]
    if rule.dst_ip:
        cmd += ["-d", rule.dst_ip]
    if rule.protocol and rule.protocol.lower() in ("tcp", "udp"):
        cmd += ["-p", rule.protocol.lower()]
    if rule.dst_port and rule.protocol and rule.protocol.lower() in ("tcp", "udp"):
        cmd += ["--dport", str(rule.dst_port)]
    cmd += ["-j", "DROP"]
    try:
        subprocess.check_call(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        return True
    except subprocess.CalledProcessError as e:
        print("iptables add failed:", e)
        return False

def iptables_remove_block_rule(rule: Rule) -> bool:
    cmd = ["iptables", "-D", "INPUT"]
    if rule.src_ip:
        cmd += ["-s", rule.src_ip]
    if rule.dst_ip:
        cmd += ["-d", rule.dst_ip]
    if rule.protocol and rule.protocol.lower() in ("tcp", "udp"):
        cmd += ["-p", rule.protocol.lower()]
    if rule.dst_port and rule.protocol and rule.protocol.lower() in ("tcp", "udp"):
        cmd += ["--dport", str(rule.dst_port)]
    cmd += ["-j", "DROP"]
    try:
        subprocess.check_call(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        return True
    except subprocess.CalledProcessError:
        
        return False

class RuleEngine:
    def __init__(self):
        self._rules: List[Rule] = load_rules()
        self.lock = threading.Lock()
        self.next_id = max((r.id for r in self._rules), default=0) + 1

    def get_rules(self) -> List[Rule]:
        with self.lock:
            return list(self._rules)

    def add_rule(self, rule_data: Dict[str, Any]) -> Rule:
        with self.lock:
            r = Rule(id=self.next_id, **rule_data)
            self._rules.append(r)
            self.next_id += 1
            save_rules(self._rules)
        return r

    def remove_rule(self, rule_id: int) -> bool:
        with self.lock:
            for r in self._rules:
                if r.id == rule_id:
                    if r.enforce_iptables:
                        iptables_remove_block_rule(r)
                    self._rules.remove(r)
                    save_rules(self._rules)
                    return True
            return False

    def toggle_rule(self, rule_id: int, enabled: bool) -> bool:
        with self.lock:
            for r in self._rules:
                if r.id == rule_id:
                    r.enabled = enabled
                    save_rules(self._rules)
                    return True
            return False

    def apply_rule_iptables(self, rule_id: int, enable: bool) -> bool:
        with self.lock:
            for r in self._rules:
                if r.id == rule_id:
                    r.enforce_iptables = enable
                    save_rules(self._rules)
                    if enable and r.action == 'block':
                        return iptables_add_block_rule(r)
                    elif not enable and r.action == 'block':
                        return iptables_remove_block_rule(r)
                    return True
            return False

    def evaluate_packet(self, pkt: Dict[str, Any]) -> Optional[Rule]:
        """
        Evaluate packet against rules in order. Return matching rule or None.
        """
        with self.lock:
            for r in self._rules:
                if r.matches_packet(pkt):
                    return r
        return None

rule_engine = RuleEngine()

# Sniffer

class SnifferThread(threading.Thread):
    def __init__(self, gui_signaler):
        super().__init__(daemon=True)
        self.gui_signal = gui_signaler
        self._running = threading.Event()
        self._running.set()

    def stop(self):
        self._running.clear()

    def run(self):
    
        def process(pkt):
            if not self._running.is_set():
                return False  
               if not pkt.haslayer(IP):
                return
            ip = pkt.getlayer(IP)
            proto = ""
            sport = None
            dport = None
            if pkt.haslayer(TCP):
                proto = "tcp"
                sport = pkt[TCP].sport
                dport = pkt[TCP].dport
            elif pkt.haslayer(UDP):
                proto = "udp"
                sport = pkt[UDP].sport
                dport = pkt[UDP].dport
            else:
                proto = "ip"

            summary = pkt.summary()
            pkt_dict = {
                "ts": time.time(),
                "src": ip.src,
                "dst": ip.dst,
                "sport": sport,
                "dport": dport,
                "proto": proto,
                "summary": summary,
                "raw": bytes(pkt) if pkt is not None else b''
            }

            
            matching_rule = rule_engine.evaluate_packet(pkt_dict)
            if matching_rule:
                
                if matching_rule.action == 'block':
                    log_packet(pkt_dict)
                    self.gui_signal.packet_detected.emit(pkt_dict, True, matching_rule.id)
                else:
                    
                    self.gui_signal.packet_detected.emit(pkt_dict, False, matching_rule.id)
            else:
            
                self.gui_signal.packet_detected.emit(pkt_dict, False, None)

        try:
            sniff(prn=process, store=0)
        except Exception as e:
            print("Sniffer stopped or error:", e)

class GuiSignaler(QObject):
    packet_detected = pyqtSignal(object, bool, object)  
    
class MainWindow(QWidget):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("NetMonitor - Live Packet Monitor & Rule Manager")
        self.resize(1000, 600)
        self.signaler = GuiSignaler()
        self.signaler.packet_detected.connect(self.on_packet)

        self.sniffer = SnifferThread(self.signaler)
        self.sniffer.start()

        
        layout = QVBoxLayout()
        top_bar = QHBoxLayout()

        self.start_btn = QPushButton("Start Sniffing")
        self.stop_btn = QPushButton("Stop Sniffing")
        self.start_btn.clicked.connect(self.start_sniff)
        self.stop_btn.clicked.connect(self.stop_sniff)
        self.stop_btn.setEnabled(True)
        self.start_btn.setEnabled(False)

        self.enforce_checkbox = QCheckBox("Auto enforce iptables for new 'block' rules (requires root)")
        top_bar.addWidget(self.start_btn)
        top_bar.addWidget(self.stop_btn)
        top_bar.addWidget(self.enforce_checkbox)
        top_bar.addStretch()

        layout.addLayout(top_bar)

        # Packet table
        self.table = QTableWidget(0, 6)
        self.table.setHorizontalHeaderLabels(["Time", "Src", "Dst", "Sport", "Dport", "Proto / Summary"])
        self.table.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        layout.addWidget(QLabel("Live packets (most recent at top). Suspicious packets highlighted red."))
        layout.addWidget(self.table)

    
        rule_layout = QHBoxLayout()
        self.action_combo = QComboBox()
        self.action_combo.addItems(["block", "allow"])
        self.src_ip_input = QLineEdit(); self.src_ip_input.setPlaceholderText("src IP (optional)")
        self.dst_ip_input = QLineEdit(); self.dst_ip_input.setPlaceholderText("dst IP (optional)")
        self.sport_input = QLineEdit(); self.sport_input.setPlaceholderText("src port (optional)")
        self.dport_input = QLineEdit(); self.dport_input.setPlaceholderText("dst port (optional)")
        self.proto_combo = QComboBox(); self.proto_combo.addItems(["any", "tcp", "udp", "ip"])
        self.desc_input = QLineEdit(); self.desc_input.setPlaceholderText("description (optional)")
        add_rule_btn = QPushButton("Add Rule")
        add_rule_btn.clicked.connect(self.add_rule_clicked)

        rule_layout.addWidget(QLabel("Action"))
        rule_layout.addWidget(self.action_combo)
        rule_layout.addWidget(self.src_ip_input)
        rule_layout.addWidget(self.dst_ip_input)
        rule_layout.addWidget(self.sport_input)
        rule_layout.addWidget(self.dport_input)
        rule_layout.addWidget(self.proto_combo)
        rule_layout.addWidget(self.desc_input)
        rule_layout.addWidget(add_rule_btn)
        layout.addLayout(rule_layout)

        
        self.rules_table = QTableWidget(0, 7)
        self.rules_table.setHorizontalHeaderLabels(["ID", "Action", "Src", "Dst", "SPort", "DPort", "Proto"])
        self.rules_table.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        layout.addWidget(QLabel("Rules (select a row to toggle/delete/enforce)"))
        layout.addWidget(self.rules_table)

        rules_btn_row = QHBoxLayout()
        self.toggle_rule_btn = QPushButton("Enable/Disable Rule")
        self.toggle_rule_btn.clicked.connect(self.toggle_selected_rule)
        self.delete_rule_btn = QPushButton("Delete Rule")
        self.delete_rule_btn.clicked.connect(self.delete_selected_rule)
        self.enforce_rule_btn = QPushButton("Toggle iptables Enforcement (block rules only)")
        self.enforce_rule_btn.clicked.connect(self.enforce_selected_rule)
        rules_btn_row.addWidget(self.toggle_rule_btn)
        rules_btn_row.addWidget(self.delete_rule_btn)
        rules_btn_row.addWidget(self.enforce_rule_btn)
        rules_btn_row.addStretch()
        layout.addLayout(rules_btn_row)

        self.setLayout(layout)

        self.load_rules_to_table()

    def start_sniff(self):
        if not self.sniffer.is_alive():
            self.sniffer = SnifferThread(self.signaler)
            self.sniffer.start()
        self.start_btn.setEnabled(False)
        self.stop_btn.setEnabled(True)

    def stop_sniff(self):
        self.sniffer.stop()
        self.start_btn.setEnabled(True)
        self.stop_btn.setEnabled(False)

    def on_packet(self, pkt_dict, suspicious: bool, rule_id):
        # Insert at top
        self.table.insertRow(0)
        t_item = QTableWidgetItem(time.strftime("%H:%M:%S", time.localtime(pkt_dict['ts'])))
        t_item.setFlags(Qt.ItemIsEnabled)
        self.table.setItem(0, 0, t_item)
        self.table.setItem(0, 1, QTableWidgetItem(pkt_dict['src']))
        self.table.setItem(0, 2, QTableWidgetItem(pkt_dict['dst']))
        self.table.setItem(0, 3, QTableWidgetItem(str(pkt_dict['sport']) if pkt_dict['sport'] else ""))
        self.table.setItem(0, 4, QTableWidgetItem(str(pkt_dict['dport']) if pkt_dict['dport'] else ""))
        proto_summary = f"{pkt_dict['proto']} / {pkt_dict['summary']}"
        self.table.setItem(0, 5, QTableWidgetItem(proto_summary))
        if suspicious:
            for col in range(6):
                self.table.item(0, col).setBackground(Qt.red)
        # keep size bounded
        if self.table.rowCount() > MAX_DISPLAY_PACKETS:
            self.table.removeRow(self.table.rowCount() - 1)

    def add_rule_clicked(self):
        rd = {
            "action": self.action_combo.currentText(),
            "src_ip": self.src_ip_input.text() or None,
            "dst_ip": self.dst_ip_input.text() or None,
            "src_port": int(self.sport_input.text()) if self.sport_input.text().isdigit() else None,
            "dst_port": int(self.dport_input.text()) if self.dport_input.text().isdigit() else None,
            "protocol": self.proto_combo.currentText(),
            "description": self.desc_input.text() or None,
            "enabled": True,
            "enforce_iptables": False
        }
        new_rule = rule_engine.add_rule(rd)
        # If user wants auto-enforce for block rules, apply
        if self.enforce_checkbox.isChecked() and new_rule.action == 'block':
            ok = rule_engine.apply_rule_iptables(new_rule.id, True)
            if ok:
                new_rule.enforce_iptables = True
            else:
                QMessageBox.warning(self, "iptables", "Could not add iptables rule. Are you root?")
        self.load_rules_to_table()

    def load_rules_to_table(self):
        rules = rule_engine.get_rules()
        self.rules_table.setRowCount(0)
        for r in rules:
            row = self.rules_table.rowCount()
            self.rules_table.insertRow(row)
            self.rules_table.setItem(row, 0, QTableWidgetItem(str(r.id)))
            self.rules_table.setItem(row, 1, QTableWidgetItem(r.action + (" (ENF)" if r.enforce_iptables else "")))
            self.rules_table.setItem(row, 2, QTableWidgetItem(r.src_ip or ""))
            self.rules_table.setItem(row, 3, QTableWidgetItem(r.dst_ip or ""))
            self.rules_table.setItem(row, 4, QTableWidgetItem(str(r.src_port) if r.src_port else ""))
            self.rules_table.setItem(row, 5, QTableWidgetItem(str(r.dst_port) if r.dst_port else ""))
            self.rules_table.setItem(row, 6, QTableWidgetItem(r.protocol or "any"))

    def get_selected_rule_id(self) -> Optional[int]:
        sel = self.rules_table.selectionModel().selectedRows()
        if not sel:
            QMessageBox.information(self, "Selection", "Select a rule row first.")
            return None
        row = sel[0].row()
        item = self.rules_table.item(row, 0)
        if not item:
            return None
        return int(item.text())

    def toggle_selected_rule(self):
        rid = self.get_selected_rule_id()
        if rid is None:
            return
        # find current and toggle
        rules = rule_engine.get_rules()
        for r in rules:
            if r.id == rid:
                rule_engine.toggle_rule(rid, not r.enabled)
                break
        self.load_rules_to_table()

    def delete_selected_rule(self):
        rid = self.get_selected_rule_id()
        if rid is None:
            return
        confirm = QMessageBox.question(self, "Delete", f"Delete rule {rid}?")
        if confirm != QMessageBox.Yes:
            return
        success = rule_engine.remove_rule(rid)
        if not success:
            QMessageBox.warning(self, "Delete", "Could not delete rule (not found).")
        self.load_rules_to_table()

    def enforce_selected_rule(self):
        rid = self.get_selected_rule_id()
        if rid is None:
            return
        rules = rule_engine.get_rules()
        target = None
        for r in rules:
            if r.id == rid:
                target = r
        if not target:
            QMessageBox.warning(self, "Error", "Rule not found.")
            return
        if target.action != 'block':
            QMessageBox.information(self, "Enforce", "iptables enforcement only supported for 'block' rules.")
            return
        desired = not target.enforce_iptables
        ok = rule_engine.apply_rule_iptables(rid, desired)
        if not ok:
            QMessageBox.warning(self, "iptables", "Operation failed. Are you root?")
        self.load_rules_to_table()

    def closeEvent(self, event):
        # Clean up
        try:
            self.sniffer.stop()
        except Exception:
            pass
        event.accept()

def main():
 
    init_db()

    app = QApplication(sys.argv)
    w = MainWindow()
    w.show()
    sys.exit(app.exec_())

if __name__ == "__main__":
    main()


