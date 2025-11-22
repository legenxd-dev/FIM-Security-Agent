import sys
import os
import json
import hashlib
import time
import requests
from datetime import datetime
from cryptography.fernet import Fernet
from plyer import notification

from PyQt6.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout, 
    QLabel, QPushButton, QListWidget, QListWidgetItem, QTextEdit, 
    QSystemTrayIcon, QMenu, QMessageBox, QFileDialog, QFrame, 
    QSlider, QComboBox, QCheckBox, QDialog, QLineEdit, QDialogButtonBox,
    QSizePolicy
)
from PyQt6.QtCore import Qt, QThread, pyqtSignal, QTimer, QSize
from PyQt6.QtGui import QIcon, QAction, QColor, QCursor

# ==========================================
# 0. STYLESHEET
# ==========================================
CHECK_ICON_B64 = "url(data:image/svg+xml;base64,PHN2ZyB4bWxucz0iaHR0cDovL3d3dy53My5vcmcvMjAwMC9zdmciIHdpZHRoPSIyNCIgaGVpZ2h0PSIyNCIgdmlld0JveD0iMCAwIDI0IDI0IiBmaWxsPSJub25lIiBzdHJva2U9IndoaXRlIiBzdHJva2Utd2lkdGg9IjMiIHN0cm9rZS1saW5lY2FwPSJyb3VuZCIgc3Ryb2tlLWxpbmVqb2luPSJyb3VuZCI+PHBvbHlsaW5lIHBvaW50cz0iMjAgNiA5IDE3IDQgMTIiLz48L3N2Zz4=)"

APP_STYLE = f"""
QMainWindow {{ background-color: #1e1e1e; }}
QWidget {{ color: #e0e0e0; font-family: 'Segoe UI', sans-serif; font-size: 14px; }}
QFrame#Sidebar {{ background-color: #252526; border-right: 1px solid #333; }}
QLabel#LogoTitle {{ color: #007acc; font-size: 22px; font-weight: bold; }}
QLabel#VersionText {{ color: #666; font-size: 11px; }}
QPushButton {{ background-color: #333; color: white; border: 1px solid #444; padding: 8px 15px; border-radius: 4px; text-align: left; }}
QPushButton:hover {{ background-color: #3e3e42; border-color: #555; }}
QPushButton:pressed {{ background-color: #007acc; }}
QPushButton#BlueBtn {{ background-color: #007acc; text-align: center; font-weight: bold; border: none; }}
QPushButton#BlueBtn:hover {{ background-color: #0062a3; }}
QPushButton#RedBtn {{ background-color: transparent; border: 1px solid #d32f2f; color: #d32f2f; text-align: center; }}
QPushButton#RedBtn:hover {{ background-color: #d32f2f; color: white; }}
QPushButton#BtnClear {{ background-color: #3a3a3a; color: #aaa; border: none; padding: 0px; font-size: 11px; border-radius: 4px; text-align: center; }}
QPushButton#BtnClear:hover {{ background-color: #444; color: white; }}
QPushButton#BtnRemove {{ background-color: #444; color: #ddd; padding: 4px 8px; font-size: 11px; border: none; text-align: center; }}
QPushButton#BtnRemove:hover {{ background-color: #666; color: white; }}
QPushButton#BtnWipe {{ background-color: #8a1c1c; color: #ffcccc; padding: 4px 8px; font-size: 11px; border: none; text-align: center; }}
QPushButton#BtnWipe:hover {{ background-color: #d32f2f; color: white; }}
QListWidget {{ background-color: #1e1e1e; border: 1px solid #333; border-radius: 6px; outline: none; }}
QListWidget::item {{ border-bottom: 1px solid #2d2d2d; }}
QListWidget::item:hover {{ background-color: #2d2d2d; }}
QTextEdit {{ background-color: #111; border: 1px solid #333; border-radius: 5px; color: #ccc; font-family: 'Consolas'; }}
QComboBox {{ background-color: #333; border: 1px solid #444; padding: 4px; }}
QSlider::groove:horizontal {{ height: 6px; background: #2d2d2d; border-radius: 3px; }}
QSlider::handle:horizontal {{ background: #007acc; width: 14px; height: 14px; margin: -4px 0; border-radius: 7px; }}
QCheckBox {{ spacing: 8px; color: #ccc; }}
QCheckBox::indicator {{ width: 18px; height: 18px; border-radius: 4px; border: 1px solid #555; background: #2d2d2d; }}
QCheckBox::indicator:unchecked:hover {{ border-color: #777; }}
QCheckBox::indicator:checked {{ background-color: #007acc; border-color: #007acc; image: {CHECK_ICON_B64}; }}
QFrame#StatCard {{ background-color: #252526; border-radius: 8px; }}
QLabel#CardValue {{ font-size: 28px; font-weight: bold; color: white; }}
QLabel#CardLabel {{ font-size: 11px; color: #888; font-weight: bold; text-transform: uppercase; }}
"""

# ==========================================
# 1. BACKEND ENGINE
# ==========================================
class FIMBackend:
    def __init__(self):
        self.data_dir = "fim_data"
        if not os.path.exists(self.data_dir):
            os.makedirs(self.data_dir)

        self.db_file = os.path.join(self.data_dir, "fim_db.enc")
        self.key_file = os.path.join(self.data_dir, "secret.key")
        self.config_file = os.path.join(self.data_dir, "config.json")
        
        self.monitored_folders = []
        self.api_key = ""
        
        self.check_crypto_setup()
        self.load_settings()

    def check_crypto_setup(self):
        if os.path.exists(self.key_file):
            with open(self.key_file, "rb") as f: self.key = f.read()
        else:
            self.key = Fernet.generate_key()
            with open(self.key_file, "wb") as f: f.write(self.key)

    def load_settings(self):
        if os.path.exists(self.config_file):
            try:
                with open(self.config_file, 'r') as f:
                    data = json.load(f)
                    self.api_key = data.get("api_key", "")
                    self.monitored_folders = data.get("targets", [])
            except: pass

    def save_settings(self, new_key=None):
        if new_key is not None: self.api_key = new_key
        with open(self.config_file, 'w') as f:
            json.dump({"api_key": self.api_key, "targets": self.monitored_folders}, f)

    def encrypt_data(self, raw_str): return Fernet(self.key).encrypt(raw_str.encode())
    def decrypt_data(self, enc_bytes): return Fernet(self.key).decrypt(enc_bytes).decode()

    def read_db(self):
        if not os.path.exists(self.db_file): return {}
        try:
            with open(self.db_file, 'rb') as f: return json.loads(self.decrypt_data(f.read()))
        except: return {}

    def write_db(self, data):
        try:
            with open(self.db_file, 'wb') as f: f.write(self.encrypt_data(json.dumps(data)))
            return True
        except: return False

    def delete_folder_records(self, folder_path):
        db = self.read_db()
        if not db: return False
        new_db = {k: v for k, v in db.items() if not k.startswith(folder_path)}
        if len(db) != len(new_db):
            self.write_db(new_db)
            return True
        return False

    def calculate_hash(self, file_path):
        sha256 = hashlib.sha256()
        try:
            with open(file_path, "rb") as f:
                for block in iter(lambda: f.read(4096), b""):
                    sha256.update(block)
            return sha256.hexdigest()
        except: return None

    def check_virustotal(self, file_hash):
        if not self.api_key: return None
        url = f"https://www.virustotal.com/api/v3/files/{file_hash}"
        headers = {"x-apikey": self.api_key}
        try:
            response = requests.get(url, headers=headers)
            if response.status_code == 200:
                stats = response.json()['data']['attributes']['last_analysis_stats']
                return stats['malicious']
        except: pass
        return None

# ==========================================
# 2. WORKER THREAD
# ==========================================
class WorkerThread(QThread):
    log_signal = pyqtSignal(str, str)
    stats_signal = pyqtSignal(int, int, int, int)
    threat_signal = pyqtSignal()

    def __init__(self, backend, task_type="scan"):
        super().__init__()
        self.backend = backend
        self.task_type = task_type
        self._is_running = True

    def stop(self):
        self._is_running = False

    def run(self):
        if self.task_type == "baseline": self.create_baseline()
        else: self.scan_files()

    def create_baseline(self):
        if not self.backend.monitored_folders:
            self.log_signal.emit("[-] No folders selected to monitor.", "#f44336")
            return
        
        self.log_signal.emit("[*] Building baseline...", "#3498db")
        db = self.backend.read_db() 
        files_processed = 0
        
        for folder in self.backend.monitored_folders:
            if not os.path.exists(folder): continue
            for root, _, files in os.walk(folder):
                for file in files:
                    if not self._is_running: return
                    full_path = os.path.join(root, file)
                    file_hash = self.backend.calculate_hash(full_path)
                    if file_hash: 
                        db[full_path] = file_hash
                        files_processed += 1
        
        if self.backend.write_db(db):
            self.log_signal.emit(f"[✓] Baseline updated ({files_processed} files).", "#2ecc71")
            self.stats_signal.emit(files_processed, 0, 0, 0)

    def scan_files(self):
        saved_db = self.backend.read_db()
        if not saved_db:
            self.log_signal.emit("[-] Baseline missing. Please create one first.", "#f44336")
            return

        current_state = {}
        for folder in self.backend.monitored_folders:
            if not os.path.exists(folder): continue
            for root, _, files in os.walk(folder):
                for file in files:
                    if not self._is_running: return
                    full_path = os.path.join(root, file)
                    h = self.backend.calculate_hash(full_path)
                    if h: current_state[full_path] = h

        if not self._is_running: return

        modified = 0
        deleted = 0
        new_files = 0
        
        relevant_db = {k:v for k,v in saved_db.items() if any(k.startswith(t) for t in self.backend.monitored_folders)}

        for path, old_hash in relevant_db.items():
            if not self._is_running: return
            new_hash = current_state.get(path)
            filename = os.path.basename(path)
            
            if new_hash is None:
                self.log_signal.emit(f"[!] DELETED: {filename}", "#e74c3c")
                deleted += 1
            elif new_hash != old_hash:
                self.log_signal.emit(f"[!] MODIFIED: {filename}", "#e67e22")
                modified += 1
                threat_level = self.backend.check_virustotal(new_hash)
                if threat_level and threat_level > 0:
                    self.log_signal.emit(f"    [☣] THREAT ALERT: {filename} ({threat_level})", "#9b59b6")
                    self.threat_signal.emit()
        
        for path in current_state:
            if not self._is_running: return
            if path not in saved_db:
                filename = os.path.basename(path)
                self.log_signal.emit(f"[+] NEW FILE: {filename}", "#3498db")
                new_files += 1
                h = current_state[path]
                threat_level = self.backend.check_virustotal(h)
                if threat_level and threat_level > 0:
                    self.log_signal.emit(f"    [☣] THREAT ALERT: {filename} ({threat_level})", "#9b59b6")
                    self.threat_signal.emit()

        self.stats_signal.emit(len(current_state), modified, deleted, new_files)
        if modified + deleted + new_files == 0:
            self.log_signal.emit("[✓] System integrity verified. No changes.", "#2ecc71")

# ==========================================
# 3. CUSTOM WIDGETS
# ==========================================
class DashboardCard(QFrame):
    def __init__(self, title, top_color):
        super().__init__()
        self.setObjectName("StatCard")
        self.setStyleSheet(f"#StatCard {{ border-top: 3px solid {top_color}; }}")
        layout = QVBoxLayout()
        self.value_lbl = QLabel("0")
        self.value_lbl.setObjectName("CardValue")
        self.value_lbl.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.title_lbl = QLabel(title)
        self.title_lbl.setObjectName("CardLabel")
        self.title_lbl.setAlignment(Qt.AlignmentFlag.AlignCenter)
        layout.addWidget(self.value_lbl)
        layout.addWidget(self.title_lbl)
        self.setLayout(layout)

    def set_value(self, value): self.value_lbl.setText(str(value))
    def get_value(self): return int(self.value_lbl.text())

class CustomListRow(QWidget):
    def __init__(self, path, remove_callback, wipe_callback):
        super().__init__()
        layout = QHBoxLayout()
        layout.setContentsMargins(5, 5, 5, 5)
        layout.setSpacing(10)
        icon = QLabel("📂")
        icon.setStyleSheet("color: #888; font-size: 16px; border: none; margin-left: 5px;")
        self.path_text = QLabel(path)
        self.path_text.setStyleSheet("color: #ddd; font-weight: bold; border: none;")
        self.path_text.setSizePolicy(QSizePolicy.Policy.Ignored, QSizePolicy.Policy.Preferred)
        
        btn_remove = QPushButton("REMOVE")
        btn_remove.setObjectName("BtnRemove")
        btn_remove.setCursor(QCursor(Qt.CursorShape.PointingHandCursor))
        btn_remove.setFixedWidth(60) 
        btn_remove.clicked.connect(lambda: remove_callback(path))
        
        btn_wipe = QPushButton("WIPE")
        btn_wipe.setObjectName("BtnWipe")
        btn_wipe.setCursor(QCursor(Qt.CursorShape.PointingHandCursor))
        btn_wipe.setFixedWidth(50) 
        btn_wipe.clicked.connect(lambda: wipe_callback(path))
        
        layout.addWidget(icon)
        layout.addWidget(self.path_text, 1) 
        layout.addWidget(btn_remove, 0)
        layout.addWidget(btn_wipe, 0)
        self.setLayout(layout)

# ==========================================
# 4. MAIN WINDOW
# ==========================================
class AppWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.backend = FIMBackend()
        self.real_quit = False
        self.worker = None

        self.setWindowTitle("FIM | Endpoint Security")
        self.setGeometry(100, 100, 1250, 800)
        self.setMinimumSize(1000, 600)
        
        self.init_tray()
        self.init_ui()
        self.auto_timer = QTimer()
        self.auto_timer.timeout.connect(self.trigger_scan)

    def init_tray(self):
        self.tray = QSystemTrayIcon(self)
        self.tray.setIcon(self.style().standardIcon(self.style().StandardPixmap.SP_ComputerIcon))
        menu = QMenu()
        act_show = QAction("Show Agent", self); act_show.triggered.connect(self.show_window)
        act_quit = QAction("Quit", self); act_quit.triggered.connect(self.quit_app)
        menu.addAction(act_show); menu.addAction(act_quit)
        self.tray.setContextMenu(menu)
        self.tray.show()

    def closeEvent(self, event):
        if not self.real_quit:
            event.ignore()
            self.hide()
            self.tray.showMessage("FIM Security", "Agent running in background.", QSystemTrayIcon.MessageIcon.Information, 2000)
        else:
            if self.worker and self.worker.isRunning():
                self.worker.stop()
                self.worker.wait()
            event.accept()

    def show_window(self):
        self.show()
        self.setWindowState(Qt.WindowState.WindowActive)
        self.activateWindow()

    def quit_app(self):
        self.real_quit = True
        self.tray.hide() 
        QApplication.instance().quit() 

    def init_ui(self):
        central_widget = QWidget()
        self.setCentralWidget(central_widget)
        main_box = QHBoxLayout(central_widget); main_box.setContentsMargins(0, 0, 0, 0); main_box.setSpacing(0)

        # --- SIDEBAR ---
        sidebar = QFrame(); sidebar.setObjectName("Sidebar"); sidebar.setFixedWidth(260)
        side_layout = QVBoxLayout(sidebar); side_layout.setContentsMargins(20, 40, 20, 40); side_layout.setSpacing(15)

        lbl_logo = QLabel("🛡️ FIM AGENT"); lbl_logo.setObjectName("LogoTitle"); lbl_logo.setAlignment(Qt.AlignmentFlag.AlignCenter)
        lbl_ver = QLabel("by Legenxd v1.3"); lbl_ver.setObjectName("VersionText"); lbl_ver.setAlignment(Qt.AlignmentFlag.AlignCenter)
        div = QFrame(); div.setFixedHeight(1); div.setStyleSheet("background-color: #333;")

        btn_add = QPushButton("  + Add Folder"); btn_add.setObjectName("BlueBtn"); btn_add.setCursor(QCursor(Qt.CursorShape.PointingHandCursor)); btn_add.clicked.connect(self.action_add_folder)
        self.btn_base = QPushButton("  Update Baseline"); self.btn_base.setCursor(QCursor(Qt.CursorShape.PointingHandCursor)); self.btn_base.clicked.connect(self.trigger_baseline)
        self.btn_manual = QPushButton("  Manual Scan"); self.btn_manual.setCursor(QCursor(Qt.CursorShape.PointingHandCursor)); self.btn_manual.clicked.connect(self.trigger_scan)
        self.btn_api = QPushButton("  API Settings"); self.btn_api.setCursor(QCursor(Qt.CursorShape.PointingHandCursor)); self.btn_api.clicked.connect(self.action_api_settings)
        btn_reset = QPushButton("Factory Reset"); btn_reset.setObjectName("RedBtn"); btn_reset.setCursor(QCursor(Qt.CursorShape.PointingHandCursor)); btn_reset.clicked.connect(self.action_factory_reset)

        side_layout.addWidget(lbl_logo); side_layout.addWidget(lbl_ver); side_layout.addWidget(div); side_layout.addSpacing(20)
        side_layout.addWidget(btn_add); side_layout.addWidget(self.btn_base); side_layout.addWidget(self.btn_manual); side_layout.addWidget(self.btn_api); side_layout.addStretch(); side_layout.addWidget(btn_reset)

        # --- CONTENT ---
        content = QWidget(); content.setStyleSheet("background-color: #1e1e1e;")
        cont_layout = QVBoxLayout(content); cont_layout.setContentsMargins(30, 30, 30, 30); cont_layout.setSpacing(20)

        # Stats
        stats_box = QHBoxLayout()
        self.card_tot = DashboardCard("TOTAL", "#007acc")
        self.card_mod = DashboardCard("MODIFIED", "#ff9800")
        self.card_del = DashboardCard("DELETED", "#f44336")
        self.card_new = DashboardCard("NEW ITEMS", "#2ecc71")
        self.card_mal = DashboardCard("THREATS", "#9b59b6")
        for c in [self.card_tot, self.card_mod, self.card_del, self.card_new, self.card_mal]: stats_box.addWidget(c)

        # Middle
        mid_box = QHBoxLayout()
        list_con = QFrame(); list_con.setStyleSheet("background-color: #252526; border-radius: 10px;")
        lc_lay = QVBoxLayout(list_con)
        lh = QHBoxLayout()
        lbl_mon = QLabel("Monitored Directories"); lbl_mon.setStyleSheet("font-weight: bold; border: none;")
        btn_clear = QPushButton("Clear List"); btn_clear.setObjectName("BtnClear"); btn_clear.setFixedSize(90, 30); btn_clear.setCursor(QCursor(Qt.CursorShape.PointingHandCursor)); btn_clear.clicked.connect(self.action_clear_list)
        lh.addWidget(lbl_mon); lh.addStretch(); lh.addWidget(btn_clear)
        self.folder_list_widget = QListWidget(); self.folder_list_widget.setStyleSheet("background-color: #1e272e; border: none;")
        self.refresh_list_ui()
        lc_lay.addLayout(lh); lc_lay.addWidget(self.folder_list_widget)

        auto_con = QFrame(); auto_con.setFixedWidth(320); auto_con.setStyleSheet("background-color: #2c3e50; border-radius: 10px;")
        ac_lay = QVBoxLayout(auto_con)
        ac_lay.addWidget(QLabel("Auto-Guard Configuration"))
        self.slider = QSlider(Qt.Orientation.Horizontal); self.slider.setRange(1, 60); self.slider.setValue(10); self.slider.valueChanged.connect(self.ui_update_interval_label)
        self.combo_time = QComboBox(); self.combo_time.addItems(["Sec", "Min", "Hour"])
        self.lbl_interval = QLabel("Interval: 10 Sec"); self.lbl_interval.setStyleSheet("color: #aaa; font-size: 12px; border:none;")
        self.chk_active = QCheckBox("Enable Auto-Guard"); self.chk_active.setCursor(QCursor(Qt.CursorShape.PointingHandCursor)); self.chk_active.stateChanged.connect(self.action_toggle_timer)
        ac_lay.addWidget(self.lbl_interval); ac_lay.addWidget(self.slider); ac_lay.addWidget(self.combo_time); ac_lay.addStretch(); ac_lay.addWidget(self.chk_active)

        mid_box.addWidget(list_con); mid_box.addWidget(auto_con)

        # Logs
        self.console = QTextEdit(); self.console.setReadOnly(True); self.console.setStyleSheet("background-color: black; color: #ccc; font-family: Consolas; border-radius: 10px; padding: 10px;")
        
        cont_layout.addLayout(stats_box); cont_layout.addLayout(mid_box); cont_layout.addWidget(QLabel("System Event Log")); cont_layout.addWidget(self.console)
        main_box.addWidget(sidebar); main_box.addWidget(content)
        self.log_to_ui("System initialized. Ready.", "green")

    # --- LOGIC ---
    def log_to_ui(self, message, color="white"):
        t = datetime.now().strftime("%H:%M:%S")
        c_map = {"green": "#2ecc71", "red": "#e74c3c", "blue": "#3498db", "orange": "#f39c12", "purple": "#9b59b6", "gray": "#7f8c8d"}
        hex_c = c_map.get(color, color)
        self.console.append(f'<span style="color:{hex_c}">[{t}] {message}</span>')

    def refresh_list_ui(self):
        self.folder_list_widget.clear()
        for path in self.backend.monitored_folders:
            item = QListWidgetItem(self.folder_list_widget)
            row = CustomListRow(path, self.action_remove_path, self.action_wipe_path)
            item.setSizeHint(row.sizeHint())
            self.folder_list_widget.setItemWidget(item, row)

    def ui_update_interval_label(self):
        self.lbl_interval.setText(f"Interval: {self.slider.value()} {self.combo_time.currentText()}")

    def action_add_folder(self):
        d = QFileDialog.getExistingDirectory(self, "Select Folder")
        if d:
            if d not in self.backend.monitored_folders:
                self.backend.monitored_folders.append(d)
                self.backend.save_settings()
                self.refresh_list_ui()
                self.log_to_ui(f"Added: {d}", "blue")

    def action_remove_path(self, path):
        if path in self.backend.monitored_folders:
            self.backend.monitored_folders.remove(path)
            self.backend.save_settings()
            self.refresh_list_ui()
            self.log_to_ui(f"Stopped monitoring: {path}", "orange")

    def action_wipe_path(self, path):
        if QMessageBox.question(self, "Wipe Data", f"Delete records for:\n{path}?", QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No) == QMessageBox.StandardButton.Yes:
            self.action_remove_path(path)
            if self.backend.delete_folder_records(path): self.log_to_ui(f"WIPED: {path}", "red")
            else: self.log_to_ui("No data found.", "gray")

    def action_clear_list(self):
        self.backend.monitored_folders.clear(); self.backend.save_settings(); self.refresh_list_ui(); self.log_to_ui("List cleared.", "orange")

    def action_factory_reset(self):
        if QMessageBox.critical(self, "Factory Reset", "Delete ALL data? Irreversible.", QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No) == QMessageBox.StandardButton.Yes:
            if os.path.exists(self.backend.db_file): os.remove(self.backend.db_file)
            self.action_clear_list(); self.update_stats_cards(0,0,0,0); self.log_to_ui("Factory Reset Done.", "red")

    def action_api_settings(self):
        d = QDialog(self); d.setWindowTitle("API Settings"); l = QVBoxLayout(d)
        i = QLineEdit(self.backend.api_key); i.setEchoMode(QLineEdit.EchoMode.Password)
        b = QDialogButtonBox(QDialogButtonBox.StandardButton.Save | QDialogButtonBox.StandardButton.Cancel)
        b.accepted.connect(d.accept); b.rejected.connect(d.reject)
        l.addWidget(QLabel("VirusTotal API Key:")); l.addWidget(i); l.addWidget(b)
        if d.exec() == QDialog.DialogCode.Accepted:
            self.backend.save_settings(i.text()); self.log_to_ui("API Key Saved.", "green")

    def action_toggle_timer(self, state):
        if state:
            val = self.slider.value(); u = self.combo_time.currentText()
            sec = val * 3600 if u == "Hour" else val * 60 if u == "Min" else val
            self.auto_timer.start(sec * 1000); self.log_to_ui("Auto-Guard STARTED.", "green")
            self.slider.setEnabled(False); self.combo_time.setEnabled(False)
        else:
            self.auto_timer.stop(); self.log_to_ui("Auto-Guard PAUSED.", "orange")
            self.slider.setEnabled(True); self.combo_time.setEnabled(True)

    def trigger_baseline(self):
        if self.worker and self.worker.isRunning(): return
        self.worker = WorkerThread(self.backend, "baseline")
        self.worker.log_signal.connect(self.log_to_ui); self.worker.stats_signal.connect(self.update_stats_cards)
        self.worker.start()

    def trigger_scan(self):
        if self.worker and self.worker.isRunning(): return
        self.worker = WorkerThread(self.backend, "scan")
        self.worker.log_signal.connect(self.log_to_ui); self.worker.stats_signal.connect(self.update_stats_cards); self.worker.threat_signal.connect(self.handle_threat)
        self.worker.start()

    def update_stats_cards(self, t, m, d, n):
        self.card_tot.set_value(t); self.card_mod.set_value(m); self.card_del.set_value(d); self.card_new.set_value(n)

    def handle_threat(self):
        curr = self.card_mal.get_value(); self.card_mal.set_value(curr + 1)
        if not self.isVisible(): notification.notify(title="FIM Alert", message="Threat Detected!", app_name="FIM", timeout=5)

if __name__ == "__main__":
    app = QApplication(sys.argv)
    app.setQuitOnLastWindowClosed(False)
    app.setStyleSheet(APP_STYLE)
    w = AppWindow()
    w.show()
    sys.exit(app.exec())