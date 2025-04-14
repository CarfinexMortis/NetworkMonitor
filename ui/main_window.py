from PyQt5.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QPushButton, QLabel,
    QHBoxLayout, QFrame, QTableWidget, QTableWidgetItem, QHeaderView, QCheckBox,
    QComboBox, QSpinBox, QGroupBox, QLineEdit, QMessageBox, QTabWidget, QMenu
)
from PyQt5.QtGui import QIcon, QColor, QFont
from PyQt5.QtCore import Qt, QSize
from monitor.sniffer import NetworkSniffer
from database.db_manager import (
    init_db, save_log, get_all_logs,
    add_to_blacklist, remove_from_blacklist, get_blacklist, is_ip_blacklisted,
    get_setting, set_setting
)
from tests.threat_simulator import ThreatSimulator
import sys
import threading


class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Network Monitor")
        self.setGeometry(100, 100, 1200, 900)
        self.sniffer = None
        self.settings = {}
        
        # Initialize database and load settings
        self.init_db()
        self.load_settings()
        
        # Set application style
        self.setStyleSheet("""
            QMainWindow {
                background-color: #f5f7fa;
            }
            QGroupBox {
                border: 1px solid #d1d5db;
                border-radius: 6px;
                margin-top: 10px;
                padding-top: 15px;
                font-weight: bold;
            }
            QGroupBox::title {
                subcontrol-origin: margin;
                left: 10px;
                padding: 0 5px;
            }
            QTableWidget {
                border: 1px solid #d1d5db;
                border-radius: 6px;
                background-color: white;
            }
            QHeaderView::section {
                background-color: #3b82f6;
                color: white;
                padding: 5px;
                border: none;
            }
            QLineEdit {
                border: 1px solid #d1d5db;
                border-radius: 4px;
                padding: 5px;
                background-color: white;
            }
            QSpinBox {
                border: 1px solid #d1d5db;
                border-radius: 4px;
                padding: 5px;
                background-color: white;
            }
        """)
        
        self.initUI()
        self.setup_threat_simulation()

    def init_db(self):
        """Initialize the database"""
        try:
            init_db()
        except Exception as e:
            QMessageBox.critical(self, "Database Error", f"Failed to initialize database: {str(e)}")

    def load_settings(self):
        """Load application settings from database"""
        self.settings = {
            'notifications_enabled': get_setting('notifications_enabled', '1') == '1',
            'log_level': get_setting('log_level', 'Medium'),
            'auto_blacklist_threshold': int(get_setting('auto_blacklist_threshold', '5')),
            'log_retention_days': int(get_setting('log_retention_days', '30')),
            'start_minimized': get_setting('start_minimized', '0') == '1'
        }

    def initUI(self):
        """Initialize the UI layout"""
        main_widget = QWidget()
        main_layout = QHBoxLayout()
        main_layout.setContentsMargins(0, 0, 0, 0)
        main_layout.setSpacing(0)

        # Sidebar menu
        sidebar = self.create_sidebar()
        
        # Separator line
        line = QFrame()
        line.setFrameShape(QFrame.VLine)
        line.setFrameShadow(QFrame.Sunken)
        line.setStyleSheet("background-color: #d1d5db;")

        # Main content area with tabs
        self.tab_widget = QTabWidget()
        self.tab_widget.tabBar().hide()
        self.tab_widget.setStyleSheet("""
            QTabWidget::pane {
                border: none;
                padding: 10px;
            }
        """)
        
        self.create_dashboard_tab()
        self.create_logs_tab()
        self.create_blacklist_tab()
        self.create_settings_tab()
        
        main_layout.addLayout(sidebar, 1)
        main_layout.addWidget(line)
        main_layout.addWidget(self.tab_widget, 5)

        main_widget.setLayout(main_layout)
        self.setCentralWidget(main_widget)

    def create_sidebar(self):
        """Create the sidebar menu"""
        sidebar = QVBoxLayout()
        sidebar.setContentsMargins(10, 20, 10, 20)
        sidebar.setSpacing(10)
        
        # App title
        title = QLabel("Network Monitor")
        title.setStyleSheet("""
            QLabel {
                font-size: 18px;
                font-weight: bold;
                color: #1e40af;
                padding: 10px;
                border-bottom: 2px solid #3b82f6;
                margin-bottom: 20px;
            }
        """)
        title.setAlignment(Qt.AlignCenter)
        sidebar.addWidget(title)

        buttons = [
            ("Monitoring", "icons/dashboard.png", lambda: self.tab_widget.setCurrentIndex(0)),
            ("Logs", "icons/logs.png", lambda: self.tab_widget.setCurrentIndex(1)),
            ("Blacklist", "icons/blacklist.png", lambda: self.tab_widget.setCurrentIndex(2)),
            ("Settings", "icons/settings.png", lambda: self.tab_widget.setCurrentIndex(3))
        ]

        for text, icon, handler in buttons:
            btn = QPushButton(text)
            btn.setIcon(QIcon(icon))
            btn.setIconSize(QSize(24, 24))
            btn.setStyleSheet("""
                QPushButton {
                    padding: 12px 15px;
                    font-size: 14px;
                    text-align: left;
                    border-radius: 6px;
                    color: #1f2937;
                    background-color: transparent;
                }
                QPushButton:hover {
                    background-color: #e5e7eb;
                }
                QPushButton:pressed {
                    background-color: #d1d5db;
                }
            """)
            btn.clicked.connect(handler)
            sidebar.addWidget(btn)

        sidebar.addStretch()
        
        # Version info
        version = QLabel("v1.0.0")
        version.setStyleSheet("color: #6b7280; font-size: 12px;")
        version.setAlignment(Qt.AlignCenter)
        sidebar.addWidget(version)
        
        return sidebar

    def create_dashboard_tab(self):
        """Create the dashboard/monitoring tab"""
        tab = QWidget()
        layout = QVBoxLayout()
        layout.setContentsMargins(15, 15, 15, 15)
        layout.setSpacing(15)

        # Monitoring controls
        control_layout = QHBoxLayout()
        control_layout.setSpacing(15)
        
        self.btn_start_monitoring = QPushButton("Start Monitoring")
        self.btn_start_monitoring.setIcon(QIcon("icons/start.png"))
        self.btn_start_monitoring.setStyleSheet("""
            QPushButton {
                padding: 10px 20px;
                font-size: 14px;
                background-color: #10b981;
                color: white;
                border-radius: 6px;
                min-width: 150px;
            }
            QPushButton:hover {
                background-color: #0d9f6e;
            }
            QPushButton:pressed {
                background-color: #0b845d;
            }
        """)
        self.btn_start_monitoring.clicked.connect(self.toggle_monitoring)

        # Auto-blacklist threshold
        threshold_label = QLabel("Auto-blacklist threshold:")
        threshold_label.setStyleSheet("font-weight: bold;")
        
        self.threshold_spinbox = QSpinBox()
        self.threshold_spinbox.setRange(1, 20)
        self.threshold_spinbox.setValue(self.settings['auto_blacklist_threshold'])
        self.threshold_spinbox.setStyleSheet("""
            QSpinBox {
                padding: 5px;
                min-width: 60px;
            }
        """)
        
        # Simulate Threat button
        self.btn_simulate_threat = QPushButton("Simulate Threat")
        self.btn_simulate_threat.setIcon(QIcon("icons/warning.png"))
        self.btn_simulate_threat.setStyleSheet("""
            QPushButton {
                padding: 10px 20px;
                font-size: 14px;
                background-color: #f59e0b;
                color: white;
                border-radius: 6px;
                min-width: 150px;
            }
            QPushButton:hover {
                background-color: #d97706;
            }
            QPushButton:pressed {
                background-color: #b45309;
            }
        """)
        
        control_layout.addWidget(self.btn_start_monitoring)
        control_layout.addWidget(threshold_label)
        control_layout.addWidget(self.threshold_spinbox)
        control_layout.addStretch()
        control_layout.addWidget(self.btn_simulate_threat)
        
        # IP table
        self.ip_table = QTableWidget()
        self.ip_table.setColumnCount(6)
        self.ip_table.setHorizontalHeaderLabels(["IP Address", "Protocol", "Port", "Country", "Provider", "Status"])
        self.ip_table.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        self.ip_table.setSelectionBehavior(QTableWidget.SelectRows)
        self.ip_table.setEditTriggers(QTableWidget.NoEditTriggers)
        self.ip_table.setStyleSheet("""
            QTableWidget {
                border-radius: 8px;
            }
            QTableWidget::item {
                padding: 5px;
            }
        """)
        
        # Context menu for IP table
        self.ip_table.setContextMenuPolicy(Qt.CustomContextMenu)
        self.ip_table.customContextMenuRequested.connect(self.show_ip_context_menu)

        layout.addLayout(control_layout)
        layout.addWidget(self.ip_table)
        tab.setLayout(layout)
        self.tab_widget.addTab(tab, QIcon("icons/dashboard.png"), "Monitoring")

    def setup_threat_simulation(self):
        """Configure threat simulation"""
        self.threat_simulator = ThreatSimulator(target_ip="127.0.0.1")
        
        # Create combo box for threat type selection
        self.threat_type_combo = QComboBox()
        for threat_type in self.threat_simulator.threat_types.keys():
            self.threat_type_combo.addItem(threat_type)
        
        # Add combo box to the dashboard tab layout
        dashboard_tab = self.tab_widget.widget(0)
        layout = dashboard_tab.layout()
        control_layout = layout.itemAt(0).layout()
        control_layout.insertWidget(4, QLabel("Threat Type:"))
        control_layout.insertWidget(5, self.threat_type_combo)
        
        # Connect the simulate threat button
        self.btn_simulate_threat.clicked.connect(self.run_threat_simulation)

    def run_threat_simulation(self):
        """Run selected threat simulation"""
        threat_type = self.threat_type_combo.currentText()
        QMessageBox.information(
            self,
            "Threat Simulation Started",
            f"Simulating {threat_type} attack pattern\n"
            "Check your monitor for detection alerts."
        )
        
        # Run in separate thread to avoid UI freezing
        thread = threading.Thread(
            target=self.threat_simulator.simulate_threat,
            args=(threat_type,),
            daemon=True
        )
        thread.start()

    def create_logs_tab(self):
        """Create the logs tab"""
        tab = QWidget()
        layout = QVBoxLayout()
        layout.setContentsMargins(15, 15, 15, 15)
        layout.setSpacing(15)

        # Log table
        self.log_table = QTableWidget()
        self.log_table.setColumnCount(6)
        self.log_table.setHorizontalHeaderLabels(["IP Address", "Protocol", "Port", "Country", "Provider", "Timestamp"])
        self.log_table.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        self.log_table.setSortingEnabled(True)
        self.log_table.setStyleSheet("""
            QTableWidget {
                border-radius: 8px;
            }
            QTableWidget::item {
                padding: 5px;
            }
        """)
        
        # Refresh button
        refresh_btn = QPushButton("Refresh Logs")
        refresh_btn.setIcon(QIcon("icons/refresh.png"))
        refresh_btn.setStyleSheet("""
            QPushButton {
                padding: 8px 15px;
                background-color: #3b82f6;
                color: white;
                border-radius: 6px;
            }
            QPushButton:hover {
                background-color: #2563eb;
            }
            QPushButton:pressed {
                background-color: #1d4ed8;
            }
        """)
        refresh_btn.clicked.connect(self.refresh_logs)
        
        btn_layout = QHBoxLayout()
        btn_layout.addStretch()
        btn_layout.addWidget(refresh_btn)
        
        layout.addLayout(btn_layout)
        layout.addWidget(self.log_table)
        tab.setLayout(layout)
        self.tab_widget.addTab(tab, QIcon("icons/logs.png"), "Logs")
        self.refresh_logs()

    def create_blacklist_tab(self):
        """Create the blacklist management tab"""
        tab = QWidget()
        layout = QVBoxLayout()
        layout.setContentsMargins(15, 15, 15, 15)
        layout.setSpacing(15)

        # Add to blacklist controls
        add_group = QGroupBox("Add to Blacklist")
        add_layout = QVBoxLayout()
        
        ip_layout = QHBoxLayout()
        ip_layout.addWidget(QLabel("IP Address:"))
        self.ip_input = QLineEdit()
        self.ip_input.setPlaceholderText("e.g., 192.168.1.1")
        ip_layout.addWidget(self.ip_input)
        
        reason_layout = QHBoxLayout()
        reason_layout.addWidget(QLabel("Reason:"))
        self.reason_input = QLineEdit()
        self.reason_input.setPlaceholderText("Optional reason for blacklisting")
        reason_layout.addWidget(self.reason_input)
        
        add_btn = QPushButton("Add to Blacklist")
        add_btn.setIcon(QIcon("icons/block.png"))
        add_btn.setStyleSheet("""
            QPushButton {
                padding: 8px 15px;
                background-color: #ef4444;
                color: white;
                border-radius: 6px;
            }
            QPushButton:hover {
                background-color: #dc2626;
            }
            QPushButton:pressed {
                background-color: #b91c1c;
            }
        """)
        add_btn.clicked.connect(lambda: self.add_to_blacklist_ui())
        
        add_layout.addLayout(ip_layout)
        add_layout.addLayout(reason_layout)
        add_layout.addWidget(add_btn, 0, Qt.AlignRight)
        add_group.setLayout(add_layout)

        # Blacklist table
        self.blacklist_table = QTableWidget()
        self.blacklist_table.setColumnCount(3)
        self.blacklist_table.setHorizontalHeaderLabels(["IP Address", "Reason", "Actions"])
        self.blacklist_table.horizontalHeader().setSectionResizeMode(0, QHeaderView.Stretch)
        self.blacklist_table.horizontalHeader().setSectionResizeMode(1, QHeaderView.Stretch)
        self.blacklist_table.setColumnWidth(2, 120)
        self.blacklist_table.setEditTriggers(QTableWidget.NoEditTriggers)
        self.blacklist_table.setStyleSheet("""
            QTableWidget {
                border-radius: 8px;
            }
            QTableWidget::item {
                padding: 5px;
            }
        """)

        layout.addWidget(add_group)
        layout.addWidget(self.blacklist_table)
        tab.setLayout(layout)
        self.tab_widget.addTab(tab, QIcon("icons/blacklist.png"), "Blacklist")
        self.refresh_blacklist()

    def create_settings_tab(self):
        """Create the settings tab"""
        tab = QWidget()
        layout = QVBoxLayout()
        layout.setContentsMargins(15, 15, 15, 15)
        layout.setSpacing(20)

        # Notification settings
        notif_group = QGroupBox("Notification Settings")
        notif_layout = QVBoxLayout()
        self.notif_checkbox = QCheckBox("Enable desktop notifications")
        self.notif_checkbox.setChecked(self.settings['notifications_enabled'])
        notif_layout.addWidget(self.notif_checkbox)
        notif_group.setLayout(notif_layout)

        # Logging settings
        log_group = QGroupBox("Logging Settings")
        log_layout = QVBoxLayout()
        
        log_level_layout = QHBoxLayout()
        log_level_layout.addWidget(QLabel("Logging level:"))
        self.log_level_combo = QComboBox()
        self.log_level_combo.addItems(["Low", "Medium", "High"])
        self.log_level_combo.setCurrentText(self.settings['log_level'])
        self.log_level_combo.setStyleSheet("padding: 5px; min-width: 150px;")
        log_level_layout.addWidget(self.log_level_combo)
        log_level_layout.addStretch()
        
        log_retention_layout = QHBoxLayout()
        log_retention_layout.addWidget(QLabel("Log retention (days):"))
        self.log_retention_spinbox = QSpinBox()
        self.log_retention_spinbox.setRange(1, 365)
        self.log_retention_spinbox.setValue(self.settings['log_retention_days'])
        log_retention_layout.addWidget(self.log_retention_spinbox)
        log_retention_layout.addStretch()
        
        log_layout.addLayout(log_level_layout)
        log_layout.addLayout(log_retention_layout)
        log_group.setLayout(log_layout)

        # Behavior settings
        behavior_group = QGroupBox("Behavior Settings")
        behavior_layout = QVBoxLayout()
        self.start_minimized_checkbox = QCheckBox("Start minimized to system tray")
        self.start_minimized_checkbox.setChecked(self.settings['start_minimized'])
        behavior_layout.addWidget(self.start_minimized_checkbox)
        behavior_group.setLayout(behavior_layout)

        # Save button
        save_btn = QPushButton("Save Settings")
        save_btn.setIcon(QIcon("icons/save.png"))
        save_btn.setStyleSheet("""
            QPushButton {
                padding: 10px 20px;
                background-color: #3b82f6;
                color: white;
                border-radius: 6px;
                min-width: 150px;
            }
            QPushButton:hover {
                background-color: #2563eb;
            }
            QPushButton:pressed {
                background-color: #1d4ed8;
            }
        """)
        save_btn.clicked.connect(self.save_settings)

        layout.addWidget(notif_group)
        layout.addWidget(log_group)
        layout.addWidget(behavior_group)
        layout.addStretch()
        
        btn_layout = QHBoxLayout()
        btn_layout.addStretch()
        btn_layout.addWidget(save_btn)
        layout.addLayout(btn_layout)
        
        tab.setLayout(layout)
        self.tab_widget.addTab(tab, QIcon("icons/settings.png"), "Settings")

    def toggle_monitoring(self):
        """Start or stop network monitoring"""
        if self.sniffer and self.sniffer.isRunning():
            self.stop_monitoring()
        else:
            self.start_monitoring()

    def start_monitoring(self):
        """Start network monitoring"""
        self.sniffer = NetworkSniffer()
        self.sniffer.new_ip_signal.connect(self.update_ip_table)
        self.sniffer.threat_detected.connect(self.handle_threat)
        self.sniffer.blacklist_updated.connect(self.refresh_blacklist)
        self.sniffer.set_blacklist_threshold(self.threshold_spinbox.value())
        self.sniffer.start()
        
        self.btn_start_monitoring.setText("Stop Monitoring")
        self.btn_start_monitoring.setIcon(QIcon("icons/stop.png"))
        self.btn_start_monitoring.setStyleSheet("""
            QPushButton {
                padding: 10px 20px;
                background-color: #ef4444;
                color: white;
                border-radius: 6px;
                min-width: 150px;
            }
            QPushButton:hover {
                background-color: #dc2626;
            }
            QPushButton:pressed {
                background-color: #b91c1c;
            }
        """)

    def stop_monitoring(self):
        """Stop network monitoring"""
        if self.sniffer:
            self.sniffer.stop()
            self.sniffer = None
        
        self.btn_start_monitoring.setText("Start Monitoring")
        self.btn_start_monitoring.setIcon(QIcon("icons/start.png"))
        self.btn_start_monitoring.setStyleSheet("""
            QPushButton {
                padding: 10px 20px;
                background-color: #10b981;
                color: white;
                border-radius: 6px;
                min-width: 150px;
            }
            QPushButton:hover {
                background-color: #0d9f6e;
            }
            QPushButton:pressed {
                background-color: #0b845d;
            }
        """)

    def update_ip_table(self, ip, protocol, port, country, provider):
        """Update the IP table with new data"""
        row = self.ip_table.rowCount()
        self.ip_table.insertRow(row)
        
        self.ip_table.setItem(row, 0, QTableWidgetItem(ip))
        self.ip_table.setItem(row, 1, QTableWidgetItem(protocol))
        self.ip_table.setItem(row, 2, QTableWidgetItem(str(port)))
        self.ip_table.setItem(row, 3, QTableWidgetItem(country))
        self.ip_table.setItem(row, 4, QTableWidgetItem(provider))
        
        # Check if IP is blacklisted
        status = "Blacklisted" if is_ip_blacklisted(ip) else "Normal"
        status_item = QTableWidgetItem(status)
        status_item.setForeground(QColor("#ef4444") if status == "Blacklisted" else QColor("#10b981"))
        
        font = QFont()
        font.setBold(True)
        status_item.setFont(font)
        
        self.ip_table.setItem(row, 5, status_item)

    def refresh_logs(self):
        """Refresh the logs table"""
        self.log_table.setRowCount(0)
        logs = get_all_logs()
        
        for row_num, log in enumerate(logs):
            self.log_table.insertRow(row_num)
            for col_num, data in enumerate(log):
                self.log_table.setItem(row_num, col_num, QTableWidgetItem(str(data)))

    def refresh_blacklist(self):
        """Refresh the blacklist table"""
        self.blacklist_table.setRowCount(0)
        blacklist = get_blacklist()
        
        for row_num, item in enumerate(blacklist):
            self.blacklist_table.insertRow(row_num)
            self.blacklist_table.setItem(row_num, 0, QTableWidgetItem(item[0]))  # IP
            self.blacklist_table.setItem(row_num, 1, QTableWidgetItem(item[1] if item[1] else "No reason"))  # Reason
            
            # Add remove button
            remove_btn = QPushButton("Remove")
            remove_btn.setIcon(QIcon("icons/unblock.png"))
            remove_btn.setStyleSheet("""
                QPushButton {
                    padding: 5px 10px;
                    background-color: #3b82f6;
                    color: white;
                    border-radius: 4px;
                }
                QPushButton:hover {
                    background-color: #2563eb;
                }
                QPushButton:pressed {
                    background-color: #1d4ed8;
                }
            """)
            remove_btn.clicked.connect(lambda _, ip=item[0]: self.remove_from_blacklist_ui(ip))
            self.blacklist_table.setCellWidget(row_num, 2, remove_btn)

    def add_to_blacklist_ui(self, ip=None):
        """Add an IP to blacklist from UI"""
        # If IP is not provided, get it from the input field
        if ip is None:
            ip = self.ip_input.text().strip()
        reason = self.reason_input.text().strip() or None
        
        if not ip:
            QMessageBox.warning(self, "Error", "Please enter an IP address")
            return
        
        if add_to_blacklist(ip, reason):
            self.refresh_blacklist()
            self.ip_input.clear()
            self.reason_input.clear()
            
            # Show success message
            msg = QMessageBox()
            msg.setIcon(QMessageBox.Information)
            msg.setWindowTitle("Success")
            msg.setText(f"IP {ip} added to blacklist")
            msg.exec_()
        else:
            QMessageBox.warning(self, "Error", f"Failed to add IP {ip} to blacklist")

    def remove_from_blacklist_ui(self, ip):
        """Remove an IP from blacklist from UI"""
        if remove_from_blacklist(ip):
            self.refresh_blacklist()
            
            # Show success message
            msg = QMessageBox()
            msg.setIcon(QMessageBox.Information)
            msg.setWindowTitle("Success")
            msg.setText(f"IP {ip} removed from blacklist")
            msg.exec_()
        else:
            QMessageBox.warning(self, "Error", f"Failed to remove IP {ip} from blacklist")

    def handle_threat(self, ip, message):
        """Handle threat detection"""
        if self.notif_checkbox.isChecked():
            msg = QMessageBox()
            msg.setIcon(QMessageBox.Warning)
            msg.setWindowTitle("Threat Detected")
            msg.setText(f"{message}\nIP: {ip}")
            msg.exec_()

    def show_ip_context_menu(self, position):
        """Show context menu for IP table"""
        menu = QMenu()
        menu.setStyleSheet("""
            QMenu {
                background-color: white;
                border: 1px solid #d1d5db;
                padding: 5px;
            }
            QMenu::item {
                padding: 5px 20px;
            }
            QMenu::item:selected {
                background-color: #e5e7eb;
                color: black;
            }
        """)
        
        selected_row = self.ip_table.rowAt(position.y())
        
        if selected_row >= 0:
            ip = self.ip_table.item(selected_row, 0).text()
            
            if not is_ip_blacklisted(ip):
                blacklist_action = menu.addAction(QIcon("icons/block.png"), "Add to Blacklist")
                blacklist_action.triggered.connect(lambda: self.add_to_blacklist_ui(ip))
            else:
                remove_action = menu.addAction(QIcon("icons/unblock.png"), "Remove from Blacklist")
                remove_action.triggered.connect(lambda: self.remove_from_blacklist_ui(ip))
            
            menu.exec_(self.ip_table.viewport().mapToGlobal(position))

    def save_settings(self):
        """Save application settings"""
        # Update settings from UI controls
        self.settings['notifications_enabled'] = self.notif_checkbox.isChecked()
        self.settings['log_level'] = self.log_level_combo.currentText()
        self.settings['auto_blacklist_threshold'] = self.threshold_spinbox.value()
        self.settings['log_retention_days'] = self.log_retention_spinbox.value()
        self.settings['start_minimized'] = self.start_minimized_checkbox.isChecked()
        
        # Save to database
        for name, value in self.settings.items():
            set_setting(name, value)
        
        # Show confirmation
        QMessageBox.information(self, "Settings Saved", "Settings have been saved successfully.")


if __name__ == "__main__":
    app = QApplication(sys.argv)
    app.setStyle("Fusion")
    
    window = MainWindow()
    window.show()
    sys.exit(app.exec_())