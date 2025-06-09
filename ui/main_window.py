from PyQt5.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QPushButton, QLabel,
    QHBoxLayout, QFrame, QTableWidget, QTableWidgetItem, QHeaderView, QCheckBox,
    QComboBox, QSpinBox, QGroupBox, QLineEdit, QMessageBox, QTabWidget, QMenu,
    QDialog, QFormLayout, QTextEdit, QTextBrowser, QSizePolicy
)
from PyQt5.QtGui import QIcon, QColor, QFont, QPixmap
from PyQt5.QtCore import Qt, QSize, QTimer, QDateTime
from monitor.sniffer import NetworkSniffer
from database.db_manager import (
    init_db, save_log, get_all_logs,
    add_to_blacklist, remove_from_blacklist, get_blacklist, is_ip_blacklisted,
    get_setting, set_setting
)
import sys
from datetime import datetime
import subprocess
import socket
import requests
from collections import defaultdict
import matplotlib
matplotlib.use('Agg')
from matplotlib.backends.backend_qt5agg import FigureCanvasQTAgg as FigureCanvas
from matplotlib.figure import Figure
import numpy as np

class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Network Monitor")
        self.setGeometry(100, 100, 1200, 900)
        self.sniffer = None
        self.settings = {}
        self.protocol_stats = defaultdict(lambda: {
            'protocols': defaultdict(int),
            'ports': defaultdict(int),
            'first_seen': datetime.now(),
            'last_seen': datetime.now(),
            'total_packets': 0,
            'packet_sizes': [],
            'timestamps': []
        })
        
        self.init_db()
        self.load_settings()
        self.initUI()
        
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
            QDialog {
                background-color: #f5f7fa;
            }
        """)

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
            'auto_blacklist_threshold': int(get_setting('auto_blacklist_threshold', '10')),
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
        self.create_alerts_tab()
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
            ("Alerts", "icons/alert.png", lambda: self.tab_widget.setCurrentIndex(3)),
            ("Settings", "icons/settings.png", lambda: self.tab_widget.setCurrentIndex(4))
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
        version = QLabel("v2.1.")
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
        
        control_layout.addWidget(self.btn_start_monitoring)
        control_layout.addWidget(threshold_label)
        control_layout.addWidget(self.threshold_spinbox)
        control_layout.addStretch()
        
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
        
        # Context menu for logs
        self.log_table.setContextMenuPolicy(Qt.CustomContextMenu)
        self.log_table.customContextMenuRequested.connect(self.show_log_context_menu)
 
        # Buttons layout
        btn_layout = QHBoxLayout()
    
        # Clear logs button
        clear_logs_btn = QPushButton("Clear Logs")
        clear_logs_btn.setIcon(QIcon("icons/clear.png"))
        clear_logs_btn.setStyleSheet("""
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
        clear_logs_btn.clicked.connect(self.clear_logs)

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
        btn_layout.addWidget(clear_logs_btn)

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

    def create_alerts_tab(self):
        """Create the alerts/notifications tab"""
        tab = QWidget()
        layout = QVBoxLayout()
        layout.setContentsMargins(15, 15, 15, 15)
        layout.setSpacing(15)

        # Alerts table
        self.alerts_table = QTableWidget()
        self.alerts_table.setColumnCount(4)
        self.alerts_table.setHorizontalHeaderLabels(["Timestamp", "IP Address", "Severity", "Message"])
        self.alerts_table.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        self.alerts_table.setSortingEnabled(True)
        self.alerts_table.setEditTriggers(QTableWidget.NoEditTriggers)
        
        # Настроим стиль таблицы
        self.alerts_table.setStyleSheet("""
            QTableWidget {
                border-radius: 8px;
            }
            QTableWidget::item {
                padding: 5px;
            }
        """)
        
        # Кнопка очистки уведомлений
        clear_btn = QPushButton("Clear Alerts")
        clear_btn.setIcon(QIcon("icons/clear.png"))
        clear_btn.setStyleSheet("""
            QPushButton {
                padding: 8px 15px;
                background-color: #6b7280;
                color: white;
                border-radius: 6px;
            }
            QPushButton:hover {
                background-color: #4b5563;
            }
            QPushButton:pressed {
                background-color: #374151;
            }
        """)
        clear_btn.clicked.connect(self.clear_alerts)
        
        btn_layout = QHBoxLayout()
        btn_layout.addStretch()
        btn_layout.addWidget(clear_btn)
        
        layout.addLayout(btn_layout)
        layout.addWidget(self.alerts_table)
        tab.setLayout(layout)
        self.tab_widget.addTab(tab, QIcon("icons/alert.png"), "Alerts")

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

    def save_settings(self):
        """Save application settings to database"""
        try:
            # Update settings from UI controls
            self.settings = {
                'notifications_enabled': self.notif_checkbox.isChecked(),
                'log_level': self.log_level_combo.currentText(),
                'auto_blacklist_threshold': self.threshold_spinbox.value(),
                'log_retention_days': self.log_retention_spinbox.value(),
                'start_minimized': self.start_minimized_checkbox.isChecked()
            }

            # Save each setting to database
            set_setting('notifications_enabled', '1' if self.settings['notifications_enabled'] else '0')
            set_setting('log_level', self.settings['log_level'])
            set_setting('auto_blacklist_threshold', str(self.settings['auto_blacklist_threshold']))
            set_setting('log_retention_days', str(self.settings['log_retention_days']))
            set_setting('start_minimized', '1' if self.settings['start_minimized'] else '0')

            # Update threshold in sniffer if it's running
            if hasattr(self, 'sniffer') and self.sniffer and self.sniffer.isRunning():
                self.sniffer.set_blacklist_threshold(self.settings['auto_blacklist_threshold'])

            # Show success message
            QMessageBox.information(
                self, 
                "Settings Saved", 
                "All settings have been saved successfully"
            )
        except Exception as e:
            QMessageBox.critical(
                self, 
                "Error", 
                f"Failed to save settings: {str(e)}"
            )

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

    def clear_logs(self):
        """Clear all logs from database"""
        reply = QMessageBox.question(
        self, 
        "Confirm Clear",
        "Are you sure you want to clear all logs? This action cannot be undone.",
        QMessageBox.Yes | QMessageBox.No,
        QMessageBox.No
        )
    
        if reply == QMessageBox.Yes:
            try:
                from database.db_manager import clear_all_logs
                clear_all_logs()
                self.refresh_logs()
                QMessageBox.information(
                self, 
                "Logs Cleared", 
                "All logs have been successfully cleared"
                )
            except Exception as e:
                QMessageBox.critical(
                self, 
                "Error", 
                f"Failed to clear logs: {str(e)}"
                )

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
        """Handle threat detection by adding to alerts tab"""
        # Determine severity based on message content
        severity = "Medium"
        if "CRITICAL" in message or "Immediate" in message or "attack" in message.lower():
            severity = "High"
        elif "attempt" in message.lower():
            severity = "Low"
        
        # Add record to alerts table
        row = self.alerts_table.rowCount()
        self.alerts_table.insertRow(row)
        
        # Fill data
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        self.alerts_table.setItem(row, 0, QTableWidgetItem(timestamp))
        self.alerts_table.setItem(row, 1, QTableWidgetItem(ip))
        self.alerts_table.setItem(row, 2, QTableWidgetItem(severity))
        self.alerts_table.setItem(row, 3, QTableWidgetItem(message))
        
        # Set row color based on severity
        for col in range(4):
            item = self.alerts_table.item(row, col)
            if severity == "High":
                item.setBackground(QColor("#fee2e2"))  # light red
            elif severity == "Medium":
                item.setBackground(QColor("#fef3c7"))  # light yellow
            else:
                item.setBackground(QColor("#ecfdf5"))  # light green
        
        # Scroll to new record
        self.alerts_table.scrollToBottom()
        # Optionally flash the alerts tab to draw attention
        if self.tab_widget.currentIndex() != 3:  # If not already on alerts tab
            self.tab_widget.tabBar().setTabTextColor(3, QColor("#ef4444"))  # Red text
            QTimer.singleShot(2000, lambda: self.tab_widget.tabBar().setTabTextColor(3, QColor("#000000")))

    def clear_alerts(self):
        """Clear all alerts from the table"""
        self.alerts_table.setRowCount(0)

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

    def check_abuseipdb(self, ip):
        """Проверка IP через AbuseIPDB API"""
        API_KEY = "e86e84afcfe924fd8f368f5f9ffc859eecc9db3d0e19942505c447709f0eaf1d00f68abcc1357b0d"  
        url = f"https://api.abuseipdb.com/api/v2/check?ipAddress={ip}"
    
        headers = {
            'Accept': 'application/json',
            'Key': API_KEY
        }
    
        try:
            response = requests.get(url, headers=headers)
            if response.status_code == 200:
                return response.json()['data']
        except:
            return None
        return None

    def check_virustotal(self, ip):
        """Проверка IP через VirusTotal API"""
        API_KEY = "1e38f6f4b20132aad9ff01e1e47e8af8849a44bd2d2f23aff7dcd382d0ac6689"  
        url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip}"
    
        headers = {
            'x-apikey': API_KEY
        }
    
        try:
            response = requests.get(url, headers=headers)
            if response.status_code == 200:
                data = response.json()['data']
                attributes = data['attributes']
                return {
                    'malicious': attributes['last_analysis_stats']['malicious'],
                    'suspicious': attributes['last_analysis_stats']['suspicious'],
                    'harmless': attributes['last_analysis_stats']['harmless'],
                    'last_analysis_date': attributes['last_analysis_date']
                }
        except:
            return None
        return None

    def show_log_context_menu(self, position):
        """Show context menu for log table with additional actions"""
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
        
        selected_row = self.log_table.rowAt(position.y())
        
        if selected_row >= 0:
            # Получаем данные из выбранной строки
            ip = self.log_table.item(selected_row, 0).text()
            protocol = self.log_table.item(selected_row, 1).text()
            port = self.log_table.item(selected_row, 2).text()
            country = self.log_table.item(selected_row, 3).text()
            provider = self.log_table.item(selected_row, 4).text()
            timestamp = self.log_table.item(selected_row, 5).text()
            
            # Создаем действие для просмотра деталей
            details_action = menu.addAction(QIcon("icons/details.png"), "View Details")
            details_action.triggered.connect(lambda: self.show_log_details(
                ip, protocol, port, country, provider, timestamp
            ))
            
            # Добавляем действие для добавления в черный список, если IP еще не там
            if not is_ip_blacklisted(ip):
                blacklist_action = menu.addAction(QIcon("icons/block.png"), "Add to Blacklist")
                blacklist_action.triggered.connect(lambda: self.add_to_blacklist_ui(ip))
            
            menu.exec_(self.log_table.viewport().mapToGlobal(position))

    def show_log_details(self, ip, protocol, port, country, provider, timestamp):
        """Show detailed information about selected log in a dialog"""
        dialog = QDialog(self)
        dialog.setWindowTitle(f"Detailed Log Info - {ip}")
        dialog.setMinimumWidth(1100)  
        dialog.setMinimumHeight(900)  
    
        layout = QVBoxLayout()
        tab_widget = QTabWidget()
    
        # Basic Info Tab
        basic_tab = QWidget()
        basic_layout = QVBoxLayout()
        basic_layout.setContentsMargins(15, 15, 15, 15)
        basic_layout.setSpacing(20)
    
        # Security Status
        security_status = self.get_security_status(ip)
        basic_layout.addWidget(security_status)
    
        # Basic Info Group
        basic_info = QGroupBox("Basic Information")
        form_layout = QFormLayout()
        form_layout.setHorizontalSpacing(20)  # Увеличим расстояние между колонками
        form_layout.setVerticalSpacing(10)
    
        # Создадим стиль для меток и значений
        label_style = "font-weight: bold; min-width: 120px;"
        value_style = "min-width: 200px;"
    
        # Добавим строки с фиксированной шириной
        form_layout.addRow(QLabel("IP Address:"), QLabel(ip))
        form_layout.addRow(QLabel("Protocol:"), QLabel(protocol))
        form_layout.addRow(QLabel("Port:"), QLabel(f"{port} ({self.get_port_description(port)})"))
        form_layout.addRow(QLabel("Country:"), QLabel(country))
        form_layout.addRow(QLabel("Provider:"), QLabel(provider))
        form_layout.addRow(QLabel("First Seen:"), QLabel(timestamp))
    
        # DNS Lookup
        try:
            hostname = socket.gethostbyaddr(ip)[0]
            form_layout.addRow(QLabel("Hostname:"), QLabel(hostname))
        except:
            form_layout.addRow(QLabel("Hostname:"), QLabel("Unknown"))
    
        # Применим стили ко всем элементам формы
        for i in range(form_layout.rowCount()):
            label_item = form_layout.itemAt(i, QFormLayout.LabelRole)
            if label_item:
                label = label_item.widget()
                if label:
                    label.setStyleSheet(label_style)
                    label.setAlignment(Qt.AlignRight | Qt.AlignVCenter)
        
            field_item = form_layout.itemAt(i, QFormLayout.FieldRole)
            if field_item:
                field = field_item.widget()
                if field:
                    field.setStyleSheet(value_style)
                    field.setAlignment(Qt.AlignLeft | Qt.AlignVCenter)
    
        basic_info.setLayout(form_layout)
        basic_layout.addWidget(basic_info)
        basic_layout.addStretch()
        basic_tab.setLayout(basic_layout)
        tab_widget.addTab(basic_tab, "Basic Info")
    
        # Traffic Stats Tab
        stats_tab = QWidget()
        stats_layout = QVBoxLayout()
        stats_layout.setContentsMargins(5, 5, 5, 5)
        stats_layout.setSpacing(40)
    
        if ip in self.protocol_stats:
            stats = self.protocol_stats[ip]
        
            # Create matplotlib figure with one subplot for Top Ports
            fig = Figure(figsize=(10, 5), dpi=100)
            canvas = FigureCanvas(fig)
            ax = fig.add_subplot(111)

            # Top 10 ports
            ports = sorted(stats['ports'].items(), key=lambda x: x[1], reverse=True)[:10]
            port_nums = [str(p[0]) for p in ports]
            port_counts = [p[1] for p in ports]

            # Bar chart
            bars = ax.bar(port_nums, port_counts, color='#10b981')
            ax.set_title('Most Active Ports', fontsize=14, pad=15)
            ax.set_xlabel('Port Number')
            ax.set_ylabel('Packet Count')
            ax.tick_params(axis='x', labelrotation=45)
            ax.grid(axis='y', linestyle='--', alpha=0.7)

            # Highlight the most active port
            if bars:
                bars[0].set_color('#f59e0b')  # Orange highlight

            fig.tight_layout()
            stats_layout.addWidget(canvas)
        
            stats_group = QGroupBox("Traffic Statistics")
            stats_table_layout = QVBoxLayout()
        
            stats_table = QTableWidget()
            stats_table.setColumnCount(2)
            stats_table.setHorizontalHeaderLabels(["Metric", "Value"])
            stats_table.verticalHeader().setVisible(False)
            stats_table.setEditTriggers(QTableWidget.NoEditTriggers)
            stats_table.setSelectionBehavior(QTableWidget.SelectRows)
            stats_table.setStyleSheet("""
                QTableWidget {
                    border: 1px solid #d1d5db;
                    border-radius: 6px;
                }
                QHeaderView::section {
                    background-color: #3b82f6;
                    color: white;
                    padding: 5px;
                }
            """)
        
            stats_data = [
                ("Total Packets", str(stats['total_packets'])),
                ("Duration", f"{(stats['last_seen'] - stats['first_seen']).total_seconds():.1f} sec"),
                ("Protocols Used", str(len(stats['protocols']))),
                ("Ports Scanned", str(len(stats['ports']))),
                ("Avg Packet Rate", f"{stats['total_packets']/max(1, (stats['last_seen'] - stats['first_seen']).total_seconds()):.1f} pkt/sec"),
                ("Most Active Port", f"{max(stats['ports'].items(), key=lambda x: x[1])[0]} ({max(stats['ports'].values())} pkts)"),
                ("Avg Packet Size", f"{np.mean(stats['packet_sizes']):.1f} bytes" if stats['packet_sizes'] else "N/A")
            ]
        
            stats_table.setRowCount(len(stats_data))
            for row, (metric, value) in enumerate(stats_data):
                stats_table.setItem(row, 0, QTableWidgetItem(metric))
                stats_table.setItem(row, 1, QTableWidgetItem(value))
            
                # Выделим важные метрики
                if metric in ["Total Packets", "Ports Scanned", "Most Active Port"]:
                    for col in range(2):
                        item = stats_table.item(row, col)
                        item.setBackground(QColor("#f0f9ff"))  # light blue
        
            # Настроим размеры таблицы
            stats_table.horizontalHeader().setSectionResizeMode(0, QHeaderView.Stretch)
            stats_table.horizontalHeader().setSectionResizeMode(1, QHeaderView.Stretch)
            stats_table.setMinimumHeight(300)  
        
            stats_table_layout.addWidget(stats_table)
            stats_group.setLayout(stats_table_layout)
            stats_layout.addWidget(stats_group)
        else:
            stats_layout.addWidget(QLabel("No traffic statistics available"))
    
        stats_tab.setLayout(stats_layout)
        tab_widget.addTab(stats_tab, "Traffic Stats")
    
        # Threat Analysis Tab
        threat_tab = QWidget()
        threat_layout = QVBoxLayout()
        threat_layout.setContentsMargins(10, 10, 10, 10)
        threat_layout.setSpacing(15)
    
        threat_info = QTextBrowser()
        threat_info.setOpenExternalLinks(True)
        threat_info.setStyleSheet("""
            QTextBrowser {
                border: 1px solid #d1d5db;
                border-radius: 6px;
                padding: 10px;
                background-color: white;
            }
        """)
    
        # Build threat report
        report = f"""
        <h2 style="margin-bottom: 15px;">Threat Analysis for {ip}</h2>
        <style>
            .threat-card {{ 
                border: 1px solid #ddd; 
                border-radius: 5px; 
                padding: 15px; 
                margin: 10px 0;
            }}
            .high {{ background-color: #fee2e2; border-left: 4px solid #ef4444; }}
            .medium {{ background-color: #fef3c7; border-left: 4px solid #f59e0b; }}
            .low {{ background-color: #ecfdf5; border-left: 4px solid #10b981; }}
            h3 {{ margin-top: 0; }}
            p {{ margin-bottom: 0; }}
        </style>
        """
    
        # Blacklist status
        if is_ip_blacklisted(ip):
            report += """
            <div class="threat-card high">
                <h3>BLACKLISTED</h3>
                <p>This IP has been manually added to your blacklist.</p>
            </div>
            """
        else:
            report += """
            <div class="threat-card low">
                <h3>CLEAN</h3>
                <p>This IP is not in your blacklist.</p>
            </div>
            """
    
        # Suspicious activity analysis
        if ip in self.protocol_stats:
            stats = self.protocol_stats[ip]
        
            # Port scanning detection
            if len(stats['ports']) > 10:
                report += f"""
                <div class="threat-card medium">
                    <h3>Possible Port Scanning</h3>
                    <p>This IP has scanned {len(stats['ports'])} different ports, which may indicate reconnaissance activity.</p>
                    <p>Most active port: {max(stats['ports'].items(), key=lambda x: x[1])[0]} ({max(stats['ports'].values())} packets)</p>
                </div>
                """
        
            # Protocol anomalies
            if 'ICMP' in stats['protocols'] and stats['protocols']['ICMP'] > 100:
                report += f"""
                <div class="threat-card medium">
                    <h3>ICMP Flood</h3>
                    <p>This IP has sent {stats['protocols']['ICMP']} ICMP packets, which may indicate ping flood attempts.</p>
                </div>
                """
    
        # External threat intelligence
        report += """
        <h3 style="margin-top: 20px;">External Threat Intelligence</h3>
        """

        try:
            abuseipdb_result = self.check_abuseipdb(ip)
            if abuseipdb_result:
                report += f"""
                <div class="threat-card {'high' if abuseipdb_result['isWhitelisted'] == False else 'low'}">
                    <h3>AbuseIPDB Reputation</h3>
                    <p>Score: {abuseipdb_result['abuseConfidenceScore']}/100</p>
                    <p>Reports: {abuseipdb_result['totalReports']}</p>
                    <p>Last reported: {abuseipdb_result['lastReportedAt']}</p>
                    <p>ISP: {abuseipdb_result['isp']}</p>
                    <p>Usage type: {abuseipdb_result['usageType']}</p>
                </div>
                """
    
            virustotal_result = self.check_virustotal(ip)
            if virustotal_result:
                report += f"""
                <div class="threat-card {'high' if virustotal_result['malicious'] > 0 else 'low'}">
                    <h3>VirusTotal Analysis</h3>
                    <p>Malicious: {virustotal_result['malicious']}</p>
                    <p>Suspicious: {virustotal_result['suspicious']}</p>
                    <p>Harmless: {virustotal_result['harmless']}</p>
                    <p>Last analysis: {virustotal_result['last_analysis_date']}</p>
                </div>
                """

        except Exception as e:
            report += f"""
            <div class="threat-card">
                <p><i>Error fetching threat intelligence: {str(e)}</i></p>
            </div>
            """

        threat_info.setHtml(report)
        threat_layout.addWidget(threat_info)
    
        # Action buttons
        btn_layout = QHBoxLayout()
        btn_layout.setSpacing(10)
    
        if not is_ip_blacklisted(ip):
            block_btn = QPushButton("Block IP")
            block_btn.setIcon(QIcon("icons/block.png"))
            block_btn.setStyleSheet("""
                QPushButton {
                    padding: 8px 15px;
                    background-color: #ef4444;
                    color: white;
                    border-radius: 4px;
                    min-width: 100px;
                }
                QPushButton:hover {
                    background-color: #dc2626;
                }
            """)
            block_btn.clicked.connect(lambda: self.block_ip(ip, dialog))
            btn_layout.addWidget(block_btn)
    
        whois_btn = QPushButton("WHOIS Lookup")
        whois_btn.setIcon(QIcon("icons/search.png"))
        whois_btn.setStyleSheet("""
            QPushButton {
                padding: 8px 15px;
                background-color: #3b82f6;
                color: white;
                border-radius: 4px;
                min-width: 100px;
            }
            QPushButton:hover {
                background-color: #2563eb;
            }
        """)
        whois_btn.clicked.connect(lambda: self.show_whois_info(ip))
        btn_layout.addWidget(whois_btn)
    
        btn_layout.addStretch()
        threat_layout.addLayout(btn_layout)
        threat_tab.setLayout(threat_layout)
        tab_widget.addTab(threat_tab, "Threat Analysis")
    
        # Packet Capture Tab
        if ip in self.protocol_stats and len(self.protocol_stats[ip]['timestamps']) > 0:
            packet_tab = QWidget()
            packet_layout = QVBoxLayout()
            packet_layout.setContentsMargins(10, 10, 10, 10)
            packet_layout.setSpacing(15)
        
            # Create timeline plot
            fig = Figure(figsize=(10, 4), dpi=100)
            canvas = FigureCanvas(fig)
            ax = fig.add_subplot(111)
        
            # Convert timestamps to relative seconds
            timestamps = self.protocol_stats[ip]['timestamps']
            first_ts = min(timestamps)
            rel_times = [(ts - first_ts).total_seconds() for ts in timestamps]
        
            ax.plot(rel_times, np.arange(len(rel_times)), 'b-')
            ax.set_title('Packet Timeline')
            ax.set_xlabel('Time (seconds)')
            ax.set_ylabel('Packet Count')
        
            packet_layout.addWidget(canvas)
        
            # Packet size stats in a group box
            stats_group = QGroupBox("Packet Size Statistics")
            size_layout = QVBoxLayout()
        
            size_stats = QLabel()
            if self.protocol_stats[ip]['packet_sizes']:
                sizes = self.protocol_stats[ip]['packet_sizes']
                size_stats.setText(
                    f"<b>Packet Size Stats:</b><br>"
                    f"Min: {min(sizes)} bytes<br>"
                    f"Max: {max(sizes)} bytes<br>"
                    f"Avg: {np.mean(sizes):.1f} bytes<br>"
                    f"Total: {sum(sizes)} bytes"
                )
            else:
                size_stats.setText("No packet size data available")
            
            size_stats.setStyleSheet("font-size: 14px; padding: 10px;")
            size_layout.addWidget(size_stats)
            stats_group.setLayout(size_layout)
            packet_layout.addWidget(stats_group)
        
            packet_tab.setLayout(packet_layout)
            tab_widget.addTab(packet_tab, "Packet Analysis")
    
        # Add tabs to dialog
        layout.addWidget(tab_widget)
    
        # Close button
        close_btn = QPushButton("Close")
        close_btn.setIcon(QIcon("icons/close.png"))
        close_btn.setStyleSheet("""
            QPushButton {
                padding: 10px 20px;
                background-color: #3b82f6;
                color: white;
                border-radius: 6px;
                min-width: 100px;
            }
            QPushButton:hover {
                background-color: #2563eb;
            }
            """)
        close_btn.clicked.connect(dialog.close)
        layout.addWidget(close_btn, 0, Qt.AlignCenter)
    
        dialog.setLayout(layout)
        dialog.exec_()
   
    def get_security_status(self, ip):
        """Create a security status widget"""
        status_widget = QWidget()
        layout = QHBoxLayout()
        
        # Determine threat level
        threat_level = 0
        if is_ip_blacklisted(ip):
            threat_level = 2
        elif ip in self.protocol_stats:
            stats = self.protocol_stats[ip]
            if len(stats['ports']) > 10 or stats['total_packets'] > 1000:
                threat_level = 1
        
        # Create icon and label
        icon = QLabel()
        label = QLabel()
        
        if threat_level == 2:
            icon.setPixmap(QIcon("icons/critical.png").pixmap(32, 32))
            label.setText("<font color='red'><b>High Threat</b></font>")
        elif threat_level == 1:
            icon.setPixmap(QIcon("icons/warning.png").pixmap(32, 32))
            label.setText("<font color='orange'><b>Suspicious</b></font>")
        else:
            icon.setPixmap(QIcon("icons/safe.png").pixmap(32, 32))
            label.setText("<font color='green'><b>Normal</b></font>")
        
        layout.addWidget(icon)
        layout.addWidget(label)
        layout.addStretch()
        status_widget.setLayout(layout)
        
        return status_widget

    def get_port_description(self, port):
        """Get description for well-known ports"""
        port_map = {
            80: "HTTP", 443: "HTTPS", 22: "SSH", 21: "FTP",
            25: "SMTP", 110: "POP3", 143: "IMAP", 53: "DNS",
            3389: "RDP", 3306: "MySQL", 5432: "PostgreSQL",
            27017: "MongoDB", 6379: "Redis", 11211: "Memcached"
        }
        return port_map.get(int(port), "Unknown")

    def block_ip(self, ip, dialog):
        """Block the IP address"""
        if add_to_blacklist(ip, "Manually blocked from interface"):
            self.refresh_blacklist()
            QMessageBox.information(dialog, "Success", f"IP {ip} has been blocked")
            dialog.close()
        else:
            QMessageBox.warning(dialog, "Error", f"Failed to block IP {ip}")

    def show_whois_info(self, ip):
        """Show WHOIS information using online API"""
        try:
            # Создаем диалоговое окно
            whois_dialog = QDialog(self)
            whois_dialog.setWindowTitle(f"WHOIS Info - {ip}")
            whois_dialog.setMinimumSize(700, 500)
        
            layout = QVBoxLayout()
        
            # Добавляем текстовый браузер
            text_browser = QTextBrowser()
            text_browser.setPlainText("Fetching WHOIS data...")
            text_browser.setStyleSheet("""
                QTextBrowser {
                    font-family: Consolas, monospace;
                    font-size: 12px;
                }
            """)
        
            # Кнопка закрытия
            close_btn = QPushButton("Close")
            close_btn.setIcon(QIcon("icons/close.png"))
            close_btn.setStyleSheet("""
                QPushButton {
                    padding: 8px 15px;
                    background-color: #3b82f6;
                    color: white;
                    border-radius: 4px;
                    min-width: 100px;
                }
                QPushButton:hover {
                    background-color: #2563eb;
                }
            """)
            close_btn.clicked.connect(whois_dialog.close)
        
            layout.addWidget(text_browser)
            layout.addWidget(close_btn, 0, Qt.AlignCenter)
            whois_dialog.setLayout(layout)
        
            # Показываем окно сразу
            whois_dialog.show()
        
            # Делаем API-запрос в отдельном потоке
            def fetch_whois():
                try:
                    # Используем бесплатный API
                    api_url = f"https://api.whois.vu/?q={ip}"
                    response = requests.get(api_url, timeout=10)
                
                    if response.status_code == 200:
                        data = response.json()
                        formatted_data = ""
                    
                        if 'available' in data:
                            formatted_data += f"Domain Available: {data['available']}\n\n"
                    
                        for key, value in data.items():
                            if key != 'available':
                                formatted_data += f"{key.upper()}: {value}\n"
                    
                        # Обновляем GUI из главного потока
                        QTimer.singleShot(0, lambda: text_browser.setPlainText(formatted_data))
                    else:
                        error_msg = f"API Error: {response.status_code}\nResponse: {response.text[:500]}..."
                        QTimer.singleShot(0, lambda: text_browser.setPlainText(error_msg))
            
                except Exception as e:
                    error_msg = f"Error fetching WHOIS data:\n{str(e)}"
                    QTimer.singleShot(0, lambda: text_browser.setPlainText(error_msg))
        
            # Запускаем запрос в отдельном потоке
            import threading
            threading.Thread(target=fetch_whois, daemon=True).start()
        
            whois_dialog.exec_()
        
        except Exception as e:
            QMessageBox.warning(
                self,
                "Error",
                f"Failed to initialize WHOIS dialog: {str(e)}"
            )

    def update_ip_table(self, ip, protocol, port, country, provider):
        """Update the IP table with new data and collect statistics"""
        # Update stats first
        stats = self.protocol_stats[ip]
        stats['protocols'][protocol] += 1
        if port > 0:
            stats['ports'][port] += 1
        stats['total_packets'] += 1
        stats['last_seen'] = datetime.now()
        
        # Then update the table as before
        row = self.ip_table.rowCount()
        self.ip_table.insertRow(row)
        
        self.ip_table.setItem(row, 0, QTableWidgetItem(ip))
        self.ip_table.setItem(row, 1, QTableWidgetItem(protocol))
        self.ip_table.setItem(row, 2, QTableWidgetItem(str(port)))
        self.ip_table.setItem(row, 3, QTableWidgetItem(country))
        self.ip_table.setItem(row, 4, QTableWidgetItem(provider))
        
        status = "Blacklisted" if is_ip_blacklisted(ip) else "Normal"
        status_item = QTableWidgetItem(status)
        status_item.setForeground(QColor("#ef4444") if status == "Blacklisted" else QColor("#10b981"))
        
        font = QFont()
        font.setBold(True)
        status_item.setFont(font)
        
        self.ip_table.setItem(row, 5, status_item)

if __name__ == "__main__":
    app = QApplication(sys.argv)
    app.setStyle("Fusion")
    
    window = MainWindow()
    window.show()
    sys.exit(app.exec_())