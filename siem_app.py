import sys
import ctypes
import os
import time
import threading
import logging
import configparser
import smtplib
import ssl
from email.message import EmailMessage
from datetime import datetime, timedelta
from collections import defaultdict, Counter
import numpy as np
import pandas as pd

# PyQt6 for GUI
from PyQt6 import QtWidgets, QtCore, QtGui
from PyQt6.QtWidgets import (
    QApplication, QMainWindow, QLabel, QPushButton, QCheckBox,
    QTableWidget, QTableWidgetItem, QVBoxLayout, QWidget,
    QMessageBox, QFileDialog, QHeaderView, QLineEdit, QComboBox,
    QFormLayout, QSplitter, QHBoxLayout, QSystemTrayIcon, QTabWidget
)
from PyQt6.QtCore import Qt, pyqtSignal, pyqtSlot
from PyQt6.QtGui import QIcon

# SQLAlchemy for database management
from sqlalchemy import create_engine, Column, Integer, String, Text, DateTime, Float
from sqlalchemy.orm import sessionmaker, declarative_base

# Advanced machine learning with TensorFlow
import tensorflow as tf
from tensorflow.keras.models import Sequential
from tensorflow.keras.layers import Dense, LSTM

# Scapy for network monitoring
from scapy.all import AsyncSniffer, IP, TCP, UDP

# Pywin32 modules for Windows Event Log access
import win32evtlog  # For accessing Windows Event Logs
import win32evtlogutil

# Matplotlib for plotting in PyQt6
from matplotlib.backends.backend_qt5agg import FigureCanvasQTAgg as FigureCanvas
from matplotlib.figure import Figure

# Additional Libraries for Enhancements
from sklearn.ensemble import IsolationForest  # For advanced anomaly detection
from loguru import logger  # Enhanced logging
import psutil  # For additional system vitals

# Suppress TensorFlow oneDNN warnings
os.environ['TF_ENABLE_ONEDNN_OPTS'] = '0'

# Function to check if the script is run with admin privileges
def is_admin():
    try:
        return ctypes.windll.shell32.IsUserAnAdmin()
    except:
        return False

# SQLAlchemy setup
Base = declarative_base()

class LogEntry(Base):
    __tablename__ = 'logs'
    id = Column(Integer, primary_key=True)
    timestamp = Column(DateTime)
    event_id = Column(Integer)
    event_type = Column(Integer)
    event_level = Column(String)
    source = Column(String)
    message = Column(Text)

class AnomalyEntry(Base):
    __tablename__ = 'anomalies'
    id = Column(Integer, primary_key=True)
    timestamp = Column(DateTime)
    event_id = Column(Integer)
    event_type = Column(Integer)
    event_level = Column(String)
    source = Column(String)
    message = Column(Text)
    anomaly_type = Column(String)

class SIEMApp(QMainWindow):
    """
    SIEM Application with Extensive Features, GPU Acceleration, and Enhanced GUI.
    """
    # Define signals
    log_entry_signal = pyqtSignal(LogEntry)
    alert_entry_signal = pyqtSignal(AnomalyEntry)
    performance_update_signal = pyqtSignal(dict)
    packet_signal = pyqtSignal(dict)
    alert_signal = pyqtSignal(str, str)

    def __init__(self):
        super().__init__()
        self.setWindowTitle("SIEM Application with Advanced Features")
        self.setGeometry(100, 100, 1800, 1000)

        # Initialize logging with RotatingFileHandler and loguru
        self.setup_logging()

        # Load configuration
        self.load_configuration()

        # Initialize variables
        self.is_monitoring = False
        self.is_network_monitoring = False
        self.ips_enabled = False

        # Data structures for plotting
        self.event_counts_per_minute = defaultdict(int)
        self.anomaly_counts_per_hour = defaultdict(int)
        self.anomaly_details = []

        # Set up database and model
        self.setup_database()
        self.model = self.load_or_train_model()

        # Initialize figures and canvases for charts
        self.figure_anomaly = None
        self.canvas_anomaly = None
        self.figure_pie_event_levels = None
        self.canvas_pie_event_levels = None
        self.figure_pie_event_sources = None
        self.canvas_pie_event_sources = None
        self.figure_pie_event_ids = None
        self.canvas_pie_event_ids = None
        self.figure_pie_anomaly_types = None
        self.canvas_pie_anomaly_types = None
        self.figure_pie_protocols = None
        self.canvas_pie_protocols = None

        # Additional System Vitals Charts
        self.figure_memory = None
        self.canvas_memory = None
        self.figure_disk = None
        self.canvas_disk = None
        self.figure_network = None
        self.canvas_network = None

        # GPU Monitoring Initialization
        self.gpu_available = False
        self.initialize_gpu_monitoring()  # Initialize GPU monitoring

        # Create UI components
        self.create_widgets()

        # Initialize system tray
        self.initialize_system_tray()

        # Connect signals to slots
        self.log_entry_signal.connect(self.update_log_table_slot)
        self.alert_entry_signal.connect(self.update_alerts_table_slot)
        self.performance_update_signal.connect(self.update_performance_charts_slot)
        self.packet_signal.connect(self.update_network_table_slot)
        self.alert_signal.connect(self.display_alert_slot)

        # Start real-time data reception
        threading.Thread(target=self.start_event_log_monitoring, daemon=True).start()

        # Start updating data and UI
        self.start_update_loop()

    def setup_logging(self):
        """
        Sets up logging with RotatingFileHandler and loguru.
        """
        try:
            from logging.handlers import RotatingFileHandler
            handler = RotatingFileHandler('siem_app.log', maxBytes=50*1024*1024, backupCount=5)
            logging.basicConfig(level=logging.INFO,
                                format='%(asctime)s %(levelname)s:%(message)s',
                                handlers=[handler])
            # Configure loguru to also log to the same file
            logger.add("siem_app.log", rotation="50 MB", enqueue=True, backtrace=True, diagnose=True)
        except Exception as e:
            print(f"Error setting up logging: {e}")

    def load_configuration(self):
        """
        Loads settings from config.ini or creates default settings.
        """
        try:
            self.config = configparser.ConfigParser()
            config_file = 'config.ini'
            if os.path.exists(config_file):
                self.config.read(config_file)
            else:
                self.config['DEFAULT'] = {
                    'UpdateInterval': '5000',
                    'AnomalyThreshold': '0.1',
                    'MonitoredLogs': 'System,Application,Security',
                    'LogLevels': 'Error,Warning,Information',
                    'ModelFile': 'lstm_model.h5',
                    'EmailAlerts': 'False',
                    'EventIDWhitelist': '',
                    'NetworkMonitoring': 'False',
                    'IPSEnabled': 'False',
                    'Theme': 'light',
                    'DatabaseURL': 'sqlite:///siem_logs.db'
                }
                self.config['EMAIL'] = {
                    'Provider': 'Gmail',
                    'SMTPServer': 'smtp.gmail.com',
                    'SMTPPort': '465',
                    'SenderEmail': '',
                    'ReceiverEmail': '',
                    'Password': ''
                }
                with open(config_file, 'w') as f:
                    self.config.write(f)
        except Exception as e:
            logging.error(f"Error loading configuration: {e}")
            QMessageBox.critical(self, "Configuration Error", f"Failed to load configuration: {e}")
            sys.exit(1)

    def setup_database(self):
        """
        Sets up the database for storing log events and anomalies.
        """
        try:
            logging.info("Setting up database...")
            self.engine = create_engine(self.config['DEFAULT']['DatabaseURL'], echo=False)
            Base.metadata.create_all(self.engine)
            Session = sessionmaker(bind=self.engine)
            self.session = Session()
        except Exception as e:
            logging.error(f"Database error: {e}")
            QMessageBox.critical(self, "Database Error", f"Failed to set up database: {e}")
            sys.exit(1)

    def load_or_train_model(self):
        """
        Loads an existing LSTM model or trains a new one.
        """
        try:
            logging.info("Loading or training model...")
            model_file = self.config['DEFAULT']['ModelFile']
            if os.path.exists(model_file):
                model = tf.keras.models.load_model(model_file)
                logging.info("Model loaded successfully.")
            else:
                model = self.train_new_model()
            return model
        except Exception as e:
            logging.error(f"Model error: {e}")
            QMessageBox.critical(self, "Model Error", f"Failed to load or train model: {e}")
            sys.exit(1)

    def train_new_model(self):
        """
        Trains a new LSTM model with GPU acceleration if available.
        """
        logging.info("Training new model...")
        # Simulate some training data
        data = np.random.rand(10000, 4)
        targets = np.random.randint(0, 2, 10000)
        data = data.reshape((10000, 1, 4))

        # Check for GPU availability
        if tf.config.list_physical_devices('GPU'):
            try:
                with tf.device('/GPU:0'):
                    model = Sequential()
                    model.add(LSTM(128, input_shape=(1, 4)))
                    model.add(Dense(1, activation='sigmoid'))
                    model.compile(loss='binary_crossentropy', optimizer='adam', metrics=['accuracy'])
                    model.fit(data, targets, epochs=10, batch_size=64)
            except Exception as e:
                logging.error(f"Error training model on GPU: {e}")
                QMessageBox.critical(self, "Model Training Error", f"Failed to train model on GPU: {e}")
                sys.exit(1)
        else:
            try:
                model = Sequential()
                model.add(LSTM(128, input_shape=(1, 4)))
                model.add(Dense(1, activation='sigmoid'))
                model.compile(loss='binary_crossentropy', optimizer='adam', metrics=['accuracy'])
                model.fit(data, targets, epochs=10, batch_size=64)
            except Exception as e:
                logging.error(f"Error training model on CPU: {e}")
                QMessageBox.critical(self, "Model Training Error", f"Failed to train model on CPU: {e}")
                sys.exit(1)

        model.save(self.config['DEFAULT']['ModelFile'])
        logging.info("New model trained and saved.")
        return model

    def initialize_gpu_monitoring(self):
        """
        Initializes GPU monitoring.
        """
        try:
            # Example using WMI for GPU monitoring (Windows)
            import wmi
            self.w = wmi.WMI(namespace="root\\OpenHardwareMonitor")
            gpu_query = self.w.Sensor(Name="GPU Core", SensorType="Temperature")
            if gpu_query:
                self.gpu_available = True
                logging.info("GPU detected and monitoring initialized.")
            else:
                self.gpu_available = False
                logging.warning("No GPU detected or OpenHardwareMonitor not running.")
        except Exception as e:
            logging.error(f"Error initializing GPU monitoring: {e}")
            self.gpu_available = False

    def get_gpu_usage(self):
        """
        Retrieves GPU usage using WMI.
        """
        if self.gpu_available:
            try:
                sensors = self.w.Sensor(Name="GPU Core", SensorType="Load")
                if sensors:
                    gpu_usage = sensors[0].Value
                    return gpu_usage
                else:
                    return 0
            except Exception as e:
                logging.error(f"Error retrieving GPU usage: {e}")
                return 0
        return 0

    def create_widgets(self):
        """
        Creates the main widgets for the GUI.
        """
        try:
            self.apply_theme()
            self.tabs = QTabWidget()
            self.setCentralWidget(self.tabs)

            # Create tabs
            self.dashboard_tab = QWidget()
            self.network_tab = QWidget()
            self.logs_tab = QWidget()
            self.alerts_tab = QWidget()
            self.settings_tab = QWidget()
            self.performance_tab = QWidget()
            self.quantified_data_tab = QWidget()  # New tab for quantified data

            self.tabs.addTab(self.dashboard_tab, 'Dashboard')
            self.tabs.addTab(self.network_tab, 'Network Monitoring')
            self.tabs.addTab(self.logs_tab, 'Logs')
            self.tabs.addTab(self.alerts_tab, 'Alerts')
            self.tabs.addTab(self.performance_tab, 'Performance')
            self.tabs.addTab(self.quantified_data_tab, 'Quantified Data')  # Add the new tab
            self.tabs.addTab(self.settings_tab, 'Settings')

            self.create_dashboard(self.dashboard_tab)
            self.create_network_tab(self.network_tab)
            self.create_logs_tab(self.logs_tab)
            self.create_alerts_tab(self.alerts_tab)
            self.create_performance_tab(self.performance_tab)
            self.create_quantified_data_tab(self.quantified_data_tab)
            self.create_settings(self.settings_tab)

            # Status bar
            self.statusBar().showMessage("Status: Monitoring Active")
        except Exception as e:
            logging.error(f"Error creating widgets: {e}")
            QMessageBox.critical(self, "UI Error", f"Failed to create UI components: {e}")
            sys.exit(1)

    def apply_theme(self):
        """
        Applies the selected theme to the application.
        """
        try:
            theme = self.config['DEFAULT'].get('Theme', 'light')
            if theme == 'dark':
                self.setStyleSheet("""
                    QWidget { background-color: #2E2E2E; color: white; }
                    QTableWidget { background-color: #2E2E2E; color: white; gridline-color: #444444; }
                    QHeaderView::section { background-color: #444444; color: white; }
                    QScrollBar { background-color: #444444; }
                    QPushButton { background-color: #444444; color: white; }
                    QLineEdit { background-color: #444444; color: white; }
                    QTextEdit { background-color: #444444; color: white; }
                """)
            else:
                self.setStyleSheet("")
        except Exception as e:
            logging.error(f"Error applying theme: {e}")

    def create_dashboard(self, parent):
        """
        Creates the dashboard tab with multiple charts and control panel.
        """
        try:
            layout = QVBoxLayout()
            parent.setLayout(layout)

            # Grid layout for charts
            chart_layout = QtWidgets.QGridLayout()

            # Anomaly Chart
            self.create_anomaly_chart()
            chart_layout.addWidget(self.canvas_anomaly, 0, 0)

            # Event Level Pie Chart
            self.create_event_level_pie_chart()
            chart_layout.addWidget(self.canvas_pie_event_levels, 0, 1)

            # Event Sources Pie Chart
            self.create_event_sources_pie_chart()
            chart_layout.addWidget(self.canvas_pie_event_sources, 1, 0)

            # Event IDs Pie Chart
            self.create_event_ids_pie_chart()
            chart_layout.addWidget(self.canvas_pie_event_ids, 1, 1)

            # Anomaly Types Pie Chart
            self.create_anomaly_types_pie_chart()
            chart_layout.addWidget(self.canvas_pie_anomaly_types, 2, 0)

            # Protocols Pie Chart
            self.create_protocols_pie_chart()
            chart_layout.addWidget(self.canvas_pie_protocols, 2, 1)

            layout.addLayout(chart_layout)

            # Control Panel
            self.create_control_panel(layout)

        except Exception as e:
            logging.error(f"Error creating dashboard: {e}")
            QMessageBox.critical(self, "Dashboard Error", f"Failed to create dashboard: {e}")

    def create_network_tab(self, parent):
        """
        Creates the network monitoring tab.
        """
        try:
            layout = QVBoxLayout()
            parent.setLayout(layout)

            # Network Monitoring Controls
            control_layout = QtWidgets.QHBoxLayout()
            self.network_monitor_var = QCheckBox("Enable Network Monitoring")
            self.network_monitor_var.setChecked(self.config['DEFAULT'].getboolean('NetworkMonitoring'))
            self.network_monitor_var.stateChanged.connect(self.toggle_network_monitoring)
            control_layout.addWidget(self.network_monitor_var)

            self.ips_var = QCheckBox("Enable Intrusion Prevention System")
            self.ips_var.setChecked(self.config['DEFAULT'].getboolean('IPSEnabled'))
            self.ips_var.stateChanged.connect(self.toggle_ips)
            control_layout.addWidget(self.ips_var)

            layout.addLayout(control_layout)

            # Network Events Table
            self.create_network_table(layout)
        except Exception as e:
            logging.error(f"Error creating network tab: {e}")
            QMessageBox.critical(self, "Network Tab Error", f"Failed to create network tab: {e}")

    def create_logs_tab(self, parent):
        """
        Creates the logs tab with log and anomaly tables.
        """
        try:
            layout = QVBoxLayout()
            parent.setLayout(layout)

            # Log Events Table
            self.create_log_table(layout)
        except Exception as e:
            logging.error(f"Error creating logs tab: {e}")
            QMessageBox.critical(self, "Logs Tab Error", f"Failed to create logs tab: {e}")

    def create_alerts_tab(self, parent):
        """
        Creates the alerts tab to display all alerts.
        """
        try:
            layout = QVBoxLayout()
            parent.setLayout(layout)

            # Alerts Table
            self.create_alerts_table(layout)
        except Exception as e:
            logging.error(f"Error creating alerts tab: {e}")
            QMessageBox.critical(self, "Alerts Tab Error", f"Failed to create alerts tab: {e}")

    def create_performance_tab(self, parent):
        """
        Creates the performance monitoring tab.
        """
        try:
            layout = QVBoxLayout()
            parent.setLayout(layout)

            # CPU, GPU, Memory, Disk, and Network Usage Charts
            self.create_performance_charts(layout)
        except Exception as e:
            logging.error(f"Error creating performance tab: {e}")
            QMessageBox.critical(self, "Performance Tab Error", f"Failed to create performance tab: {e}")

    def create_quantified_data_tab(self, parent):
        """
        Creates the quantified data tab with collected data charts.
        """
        try:
            layout = QVBoxLayout()
            parent.setLayout(layout)

            # Example Chart: Collected Data Over Time
            self.figure_quantified = Figure()
            self.canvas_quantified = FigureCanvas(self.figure_quantified)
            layout.addWidget(self.canvas_quantified)

            # Start data collection thread
            threading.Thread(target=self.update_quantified_data_chart_thread, daemon=True).start()
        except Exception as e:
            logging.error(f"Error creating quantified data tab: {e}")
            QMessageBox.critical(self, "Quantified Data Tab Error", f"Failed to create quantified data tab: {e}")

    def create_log_table(self, layout):
        """
        Creates the log events table.
        """
        try:
            self.log_table = QTableWidget()
            self.log_table.setColumnCount(5)
            self.log_table.setHorizontalHeaderLabels(['Timestamp', 'Event ID', 'Level', 'Source', 'Message'])
            self.log_table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
            layout.addWidget(self.log_table)
        except Exception as e:
            logging.error(f"Error creating log table: {e}")
            QMessageBox.critical(self, "UI Error", f"Failed to create log table: {e}")

    def create_alerts_table(self, layout):
        """
        Creates the alerts table.
        """
        try:
            self.alerts_table = QTableWidget()
            self.alerts_table.setColumnCount(3)
            self.alerts_table.setHorizontalHeaderLabels(['Timestamp', 'Alert Level', 'Message'])
            self.alerts_table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
            layout.addWidget(self.alerts_table)
        except Exception as e:
            logging.error(f"Error creating alerts table: {e}")
            QMessageBox.critical(self, "UI Error", f"Failed to create alerts table: {e}")

    def create_network_table(self, layout):
        """
        Creates the network events table.
        """
        try:
            self.network_table = QTableWidget()
            self.network_table.setColumnCount(6)
            self.network_table.setHorizontalHeaderLabels(['Timestamp', 'Source IP', 'Dest IP', 'Protocol', 'Length', 'Info'])
            self.network_table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
            layout.addWidget(self.network_table)
        except Exception as e:
            logging.error(f"Error creating network table: {e}")
            QMessageBox.critical(self, "UI Error", f"Failed to create network table: {e}")

    def create_anomaly_chart(self):
        """
        Creates the anomaly chart with drill-down capabilities.
        """
        try:
            self.figure_anomaly = Figure()
            self.canvas_anomaly = FigureCanvas(self.figure_anomaly)
        except Exception as e:
            logging.error(f"Error creating anomaly chart: {e}")
            QMessageBox.critical(self, "UI Error", f"Failed to create anomaly chart: {e}")

    def create_event_level_pie_chart(self):
        """
        Creates a pie chart of event levels.
        """
        try:
            self.figure_pie_event_levels = Figure()
            self.canvas_pie_event_levels = FigureCanvas(self.figure_pie_event_levels)
        except Exception as e:
            logging.error(f"Error creating event level pie chart: {e}")
            QMessageBox.critical(self, "UI Error", f"Failed to create event level pie chart: {e}")

    def create_event_sources_pie_chart(self):
        """
        Creates a pie chart of event sources.
        """
        try:
            self.figure_pie_event_sources = Figure()
            self.canvas_pie_event_sources = FigureCanvas(self.figure_pie_event_sources)
        except Exception as e:
            logging.error(f"Error creating event sources pie chart: {e}")
            QMessageBox.critical(self, "UI Error", f"Failed to create event sources pie chart: {e}")

    def create_event_ids_pie_chart(self):
        """
        Creates a pie chart of event IDs.
        """
        try:
            self.figure_pie_event_ids = Figure()
            self.canvas_pie_event_ids = FigureCanvas(self.figure_pie_event_ids)
        except Exception as e:
            logging.error(f"Error creating event IDs pie chart: {e}")
            QMessageBox.critical(self, "UI Error", f"Failed to create event IDs pie chart: {e}")

    def create_anomaly_types_pie_chart(self):
        """
        Creates a pie chart of anomaly types.
        """
        try:
            self.figure_pie_anomaly_types = Figure()
            self.canvas_pie_anomaly_types = FigureCanvas(self.figure_pie_anomaly_types)
        except Exception as e:
            logging.error(f"Error creating anomaly types pie chart: {e}")
            QMessageBox.critical(self, "UI Error", f"Failed to create anomaly types pie chart: {e}")

    def create_protocols_pie_chart(self):
        """
        Creates a pie chart of network protocols.
        """
        try:
            self.figure_pie_protocols = Figure()
            self.canvas_pie_protocols = FigureCanvas(self.figure_pie_protocols)
        except Exception as e:
            logging.error(f"Error creating protocols pie chart: {e}")
            QMessageBox.critical(self, "UI Error", f"Failed to create protocols pie chart: {e}")

    def create_performance_charts(self, layout):
        """
        Creates charts to monitor CPU, GPU, Memory, Disk, and Network usage.
        """
        try:
            splitter = QSplitter(Qt.Orientation.Horizontal)

            # CPU Usage Chart
            self.figure_cpu = Figure()
            self.canvas_cpu = FigureCanvas(self.figure_cpu)
            splitter.addWidget(self.canvas_cpu)

            # GPU Usage Chart
            self.figure_gpu = Figure()
            self.canvas_gpu = FigureCanvas(self.figure_gpu)
            splitter.addWidget(self.canvas_gpu)

            # Memory Usage Chart
            self.figure_memory = Figure()
            self.canvas_memory = FigureCanvas(self.figure_memory)
            splitter.addWidget(self.canvas_memory)

            # Disk Usage Chart
            self.figure_disk = Figure()
            self.canvas_disk = FigureCanvas(self.figure_disk)
            splitter.addWidget(self.canvas_disk)

            # Network Usage Chart
            self.figure_network = Figure()
            self.canvas_network = FigureCanvas(self.figure_network)
            splitter.addWidget(self.canvas_network)

            layout.addWidget(splitter)

            # Start performance monitoring in a separate thread
            threading.Thread(target=self.update_performance_charts_thread, daemon=True).start()
        except Exception as e:
            logging.error(f"Error creating performance charts: {e}")
            QMessageBox.critical(self, "UI Error", f"Failed to create performance charts: {e}")

    def create_control_panel(self, layout):
        """
        Creates the control panel with various action buttons.
        """
        try:
            control_layout = QHBoxLayout()

            retrain_button = QPushButton("Retrain Model")
            retrain_button.clicked.connect(self.retrain_model)
            control_layout.addWidget(retrain_button)

            clear_alerts_button = QPushButton("Clear Alerts")
            clear_alerts_button.clicked.connect(self.clear_alerts)
            control_layout.addWidget(clear_alerts_button)

            export_logs_button = QPushButton("Export Logs")
            export_logs_button.clicked.connect(self.export_logs)
            control_layout.addWidget(export_logs_button)

            clear_logs_button = QPushButton("Clear Logs")
            clear_logs_button.clicked.connect(self.clear_logs)
            control_layout.addWidget(clear_logs_button)

            exit_button = QPushButton("Exit")
            exit_button.clicked.connect(self.on_exit)
            control_layout.addWidget(exit_button)

            layout.addLayout(control_layout)
        except Exception as e:
            logging.error(f"Error creating control panel: {e}")
            QMessageBox.critical(self, "UI Error", f"Failed to create control panel: {e}")

    def create_settings(self, parent):
        """
        Creates the settings tab for configuration.
        """
        try:
            layout = QVBoxLayout()
            parent.setLayout(layout)

            settings_layout = QFormLayout()

            # Update Interval
            self.update_interval_input = QLineEdit(self.config['DEFAULT'].get('UpdateInterval', '5000'))
            settings_layout.addRow('Update Interval (ms):', self.update_interval_input)

            # Anomaly Threshold
            self.anomaly_threshold_input = QLineEdit(self.config['DEFAULT'].get('AnomalyThreshold', '0.1'))
            settings_layout.addRow('Anomaly Threshold:', self.anomaly_threshold_input)

            # Monitored Logs
            self.monitored_logs_input = QLineEdit(self.config['DEFAULT'].get('MonitoredLogs', 'System,Application,Security'))
            settings_layout.addRow('Monitored Logs (comma-separated):', self.monitored_logs_input)

            # Log Levels
            self.log_levels_input = QLineEdit(self.config['DEFAULT'].get('LogLevels', 'Error,Warning,Information'))
            settings_layout.addRow('Log Levels (comma-separated):', self.log_levels_input)

            # Event ID Whitelist (Optional: Consider removing to capture all logs)
            self.event_id_whitelist_input = QLineEdit(self.config['DEFAULT'].get('EventIDWhitelist', ''))
            settings_layout.addRow('Event ID Whitelist (comma-separated):', self.event_id_whitelist_input)

            # Email Alerts
            self.email_alerts_checkbox = QCheckBox()
            self.email_alerts_checkbox.setChecked(self.config['DEFAULT'].getboolean('EmailAlerts', False))
            settings_layout.addRow('Email Alerts:', self.email_alerts_checkbox)

            # Email Settings
            self.email_provider_input = QLineEdit(self.config['EMAIL'].get('Provider', 'Gmail'))
            settings_layout.addRow('Email Provider:', self.email_provider_input)

            self.smtp_server_input = QLineEdit(self.config['EMAIL'].get('SMTPServer', 'smtp.gmail.com'))
            settings_layout.addRow('SMTP Server:', self.smtp_server_input)

            self.smtp_port_input = QLineEdit(self.config['EMAIL'].get('SMTPPort', '465'))
            settings_layout.addRow('SMTP Port:', self.smtp_port_input)

            self.sender_email_input = QLineEdit(self.config['EMAIL'].get('SenderEmail', ''))
            settings_layout.addRow('Sender Email:', self.sender_email_input)

            self.receiver_email_input = QLineEdit(self.config['EMAIL'].get('ReceiverEmail', ''))
            settings_layout.addRow('Receiver Email:', self.receiver_email_input)

            self.email_password_input = QLineEdit(self.config['EMAIL'].get('Password', ''))
            self.email_password_input.setEchoMode(QLineEdit.EchoMode.Password)
            settings_layout.addRow('Email Password:', self.email_password_input)

            # Theme
            self.theme_input = QComboBox()
            self.theme_input.addItems(['light', 'dark'])
            self.theme_input.setCurrentText(self.config['DEFAULT'].get('Theme', 'light'))
            settings_layout.addRow('Theme:', self.theme_input)

            layout.addLayout(settings_layout)

            # Save Settings Button
            save_button = QPushButton("Save Settings")
            save_button.clicked.connect(self.save_settings)
            layout.addWidget(save_button)

        except Exception as e:
            logging.error(f"Error creating settings tab: {e}")
            QMessageBox.critical(self, "Settings Error", f"Failed to create settings tab: {e}")

    def save_settings(self):
        """
        Saves the settings from the settings tab.
        """
        try:
            self.config['DEFAULT']['UpdateInterval'] = self.update_interval_input.text()
            self.config['DEFAULT']['AnomalyThreshold'] = self.anomaly_threshold_input.text()
            self.config['DEFAULT']['MonitoredLogs'] = self.monitored_logs_input.text()
            self.config['DEFAULT']['LogLevels'] = self.log_levels_input.text()
            self.config['DEFAULT']['EventIDWhitelist'] = self.event_id_whitelist_input.text()
            self.config['DEFAULT']['EmailAlerts'] = str(self.email_alerts_checkbox.isChecked())
            self.config['DEFAULT']['Theme'] = self.theme_input.currentText()

            self.config['EMAIL']['Provider'] = self.email_provider_input.text()
            self.config['EMAIL']['SMTPServer'] = self.smtp_server_input.text()
            self.config['EMAIL']['SMTPPort'] = self.smtp_port_input.text()
            self.config['EMAIL']['SenderEmail'] = self.sender_email_input.text()
            self.config['EMAIL']['ReceiverEmail'] = self.receiver_email_input.text()
            self.config['EMAIL']['Password'] = self.email_password_input.text()

            with open('config.ini', 'w') as f:
                self.config.write(f)

            QMessageBox.information(self, "Settings Saved", "Configuration settings have been updated.")
            logger.info("Configuration settings updated.")

            # Apply new settings
            self.apply_theme()
            self.retrain_model()
        except Exception as e:
            logging.error(f"Error saving settings: {e}")
            QMessageBox.critical(self, "Settings Error", f"Failed to save settings: {e}")

    def start_update_loop(self):
        """
        Starts the loop to update data and UI at regular intervals.
        """
        try:
            self.update_tables()
            interval = int(self.config['DEFAULT']['UpdateInterval'])
            QtCore.QTimer.singleShot(interval, self.start_update_loop)
        except Exception as e:
            logging.error(f"Error in update loop: {e}")

    def update_tables(self):
        """
        Updates the log table, anomaly table, and all charts.
        """
        try:
            # Update the anomaly chart
            self.update_anomaly_chart()

            # Update the event level pie chart
            self.update_event_level_pie_chart()

            # Update additional pie charts
            self.update_event_sources_pie_chart()
            self.update_event_ids_pie_chart()
            self.update_anomaly_types_pie_chart()
            self.update_protocols_pie_chart()

            # Update quantified data chart
            self.update_quantified_data_chart()

        except Exception as e:
            logging.error(f"Error updating tables: {e}")

    @pyqtSlot(LogEntry)
    def update_log_table_slot(self, log_entry):
        """
        Slot to update the log table when a new log entry is added.
        """
        try:
            row = self.log_table.rowCount()
            self.log_table.insertRow(row)
            self.log_table.setItem(row, 0, QTableWidgetItem(log_entry.timestamp.strftime('%Y-%m-%d %H:%M:%S')))
            self.log_table.setItem(row, 1, QTableWidgetItem(str(log_entry.event_id)))
            self.log_table.setItem(row, 2, QTableWidgetItem(log_entry.event_level))
            self.log_table.setItem(row, 3, QTableWidgetItem(log_entry.source))
            self.log_table.setItem(row, 4, QTableWidgetItem(log_entry.message))
        except Exception as e:
            logging.error(f"Error updating log table in slot: {e}")

    @pyqtSlot(AnomalyEntry)
    def update_alerts_table_slot(self, anomaly_entry):
        """
        Slot to update the alerts table when a new anomaly is detected.
        """
        try:
            row = self.alerts_table.rowCount()
            self.alerts_table.insertRow(row)
            self.alerts_table.setItem(row, 0, QTableWidgetItem(anomaly_entry.timestamp.strftime('%Y-%m-%d %H:%M:%S')))
            self.alerts_table.setItem(row, 1, QTableWidgetItem(anomaly_entry.event_level))
            self.alerts_table.setItem(row, 2, QTableWidgetItem(anomaly_entry.message))
        except Exception as e:
            logging.error(f"Error updating alerts table in slot: {e}")

    @pyqtSlot(dict)
    def update_network_table_slot(self, packet_data):
        """
        Slot to update the network table when a new packet is processed.
        """
        try:
            row_position = self.network_table.rowCount()
            self.network_table.insertRow(row_position)
            self.network_table.setItem(row_position, 0, QTableWidgetItem(packet_data['timestamp']))
            self.network_table.setItem(row_position, 1, QTableWidgetItem(packet_data['src_ip']))
            self.network_table.setItem(row_position, 2, QTableWidgetItem(packet_data['dst_ip']))
            self.network_table.setItem(row_position, 3, QTableWidgetItem(packet_data['protocol']))
            self.network_table.setItem(row_position, 4, QTableWidgetItem(str(packet_data['length'])))
            self.network_table.setItem(row_position, 5, QTableWidgetItem(packet_data['info']))
        except Exception as e:
            logging.error(f"Error updating network table in slot: {e}")

    @pyqtSlot(str, str)
    def display_alert_slot(self, alert_message, alert_level='Info'):
        """
        Slot to display alerts using system tray notifications.
        """
        try:
            # Update the status bar
            self.statusBar().showMessage(f"Alert: {alert_message}")

            # Determine the notification type based on alert level
            if alert_level.lower() in ['error', 'critical']:
                icon = QSystemTrayIcon.MessageIcon.Critical
                title = "Critical Alert"
                # Log as critical
                logger.critical(alert_message)
            elif alert_level.lower() == 'warning':
                icon = QSystemTrayIcon.MessageIcon.Warning
                title = "Warning Alert"
                logger.warning(alert_message)
            else:
                icon = QSystemTrayIcon.MessageIcon.Information
                title = "Info Alert"
                logger.info(alert_message)

            # Show the notification
            self.tray_icon.showMessage(
                title,
                alert_message,
                icon,
                5000  # Duration in milliseconds
            )
        except Exception as e:
            logging.error(f"Error in display_alert_slot: {e}")

    @pyqtSlot(dict)
    def update_performance_charts_slot(self, data):
        """
        Slot to update performance charts in the main thread.
        """
        try:
            cpu_percent = data.get('cpu_percent', 0)
            gpu_percent = data.get('gpu_percent', 0)
            memory_percent = data.get('memory_percent', 0)
            disk_percent = data.get('disk_percent', 0)
            bytes_recv = data.get('bytes_recv', 0)

            # Update CPU Usage Chart
            self.figure_cpu.clear()
            ax_cpu = self.figure_cpu.add_subplot(111)
            ax_cpu.bar(['CPU Usage'], [cpu_percent], color='blue')
            ax_cpu.set_ylim(0, 100)
            ax_cpu.set_ylabel('Usage (%)')
            ax_cpu.set_title('CPU Usage')
            self.figure_cpu.tight_layout()
            self.canvas_cpu.draw()

            # Update GPU Usage Chart
            self.figure_gpu.clear()
            ax_gpu = self.figure_gpu.add_subplot(111)
            if gpu_percent > 0:
                ax_gpu.bar(['GPU Usage'], [gpu_percent], color='green')
                ax_gpu.set_ylim(0, 100)
                ax_gpu.set_ylabel('Usage (%)')
                ax_gpu.set_title('GPU Usage')
            else:
                ax_gpu.text(0.5, 0.5, 'No GPU Detected', horizontalalignment='center', verticalalignment='center')
            self.figure_gpu.tight_layout()
            self.canvas_gpu.draw()

            # Update Memory Usage Chart
            self.figure_memory.clear()
            ax_memory = self.figure_memory.add_subplot(111)
            ax_memory.bar(['Memory Usage'], [memory_percent], color='orange')
            ax_memory.set_ylim(0, 100)
            ax_memory.set_ylabel('Usage (%)')
            ax_memory.set_title('Memory Usage')
            self.figure_memory.tight_layout()
            self.canvas_memory.draw()

            # Update Disk Usage Chart
            self.figure_disk.clear()
            ax_disk = self.figure_disk.add_subplot(111)
            ax_disk.bar(['Disk Usage'], [disk_percent], color='purple')
            ax_disk.set_ylim(0, 100)
            ax_disk.set_ylabel('Usage (%)')
            ax_disk.set_title('Disk Usage')
            self.figure_disk.tight_layout()
            self.canvas_disk.draw()

            # Update Network Usage Chart
            self.figure_network.clear()
            ax_network = self.figure_network.add_subplot(111)
            ax_network.bar(['Bytes Received'], [bytes_recv], color='cyan')
            ax_network.set_ylabel('Bytes')
            ax_network.set_title('Network Usage')
            self.figure_network.tight_layout()
            self.canvas_network.draw()

        except Exception as e:
            logging.error(f"Error updating performance charts in slot: {e}")

    def update_system_vitals_charts(self):
        """
        Updates system vitals charts with current data.
        """
        try:
            cpu_percent = psutil.cpu_percent(interval=1)
            memory = psutil.virtual_memory()
            memory_percent = memory.percent
            disk = psutil.disk_usage('/')
            disk_percent = disk.percent
            net_io = psutil.net_io_counters()
            bytes_recv = net_io.bytes_recv

            # GPU Usage
            gpu_percent = self.get_gpu_usage()

            # Emit signal to update performance charts
            self.performance_update_signal.emit({
                'cpu_percent': cpu_percent,
                'gpu_percent': gpu_percent,
                'memory_percent': memory_percent,
                'disk_percent': disk_percent,
                'bytes_recv': bytes_recv
            })
        except Exception as e:
            logging.error(f"Error updating system vitals charts: {e}")

    def update_anomaly_chart(self):
        """
        Updates the anomaly chart with data from the last 24 hours.
        """
        try:
            self.figure_anomaly.clear()
            ax = self.figure_anomaly.add_subplot(111)

            time_threshold = datetime.now() - timedelta(hours=24)
            anomalies = self.session.query(AnomalyEntry).filter(AnomalyEntry.timestamp >= time_threshold).all()

            time_bins = []
            counts = []
            time_pointer = time_threshold.replace(minute=0, second=0, microsecond=0)

            while time_pointer <= datetime.now():
                bin_end = time_pointer + timedelta(hours=1)
                count = sum(1 for a in anomalies if time_pointer <= a.timestamp < bin_end)
                time_bins.append(time_pointer.strftime('%H:%M'))
                counts.append(count)
                time_pointer = bin_end

            ax.plot(time_bins, counts, marker='o')
            ax.set_title('Anomalies Every Hour')
            ax.set_xlabel('Time')
            ax.set_ylabel('Number of Anomalies')
            ax.tick_params(axis='x', rotation=45)
            self.figure_anomaly.tight_layout()
            self.canvas_anomaly.draw()
        except Exception as e:
            logging.error(f"Error updating anomaly chart: {e}")

    def update_event_level_pie_chart(self):
        """
        Updates the pie chart showing distribution of event levels.
        """
        try:
            self.figure_pie_event_levels.clear()
            ax = self.figure_pie_event_levels.add_subplot(111)

            logs = self.session.query(LogEntry).all()
            levels = [log.event_level for log in logs]
            level_counts = Counter(levels)

            ax.pie(level_counts.values(), labels=level_counts.keys(), autopct='%1.1f%%', startangle=140)
            ax.set_title('Event Level Distribution')
            self.figure_pie_event_levels.tight_layout()
            self.canvas_pie_event_levels.draw()
        except Exception as e:
            logging.error(f"Error updating event level pie chart: {e}")

    def update_event_sources_pie_chart(self):
        """
        Updates the pie chart showing distribution of event sources.
        """
        try:
            self.figure_pie_event_sources.clear()
            ax = self.figure_pie_event_sources.add_subplot(111)

            logs = self.session.query(LogEntry).all()
            sources = [log.source for log in logs]
            source_counts = Counter(sources).most_common(5)  # Top 5 sources

            if source_counts:
                labels, counts = zip(*source_counts)
                ax.pie(counts, labels=labels, autopct='%1.1f%%', startangle=140)
            else:
                ax.text(0.5, 0.5, 'No Data Available', horizontalalignment='center', verticalalignment='center')

            ax.set_title('Top 5 Event Sources')
            self.figure_pie_event_sources.tight_layout()
            self.canvas_pie_event_sources.draw()
        except Exception as e:
            logging.error(f"Error updating event sources pie chart: {e}")

    def update_event_ids_pie_chart(self):
        """
        Updates the pie chart showing distribution of event IDs.
        """
        try:
            self.figure_pie_event_ids.clear()
            ax = self.figure_pie_event_ids.add_subplot(111)

            logs = self.session.query(LogEntry).all()
            event_ids = [log.event_id for log in logs]
            event_id_counts = Counter(event_ids).most_common(5)  # Top 5 event IDs

            if event_id_counts:
                labels = [str(eid) for eid, _ in event_id_counts]
                counts = [count for _, count in event_id_counts]
                ax.pie(counts, labels=labels, autopct='%1.1f%%', startangle=140)
            else:
                ax.text(0.5, 0.5, 'No Data Available', horizontalalignment='center', verticalalignment='center')

            ax.set_title('Top 5 Event IDs')
            self.figure_pie_event_ids.tight_layout()
            self.canvas_pie_event_ids.draw()
        except Exception as e:
            logging.error(f"Error updating event IDs pie chart: {e}")

    def update_anomaly_types_pie_chart(self):
        """
        Updates the pie chart showing distribution of anomaly types.
        """
        try:
            self.figure_pie_anomaly_types.clear()
            ax = self.figure_pie_anomaly_types.add_subplot(111)

            anomalies = self.session.query(AnomalyEntry).all()
            anomaly_types = [anomaly.anomaly_type for anomaly in anomalies]
            anomaly_type_counts = Counter(anomaly_types)

            if anomaly_type_counts:
                ax.pie(anomaly_type_counts.values(), labels=anomaly_type_counts.keys(), autopct='%1.1f%%', startangle=140)
            else:
                ax.text(0.5, 0.5, 'No Data Available', horizontalalignment='center', verticalalignment='center')

            ax.set_title('Anomaly Types Distribution')
            self.figure_pie_anomaly_types.tight_layout()
            self.canvas_pie_anomaly_types.draw()
        except Exception as e:
            logging.error(f"Error updating anomaly types pie chart: {e}")

    def update_protocols_pie_chart(self):
        """
        Updates the pie chart showing distribution of network protocols.
        """
        try:
            self.figure_pie_protocols.clear()
            ax = self.figure_pie_protocols.add_subplot(111)

            protocols = [self.network_table.item(row, 3).text() for row in range(self.network_table.rowCount())]
            protocol_counts = Counter(protocols)

            if protocol_counts:
                ax.pie(protocol_counts.values(), labels=protocol_counts.keys(), autopct='%1.1f%%', startangle=140)
            else:
                ax.text(0.5, 0.5, 'No Data Available', horizontalalignment='center', verticalalignment='center')

            ax.set_title('Network Protocol Distribution')
            self.figure_pie_protocols.tight_layout()
            self.canvas_pie_protocols.draw()
        except Exception as e:
            logging.error(f"Error updating protocols pie chart: {e}")

    def update_performance_charts_thread(self):
        """
        Thread function to continuously update performance charts.
        """
        try:
            while True:
                cpu_percent = psutil.cpu_percent(interval=1)
                memory = psutil.virtual_memory()
                memory_percent = memory.percent
                disk = psutil.disk_usage('/')
                disk_percent = disk.percent
                net_io = psutil.net_io_counters()
                bytes_recv = net_io.bytes_recv

                # GPU Usage
                gpu_percent = self.get_gpu_usage()

                # Emit signal to update performance charts
                self.performance_update_signal.emit({
                    'cpu_percent': cpu_percent,
                    'gpu_percent': gpu_percent,
                    'memory_percent': memory_percent,
                    'disk_percent': disk_percent,
                    'bytes_recv': bytes_recv
                })

                time.sleep(1)
        except Exception as e:
            logging.error(f"Error in performance charts thread: {e}")

    def update_quantified_data_chart_thread(self):
        """
        Thread function to collect data and update the quantified data chart.
        """
        try:
            self.quantified_data = []
            while True:
                current_time = datetime.now()
                # Collect some data point (e.g., number of logs per minute)
                log_count = self.session.query(LogEntry).filter(
                    LogEntry.timestamp >= current_time - timedelta(minutes=1)
                ).count()
                self.quantified_data.append((current_time, log_count))

                # Keep data for the last hour
                self.quantified_data = [
                    (t, count) for t, count in self.quantified_data
                    if t >= current_time - timedelta(hours=1)
                ]

                # Emit signal to update the chart
                self.update_quantified_data_chart()

                time.sleep(60)
        except Exception as e:
            logging.error(f"Error in quantified data chart thread: {e}")

    def update_quantified_data_chart(self):
        """
        Updates the quantified data chart with collected data.
        """
        try:
            if not hasattr(self, 'quantified_data') or not self.quantified_data:
                return

            times, counts = zip(*self.quantified_data)
            self.figure_quantified.clear()
            ax = self.figure_quantified.add_subplot(111)
            ax.plot(times, counts, marker='o')
            ax.set_title('Logs Collected Over Time')
            ax.set_xlabel('Time')
            ax.set_ylabel('Number of Logs')
            ax.tick_params(axis='x', rotation=45)
            self.figure_quantified.tight_layout()
            self.canvas_quantified.draw()
        except Exception as e:
            logging.error(f"Error updating quantified data chart: {e}")

    def show_anomaly_breakdown(self):
        """
        Shows a breakdown of anomalies by type in a new chart.
        """
        try:
            # Get anomalies from the last 24 hours
            time_threshold = datetime.now() - timedelta(hours=24)
            anomalies = self.session.query(AnomalyEntry).filter(AnomalyEntry.timestamp >= time_threshold).all()

            anomaly_types = [a.anomaly_type for a in anomalies]
            type_counts = Counter(anomaly_types)

            # Create a new window for the breakdown chart
            breakdown_window = QtWidgets.QDialog(self)
            breakdown_window.setWindowTitle("Anomaly Breakdown by Type")
            breakdown_window.setGeometry(200, 200, 600, 400)

            figure = Figure()
            canvas = FigureCanvas(figure)
            ax = figure.add_subplot(111)
            ax.bar(type_counts.keys(), type_counts.values())
            ax.set_title('Anomaly Breakdown by Type')
            ax.set_xlabel('Anomaly Type')
            ax.set_ylabel('Count')
            ax.tick_params(axis='x', rotation=45)
            figure.tight_layout()

            layout = QVBoxLayout()
            layout.addWidget(canvas)
            breakdown_window.setLayout(layout)
            breakdown_window.exec()
        except Exception as e:
            logging.error(f"Error generating anomaly breakdown: {e}")

    def start_event_log_monitoring(self):
        """
        Starts monitoring Windows Event Logs.
        """
        try:
            if not self.is_monitoring:
                self.is_monitoring = True
                threading.Thread(target=self.event_log_thread_func, daemon=True).start()
                self.statusBar().showMessage("Status: Event Log Monitoring Active")
        except Exception as e:
            logging.error(f"Error starting event log monitoring: {e}")
            QMessageBox.critical(self, "Monitoring Error", f"Failed to start event log monitoring: {e}")

    def event_log_thread_func(self):
        """
        Function that runs in a separate thread to monitor Windows Event Logs.
        """
        logging.info("Starting Windows Event Log monitoring...")
        server = 'localhost'
        flags = win32evtlog.EVENTLOG_BACKWARDS_READ | win32evtlog.EVENTLOG_SEQUENTIAL_READ
        handles = {}
        event_read_position = {}

        while self.is_monitoring:
            try:
                monitored_logs = self.config['DEFAULT']['MonitoredLogs'].split(',')
                log_levels = self.config['DEFAULT']['LogLevels'].split(',')

                for log_type in monitored_logs:
                    log_type = log_type.strip()
                    try:
                        if log_type not in handles:
                            handles[log_type] = win32evtlog.OpenEventLog(server, log_type)
                            win32evtlog.GetNumberOfEventLogRecords(handles[log_type])
                            event_read_position[log_type] = 0

                        hand = handles[log_type]
                        total_records = win32evtlog.GetNumberOfEventLogRecords(hand)
                        events_to_read = total_records - event_read_position[log_type]

                        if events_to_read > 0:
                            events = win32evtlog.ReadEventLog(hand, flags, 0)
                            for event in events:
                                event_level = self.get_event_level(event.EventType)
                                if event_level in log_levels:
                                    self.process_event_log_entry(event, log_type)
                            event_read_position[log_type] = total_records
                    except Exception as e:
                        logging.error(f"Error processing log type '{log_type}': {e}")
                time.sleep(1)
            except Exception as e:
                logging.error(f"Error in event log monitoring thread: {e}")
                time.sleep(1)
        # Close all handles when monitoring stops
        for hand in handles.values():
            try:
                win32evtlog.CloseEventLog(hand)
            except Exception as e:
                logging.error(f"Error closing event log handle: {e}")
        logging.info("Stopped Windows Event Log monitoring.")

    def get_event_level(self, event_type):
        """
        Returns the event level as a string.
        """
        level_mapping = {
            win32evtlog.EVENTLOG_ERROR_TYPE: 'Error',
            win32evtlog.EVENTLOG_WARNING_TYPE: 'Warning',
            win32evtlog.EVENTLOG_INFORMATION_TYPE: 'Information',
            win32evtlog.EVENTLOG_AUDIT_SUCCESS: 'Audit Success',
            win32evtlog.EVENTLOG_AUDIT_FAILURE: 'Audit Failure'
        }
        return level_mapping.get(event_type, 'Unknown')

    def process_event_log_entry(self, event, log_type):
        """
        Processes a Windows Event Log entry.
        """
        try:
            current_time = datetime.now()
            event_id = event.EventID & 0xFFFF  # Mask to get the actual event ID
            event_level = self.get_event_level(event.EventType)
            event_type = event.EventType
            source = str(event.SourceName)
            try:
                message = str(win32evtlogutil.SafeFormatMessage(event, log_type))
            except Exception as e:
                message = "Could not retrieve message"
                logging.error(f"Error formatting message: {e}")

            # Check if the event ID is in the whitelist
            whitelist = self.config['DEFAULT'].get('EventIDWhitelist', '')
            event_id_whitelist = [int(eid.strip()) for eid in whitelist.split(',') if eid.strip().isdigit()]
            if event_id_whitelist and event_id in event_id_whitelist:
                # Log the ignored event
                ignored_message = f"Ignored Event ID: {event_id} from {source}."
                self.display_alert(ignored_message, 'Info')
                # Optionally, log to a separate table or log file
                return  # Ignore this event

            # Insert into database
            log_entry = LogEntry(
                timestamp=current_time,
                event_id=event_id,
                event_type=event_type,
                event_level=event_level,
                source=source,
                message=message
            )
            self.session.add(log_entry)
            self.session.commit()

            # Emit signal to update log table
            self.log_entry_signal.emit(log_entry)

            # Update event counts per minute
            time_key = current_time.strftime('%Y-%m-%d %H:%M')
            self.event_counts_per_minute[time_key] += 1

            # Check for anomalies
            self.check_for_anomalies(event_id, event_type, event_level, source, message)
        except Exception as e:
            logging.error(f"Error processing event log entry: {e}")
            # Log the error as an alert
            self.display_alert(f"Error processing event log entry: {e}", 'Error')

    def check_for_anomalies(self, event_id, event_type, event_level, source, message):
        """
        Checks if the current event is an anomaly.
        """
        try:
            # Convert event_level and source to numeric codes
            level_mapping = {'Error': 1, 'Warning': 2, 'Information': 3, 'Audit Success': 4, 'Audit Failure': 5}
            source_code = hash(source) % 1000  # Simple hash to numeric code
            event_level_code = level_mapping.get(event_level, 0)
            data_point = np.array([[event_id, event_type, event_level_code, source_code]])
            data_point = data_point.reshape((1, 1, 4))
            prediction = self.model.predict(data_point)
            if prediction[0][0] > float(self.config['DEFAULT'].get('AnomalyThreshold', 0.5)):
                # Anomaly detected
                anomaly_type = 'Windows Event Log Anomaly'
                alert_message = f"Anomaly detected at {datetime.now().strftime('%Y-%m-%d %H:%M:%S')} - Event ID: {event_id}, Level: {event_level}, Source: {source}."
                self.display_alert(alert_message, event_level)
                if self.config['DEFAULT'].getboolean('EmailAlerts'):
                    self.send_email_alert(alert_message)
                # Insert anomaly into database
                anomaly = AnomalyEntry(
                    timestamp=datetime.now(),
                    event_id=event_id,
                    event_type=event_type,
                    event_level=event_level,
                    source=source,
                    message=message,
                    anomaly_type=anomaly_type
                )
                self.session.add(anomaly)
                self.session.commit()

                # Emit signal to update alerts table
                self.alert_entry_signal.emit(anomaly)
        except Exception as e:
            logging.error(f"Error checking for anomalies: {e}")

    def display_alert(self, alert_message, alert_level='Info'):
        """
        Displays an alert message using system tray notifications.
        """
        try:
            # Emit signal to display alert
            self.alert_signal.emit(alert_message, alert_level)
        except Exception as e:
            logging.error(f"Error displaying alert: {e}")

    def send_email_alert(self, message):
        """
        Sends an email alert for critical anomalies.
        """
        try:
            email_settings = self.config['EMAIL']
            msg = EmailMessage()
            msg.set_content(message)
            msg['Subject'] = 'SIEM Alert Notification'
            msg['From'] = email_settings['SenderEmail']
            msg['To'] = email_settings['ReceiverEmail']

            context = ssl.create_default_context()

            with smtplib.SMTP_SSL(email_settings['SMTPServer'], int(email_settings['SMTPPort']), context=context) as server:
                server.login(email_settings['SenderEmail'], email_settings['Password'])
                server.send_message(msg)
            logger.info("Email alert sent.")
        except smtplib.SMTPAuthenticationError as e:
            logger.error(f"SMTP Authentication Error: {e}")
        except Exception as e:
            logger.error(f"Failed to send email alert: {e}")

    def retrain_model(self):
        """
        Retrains the LSTM model with current log data.
        """
        try:
            logs = self.session.query(LogEntry).all()
            if logs:
                # Prepare data
                level_mapping = {'Error': 1, 'Warning': 2, 'Information': 3, 'Audit Success': 4, 'Audit Failure': 5}
                data = []
                for log in logs:
                    event_id = log.event_id
                    event_type = log.event_type
                    event_level_code = level_mapping.get(log.event_level, 0)
                    source_code = hash(log.source) % 1000
                    data.append([event_id, event_type, event_level_code, source_code])
                data = np.array(data)
                data = data.reshape((len(data), 1, 4))
                targets = np.zeros(len(data))  # Assuming all current data is normal

                # Check for GPU availability
                if tf.config.list_physical_devices('GPU'):
                    try:
                        with tf.device('/GPU:0'):
                            self.model = Sequential()
                            self.model.add(LSTM(128, input_shape=(1, 4)))
                            self.model.add(Dense(1, activation='sigmoid'))

                            self.model.compile(loss='binary_crossentropy', optimizer='adam', metrics=['accuracy'])
                            self.model.fit(data, targets, epochs=10, batch_size=64)
                    except Exception as e:
                        logging.error(f"Error retraining model on GPU: {e}")
                        QMessageBox.critical(self, "Model Training Error", f"Failed to retrain model on GPU: {e}")
                        return
                else:
                    try:
                        self.model = Sequential()
                        self.model.add(LSTM(128, input_shape=(1, 4)))
                        self.model.add(Dense(1, activation='sigmoid'))

                        self.model.compile(loss='binary_crossentropy', optimizer='adam', metrics=['accuracy'])
                        self.model.fit(data, targets, epochs=10, batch_size=64)
                    except Exception as e:
                        logging.error(f"Error retraining model on CPU: {e}")
                        QMessageBox.critical(self, "Model Training Error", f"Failed to retrain model on CPU: {e}")
                        return

                self.model.save(self.config['DEFAULT']['ModelFile'])
                QMessageBox.information(self, "Retrain Model", "Model retrained successfully with current log data.")
                logger.info("Model retrained successfully with current log data.")
            else:
                QMessageBox.warning(self, "Retrain Model", "No data available for retraining.")
                logger.warning("No data available for retraining.")
        except Exception as e:
            logging.error(f"Error retraining model: {e}")
            QMessageBox.critical(self, "Model Error", f"Failed to retrain model: {e}")

    def toggle_network_monitoring(self):
        """
        Toggles network monitoring on or off.
        """
        try:
            if self.network_monitor_var.isChecked():
                if not self.is_network_monitoring:
                    self.is_network_monitoring = True
                    self.sniffer = AsyncSniffer(prn=self.process_packet)
                    self.sniffer.start()
                    self.statusBar().showMessage("Status: Network Monitoring Active")
            else:
                if self.is_network_monitoring:
                    self.is_network_monitoring = False
                    self.sniffer.stop()
                    self.statusBar().showMessage("Status: Network Monitoring Stopped")
        except Exception as e:
            logging.error(f"Error toggling network monitoring: {e}")
            QMessageBox.critical(self, "Network Monitoring Error", f"Failed to toggle network monitoring: {e}")

    def process_packet(self, packet):
        """
        Processes a network packet for anomaly detection.
        """
        try:
            if IP in packet:
                src_ip = packet[IP].src
                dst_ip = packet[IP].dst
                protocol = packet[IP].proto
                length = len(packet)
                info = ''
                if TCP in packet:
                    protocol = 'TCP'
                    info = f"Src Port: {packet[TCP].sport}, Dst Port: {packet[TCP].dport}"
                elif UDP in packet:
                    protocol = 'UDP'
                    info = f"Src Port: {packet[UDP].sport}, Dst Port: {packet[UDP].dport}"
                else:
                    protocol = 'Other'

                # Prepare data to emit
                packet_data = {
                    'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                    'src_ip': src_ip,
                    'dst_ip': dst_ip,
                    'protocol': protocol,
                    'length': length,
                    'info': info
                }

                # Emit signal to update network table
                self.packet_signal.emit(packet_data)

                # Check for anomalies
                self.check_network_anomalies(src_ip, dst_ip, protocol, length)
        except Exception as e:
            logging.error(f"Error processing packet: {e}")

    def check_network_anomalies(self, src_ip, dst_ip, protocol, length):
        """
        Checks if the network packet is an anomaly.
        """
        try:
            # Advanced anomaly detection using thresholds and patterns
            anomaly_detected = False
            anomaly_reason = ""
            if length > 1500:  # MTU size exceeded
                anomaly_detected = True
                anomaly_reason = "Packet size exceeds MTU."
            elif protocol == 'TCP' and (src_ip == dst_ip):
                anomaly_detected = True
                anomaly_reason = "Source and destination IP are the same."

            # Implement Isolation Forest or other advanced models here if needed

            if anomaly_detected:
                anomaly_type = 'Network Packet Anomaly'
                alert_message = f"Anomalous network packet detected from {src_ip} to {dst_ip} using {protocol} protocol. Reason: {anomaly_reason}"
                self.display_alert(alert_message, 'Critical')
                if self.config['DEFAULT'].getboolean('EmailAlerts'):
                    self.send_email_alert(alert_message)
                # Insert anomaly into database
                anomaly = AnomalyEntry(
                    timestamp=datetime.now(),
                    event_id=0,
                    event_type=0,
                    event_level='Critical',
                    source=src_ip,
                    message=alert_message,
                    anomaly_type=anomaly_type
                )
                self.session.add(anomaly)
                self.session.commit()

                # Emit signal to update alerts table
                self.alert_entry_signal.emit(anomaly)

                if self.ips_var.isChecked():
                    self.block_ip(src_ip)
        except Exception as e:
            logging.error(f"Error checking network anomalies: {e}")

    def block_ip(self, ip_address):
        """
        Blocks an IP address using firewall rules.
        """
        try:
            # Implement firewall rule to block the IP address
            # This requires administrative privileges
            command = f'netsh advfirewall firewall add rule name="Block {ip_address}" dir=in action=block remoteip={ip_address}'
            os.system(command)
            logger.info(f"Blocked IP address: {ip_address}")
        except Exception as e:
            logging.error(f"Error blocking IP address: {e}")

    def toggle_ips(self):
        """
        Toggles the Intrusion Prevention System on or off.
        """
        try:
            self.ips_enabled = self.ips_var.isChecked()
            if self.ips_enabled:
                logging.info("Intrusion Prevention System enabled.")
            else:
                logging.info("Intrusion Prevention System disabled.")
        except Exception as e:
            logging.error(f"Error toggling IPS: {e}")
            QMessageBox.critical(self, "IPS Error", f"Failed to toggle Intrusion Prevention System: {e}")

    def clear_alerts(self):
        """
        Clears the alerts table and status bar alert message.
        """
        try:
            self.alerts_table.setRowCount(0)
            self.statusBar().showMessage("Status: Monitoring Active")
            logging.info("Alerts cleared.")
        except Exception as e:
            logging.error(f"Error clearing alerts: {e}")
            QMessageBox.critical(self, "Clear Alerts Error", f"Failed to clear alerts: {e}")

    def clear_logs(self):
        """
        Clears all logs from the database and updates the UI.
        """
        try:
            reply = QMessageBox.question(self, 'Clear Logs', 'Are you sure you want to clear all logs?',
                                         QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No, QMessageBox.StandardButton.No)
            if reply == QMessageBox.StandardButton.Yes:
                self.session.query(LogEntry).delete()
                self.session.query(AnomalyEntry).delete()
                self.session.commit()
                self.event_counts_per_minute.clear()
                self.update_tables()
                QMessageBox.information(self, "Logs Cleared", "All logs have been cleared.")
                logging.info("All logs have been cleared.")
        except Exception as e:
            logging.error(f"Error clearing logs: {e}")
            QMessageBox.critical(self, "Clear Logs Error", f"Failed to clear logs: {e}")

    def export_logs(self):
        """
        Exports the logs to a CSV or JSON file.
        """
        try:
            options = QFileDialog.Options()
            file_name, _ = QFileDialog.getSaveFileName(self, "Export Logs", "", "CSV Files (*.csv);;JSON Files (*.json)", options=options)
            if file_name:
                logs = self.session.query(LogEntry).all()
                data = [{
                    'ID': log.id,
                    'Timestamp': log.timestamp.strftime('%Y-%m-%d %H:%M:%S'),
                    'Event ID': log.event_id,
                    'Event Type': log.event_type,
                    'Event Level': log.event_level,
                    'Source': log.source,
                    'Message': log.message
                } for log in logs]
                df = pd.DataFrame(data)
                if file_name.endswith('.csv'):
                    df.to_csv(file_name, index=False)
                elif file_name.endswith('.json'):
                    df.to_json(file_name, orient='records', lines=True)
                else:
                    df.to_csv(file_name, index=False)
                QMessageBox.information(self, "Export Successful", f"Logs exported successfully to {file_name}.")
                logger.info(f"Logs exported to {file_name}.")
        except Exception as e:
            logging.error(f"Error exporting logs: {e}")
            QMessageBox.critical(self, "Export Error", f"Failed to export logs: {e}")

    def on_exit(self):
        """
        Handles application exit, ensuring resources are properly released.
        """
        try:
            reply = QMessageBox.question(self, 'Quit', 'Do you really wish to quit?',
                                         QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No, QMessageBox.StandardButton.No)
            if reply == QMessageBox.StandardButton.Yes:
                self.is_monitoring = False
                self.is_network_monitoring = False
                if hasattr(self, 'sniffer') and self.sniffer:
                    self.sniffer.stop()
                if self.session:
                    self.session.close()
                if hasattr(self, 'tray_icon'):
                    self.tray_icon.hide()
                logger.info("Application exited.")
                QtCore.QCoreApplication.quit()
        except Exception as e:
            logging.error(f"Error during application exit: {e}")
            QtCore.QCoreApplication.quit()

    def initialize_system_tray(self):
        """
        Initializes the system tray icon for notifications.
        """
        try:
            self.tray_icon = QSystemTrayIcon(self)
            icon_path = os.path.join(os.path.dirname(__file__), 'icon.png')  # Ensure you have an 'icon.png' in your directory
            if not os.path.exists(icon_path):
                # Use a default icon if your icon file is missing
                self.tray_icon.setIcon(self.style().standardIcon(QtWidgets.QStyle.StandardPixmap.SP_ComputerIcon))
            else:
                self.tray_icon.setIcon(QIcon(icon_path))

            # Create a context menu for the tray icon
            tray_menu = QtWidgets.QMenu()
            show_action = tray_menu.addAction("Show")
            quit_action = tray_menu.addAction("Quit")

            show_action.triggered.connect(self.show)
            quit_action.triggered.connect(self.on_exit)

            self.tray_icon.setContextMenu(tray_menu)
            self.tray_icon.show()

            # Connect the activated signal to handle clicks
            self.tray_icon.activated.connect(self.on_tray_icon_activated)

            # Optional: Show a welcome message
            self.tray_icon.showMessage(
                "SIEM Application",
                "SIEM Application is running in the background.",
                QSystemTrayIcon.MessageIcon.Information,
                3000  # Duration in milliseconds
            )
        except Exception as e:
            logging.error(f"Error initializing system tray: {e}")
            QMessageBox.critical(self, "System Tray Error", f"Failed to initialize system tray: {e}")

    def on_tray_icon_activated(self, reason):
        """
        Handles tray icon activation (e.g., clicks).
        """
        if reason == QSystemTrayIcon.ActivationReason.Trigger:
            self.showNormal()
            self.activateWindow()

if __name__ == "__main__":
    if is_admin():
        try:
            app = QApplication(sys.argv)
            window = SIEMApp()
            window.show()
            sys.exit(app.exec())
        except Exception as e:
            logger.error(f"Unhandled exception in main loop: {e}")
            QMessageBox.critical(None, "Application Error", f"An unexpected error occurred: {e}")
    else:
        # Re-run the program with admin rights
        ctypes.windll.shell32.ShellExecuteW(None, "runas", sys.executable, sys.argv[0], None, 1)
