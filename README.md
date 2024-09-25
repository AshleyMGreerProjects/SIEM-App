# SIEM-App

## **Introduction**
The **SIEM (Security Information and Event Management) Application** is an advanced tool designed to monitor system logs, analyze network traffic, detect anomalies in real-time using machine learning, and provide system performance insights through a user-friendly graphical interface. The application integrates several key libraries, such as **TensorFlow** for anomaly detection, **Scapy** for network packet monitoring, **SQLAlchemy** for database operations, and **PyQt6** for the graphical user interface (GUI).

---

## **Table of Contents**

1. [SIEM Python Script - Full Breakdown](#siem-python-script---full-breakdown)
2. [Log File Analysis (siem_app.log)](#log-file-analysis-siem_applog)
3. [Database File Breakdown (siem_logs.db)](#database-file-breakdown-siem_logsdb)
4. [LSTM Model Details (lstm_model.h5)](#lstm-model-details-lstm_modelh5)
5. [Image Analysis](#image-analysis)
   - [Alerts.png](#alertspng)
   - [Graphs and Charts of Events.png](#graphs-and-charts-of-eventspng)
   - [Logs.png](#logspng)
   - [Network Monitoring.png](#network-monitoringpng)
   - [Start Up.png](#start-uppng)
6. [Detailed Data from Charts, Graphs, and Logs](#detailed-data-from-charts-graphs-and-logs)
7. [Anomaly Detection Breakdown](#anomaly-detection-breakdown)
8. [Quantitative Data Points](#quantitative-data-points)
9. [Conclusion](#conclusion)

---

## **1. SIEM Python Script - Full Breakdown**

### **Key Libraries**
1. **PyQt6**: Responsible for building the user interface, including real-time performance monitoring displays.
   ```python
   from PyQt6.QtWidgets import QMainWindow, QApplication
   from PyQt6.QtCore import QTimer
   from PyQt6.QtGui import QIcon
   ```

2. **SQLAlchemy**: Manages database operations, where logs and anomalies are stored.
   ```python
   from sqlalchemy import create_engine, Column, Integer, String, Text, DateTime, Float
   from sqlalchemy.ext.declarative import declarative_base
   from sqlalchemy.orm import sessionmaker
   ```

3. **Scapy**: Captures and analyzes network traffic (e.g., IP addresses, packet sizes, and protocols).
   ```python
   from scapy.all import sniff, IP, TCP, UDP
   ```

4. **TensorFlow (Keras API)**: Drives the LSTM model used for real-time anomaly detection.
   ```python
   import tensorflow as tf
   from tensorflow.keras.models import load_model
   from tensorflow.keras.layers import LSTM, Dense
   ```

5. **Psutil**: Provides real-time system performance metrics, such as CPU, memory, and network activity.
   ```python
   import psutil
   ```

6. **Win32evtlog**: Extracts data from the Windows Event Log for analysis.
   ```python
   import win32evtlog
   ```

7. **Loguru**: Implements a robust logging mechanism that captures key events and system behaviors.
   ```python
   from loguru import logger
   ```

### **Core Functions**

#### **load_or_train_model()**
Loads or trains the **LSTM model** used for anomaly detection.
```python
def load_or_train_model(self):
    model_file = self.config['DEFAULT']['ModelFile']
    if os.path.exists(model_file):
        model = tf.keras.models.load_model(model_file)
    else:
        model = self.train_new_model()
    return model
```

#### **process_packet()**
Processes network packets captured by **Scapy** and checks for anomalies, logging details like **source IP**, **destination IP**, **protocol**, and **packet length**.
```python
def process_packet(self, packet):
    if IP in packet:
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        protocol = packet[IP].proto
        length = len(packet)
        # Check for anomalies based on packet size, IP spoofing, etc.
```

#### **process_event_log_entry()**
Processes Windows Event Log entries, analyzing **event IDs**, **event levels**, and other parameters for anomalies.
```python
def process_event_log_entry(self, event, log_type):
    current_time = datetime.now()
    event_id = event.EventID & 0xFFFF
    event_level = self.get_event_level(event.EventType)
    # Insert into database, check for anomalies
```

#### **update_performance_charts_slot()**
Monitors system performance (CPU, memory, and network activity) and updates the PyQt6 GUI using **matplotlib**.
```python
def update_performance_charts_slot(self, data):
    cpu_percent = data.get('cpu_percent', 0)
    memory_percent = data.get('memory_percent', 0)
    # Update CPU, Memory, Disk, and Network charts using matplotlib
```

---

## **2. Log File Analysis (siem_app.log)**

### **Notable Log Entries**:
- **TensorFlow oneDNN Warning**:
  ```
  I tensorflow/core/util/port.cc:153 oneDNN custom operations are on. 
  You may see slightly different numerical results due to floating-point round-off errors.
  ```

- **Cryptography Deprecation Warning**:
  ```
  CryptographyDeprecationWarning: TripleDES has been moved to cryptography.hazmat.decrepit.ciphers.algorithms.TripleDES and will be removed in version 48.0.0.
  ```

- **Anomaly Detected**:
  ```
  WARNING | display_alert_slot:907 - Anomaly detected at 2024-09-25 01:38:01 - Event ID: 701, Level: Warning, Source: Win32k.
  ```

---

## **3. Database File Breakdown (siem_logs.db)**

### **LogEntry Table**:
- **Timestamp**: The time the event occurred.
- **Event ID**: Unique identifier for the event.
- **Event Level**: Severity of the event (e.g., Information, Warning, Critical).
- **Source**: Origin of the event (e.g., Microsoft-Windows-Kernel-Power).
- **Message**: Detailed message regarding the event.

### **AnomalyEntry Table**:
- **Timestamp**: Time the anomaly was detected.
- **Event ID**: Unique ID tied to the event triggering the anomaly.
- **Anomaly Type**: Specifies the type of anomaly (e.g., Network Packet Anomaly).
- **Source**: The source triggering the anomaly (e.g., Win32k).
- **Message**: Details of the anomaly event.

---

## **4. LSTM Model Details (lstm_model.h5)**

### **Model Architecture**:
- **LSTM Layers**: Captures sequential dependencies in the data (e.g., time-series analysis for anomaly detection).
- **Dense Layer**: Classifies the output as normal or anomalous.

### **Purpose**:
The model detects anomalies in **network traffic** and **system logs** using historical data, improving the accuracy of anomaly detection over time as it is further trained.

---

## **5. Image Analysis**

### **1. Alerts.png**
- **Critical Alerts**: These alerts are generated from detected anomalies in network traffic, such as **oversized TCP packets**.
- **Warnings**: Related to power management and graphical subsystem anomalies (e.g., **Win32k warnings**).

### **2. Graphs and Charts of Events.png**

#### **Anomalies Every Hour (Line Graph)**:
- **4000 anomalies** were detected between **15:00 and 16:00**, representing the biggest spike in the day.
- The rest of the hours show minimal anomalies.

#### **Event Level Distribution (Pie Chart)**:
- **92.5% of events** are classified as **Information**.
- **6.5%** are warnings or errors.

#### **Top Event Sources (Pie Chart)**:
1. **Microsoft-Windows-Kernel-Power**: Contributes to **32.1%** of events.
2. **TPM (Trusted Platform Module)**: **24.6%**.
3. **Software Protection Platform Service**: **21.5%**.
4. **DellTechHub**: **11.1%**.
5. **Alienware SupportAssist Remediation**: **10.6%**.

#### **Top Event IDs (Pie Chart)**:
1. **Event ID 17**: **31.5%** of all events.
2. **Event ID 0**: **29.0%**.
3. **Event ID 566**: **13.8%**.
4. **Event ID 16384**: **12.3%**.
5. **Event ID 16394**: **13.4%**.

#### **Anomaly Types Distribution (Pie Chart)**:
- **96.0%** of detected anomalies are **Network Packet Anomalies**.
- **4.0%** are **Windows Event Log Anomalies**.

#### **Network Protocol Distribution (Pie Chart)**:
- **66.8% TCP traffic**.
- **32.6% UDP traffic**

.
- **0.6% Other protocols**.

### **3. Logs.png**
Logs contain information about system events such as **power state changes**, **system warnings**, and **security events**.

### **4. Network Monitoring.png**
Displays details on network traffic, including:
- **Source IP**, **Destination IP**, **Packet Length**, and **Protocol** (TCP/UDP).
- **Port Information** (e.g., Src Port 443, Dst Port 52404).

### **5. Start Up.png**
Shows the startup process of the application, including **TensorFlow initialization** and **cryptographic warnings**.

---

## **6. Detailed Data from Charts, Graphs, and Logs**

### **Anomalies Every Hour**:
- **4000 anomalies** were detected between **15:00 and 16:00**.

### **Event Level Distribution**:
- **92.5%** of events were classified as **Information**.
- **6.5%** were classified as **Warnings** or **Errors**.

### **Top 5 Event Sources**:
1. **Microsoft-Windows-Kernel-Power**: **32.1%** of total events.
2. **TPM (Trusted Platform Module)**: **24.6%**.
3. **DellTechHub**: **11.1%**.

### **Top 5 Event IDs**:
1. **Event ID 17**: **31.5%**.
2. **Event ID 0**: **29.0%**.

### **Network Protocol Breakdown**:
- **66.8% TCP traffic**.
- **32.6% UDP traffic**.

### **Top 5 Anomalies**:
1. **96% Network Packet Anomalies**.
2. **4% Windows Event Log Anomalies**.

---

## **7. Anomaly Detection Breakdown**

- **Event ID 701 (Win32k)**: Triggered **5 warnings** regarding graphical subsystem anomalies.
- **Oversized Network Packets**: Multiple packets detected exceeded the **MTU** size limit.

---

## **8. Quantitative Data Points**

- **4000 anomalies** detected between **15:00 and 16:00**.
- **92.5% of events** were informational.
- **6.5%** flagged as warnings or errors.
- **66.8% TCP traffic**, **32.6% UDP traffic**.
- **170ms/step** average inference time for TensorFlow processing.

---

## **9. Conclusion**

The **SIEM Application** is a comprehensive tool for real-time system monitoring and anomaly detection, integrating machine learning to enhance the detection of security incidents. Through powerful logging, database management, and real-time network packet analysis, it successfully identifies critical issues in network traffic and system performance, providing administrators with actionable insights.
