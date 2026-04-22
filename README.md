# Log-Based Intrusion Detection System

A Flask-based intrusion detection system that analyzes authentication logs to identify potential brute-force attacks. The system supports multiple log formats and provides structured outputs for analysis and reporting.

---

## Features

- Multi-format log support:
  - CSV files
  - TXT / LOG files
  - Windows Event Logs (.evtx)

-  Detects brute-force attacks based on:
  - Repeated failed login attempts
  - Successful login after multiple failures

- Extracts timestamps from logs (EVTX support)

- Displays suspicious logs responsible for detection

- Allows downloading detected attack logs as a CSV file

---

## Detection Logic

The system uses rule-based detection:

- Counts failed login attempts per IP address  
- **5 or more failed attempts → marked as suspicious**  
- If a successful login occurs after multiple failures:
  -  **Brute Force Attack Detected**
- If no success occurs:
  -  **Possible Brute Force Attempt**

---

## Supported Input Formats

### CSV Files
- Supports raw logs and structured datasets  
- If the following columns are present, network-based detection is used:

IPV4_SRC_ADDR, IPV4_DST_ADDR, L4_DST_PORT


---

### TXT / LOG Files
- Standard SSH log format

**Example:**
Failed password for admin from 192.168.1.10
Accepted password for admin from 192.168.1.10


---

### EVTX Files (Windows Logs)
- Parses Windows Security Event Logs  
- Uses:
  - `Event ID 4625` → Failed login  
  - `Event ID 4624` → Successful login  

---

## Output

After analysis, the system provides:

- Detection result  
- Confidence level  
- Logs responsible for the detection  

---

##  Export Feature

Download detected suspicious logs in CSV format.

**CSV Structure:**
Timestamp, Status, IP


**Example:**
2024-05-01T10:15:30Z, Failed, 192.168.1.10
2024-05-01T10:15:40Z, Success, 192.168.1.10


---

##  Tech Stack

- Python  
- Flask  
- Pandas  
- python-evtx  

---

## Getting Started

### 1. Install dependencies
```bash
pip install flask pandas python-evtx
2. Run the application
python app.py
3. Open in browser
