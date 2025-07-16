 🖥️ Cross-Platform System Monitoring Utility (Client + Backend)

A lightweight cross-platform system monitoring utility built with Python and FastAPI.  
It performs regular checks on system security and power settings and reports the results to a local API.

## 🔍 Features

- ✅ OS Detection and Version Check
- 🔐 Disk Encryption Status:
  - BitLocker (Windows)
  - FileVault (macOS)
  - LUKS/device-mapper (Linux)
- 🛡️ Antivirus Detection:
  - Windows Defender and third-party AVs (WMIC)
  - Known AV processes (Linux/macOS)
- 💤 Inactivity Sleep Settings Compliance (<= 10 minutes)
- 🔄 Daemon support for periodic checking and updating (every 15 minutes)
- 📡 FastAPI backend with:
  - POST/PUT endpoints to store/update status
  - GET filters, list, and export to CSV
  - JSON-based file persistence (`system_status_db.json`)

---

## 📦 Project Structure
project/

├── system.py # System monitor and daemon client  

├── systemstatusapi.py # FastAPI backend

├── system_status_db.json # Local status store (auto-generated)

├── requirements.txt # Python dependencies

├── .gitignore # Ignore sensitive and generated files

└── README.md


## ⚙️ Installation & Setup

### 1. Clone the Repository 
```bash
git clone https://github.com/vdh05/internship-assignment.git
```

### 2. Create a virtual environment (optional but recommended)
```bash

python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
```
### 3. Install dependencies
```bash

pip install -r requirements.txt
```
### 4. Start the Backend Server (FastAPI)
```bash
uvicorn systemstatusapi:app --reload
```
### 5. Run the System Monitor Script
```bash
python system.py
```
