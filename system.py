import platform
import subprocess
import os
import sys
import requests
from datetime import datetime
from zoneinfo import ZoneInfo
import threading
import time
import hashlib
import uuid


def check_antivirus_unix():
    """Checks for known antivirus services/processes on Unix systems."""
    known_services = [
        "clamav-daemon", "clamav-freshclam", "sav-protect", "sophos", 
        "avgd", "avast", "bitdefender", "esets", "comodo", "f-protd"
    ]

    found_services = []
    for service in known_services:
        try:
            result = subprocess.run(
                ["systemctl", "is-active", "--quiet", service],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL
            )
            if result.returncode == 0:
                found_services.append(service)
        except Exception:
            continue  

    if found_services:
        return f"Active antivirus services: {', '.join(found_services)}"

    known_processes = ["clamd", "freshclam", "savscand", "symcfgd", "sophos", "avgd", "avast", "bitdefender"]
    found_processes = []
    for process in known_processes:
        try:
            result = subprocess.run(["pgrep", "-f", process], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            if result.returncode == 0:
                found_processes.append(process)
        except FileNotFoundError:
            return "pgrep command not found"

    if found_processes:
        return f"Running antivirus processes: {', '.join(found_processes)}"
    else:
        return "No known antivirus services or processes are running"


# ---------- OS Detection ----------
def get_os():
    """Detects the current operating system."""
    system = platform.system()
    if system == "Windows":
        return "windows"
    elif system == "Darwin":
        return "macos"
    elif system == "Linux":
        return "linux"
    else:
        return "unknown"

# ---------- OS Version Check ----------
def get_os_version():
    """Returns the OS version string."""
    os_name = get_os()
    if os_name == "windows":
        return platform.version().strip()
    elif os_name == "macos":
        return platform.mac_ver()[0].strip()
    elif os_name == "linux":
        try:
            with open("/etc/os-release") as f:
                for line in f:
                    if "VERSION_ID" in line:
                        return line.strip().split("=")[1].strip('"')
        except:
            return platform.release()
    return "Unknown"

def is_up_to_date(current_version, latest_version):
    """Compares current and latest OS versions."""
    def parse(v): return [int(x) for x in v.split('.') if x.isdigit()]
    return parse(current_version) >= parse(latest_version)

# ---------- Disk Encryption ----------
import re

def check_windows_encryption():
    """Checks BitLocker encryption status on Windows."""
    try:
       
        output = subprocess.check_output(
            "manage-bde -status",
            shell=True,
            stderr=subprocess.STDOUT
        ).decode(errors='ignore')

        volumes = re.split(r'Volume ([A-Z]):', output)  
        encrypted = []
        not_encrypted = []

        for i in range(1, len(volumes), 2):
            drive_letter = volumes[i]
            vol_info = volumes[i+1]

            protection_on = "Protection Status: Protection On" in vol_info
            fully_encrypted = "Percentage Encrypted: 100%" in vol_info

            if protection_on and fully_encrypted:
                encrypted.append(drive_letter)
            else:
                not_encrypted.append(drive_letter)

        if encrypted and not not_encrypted:
            return "🔐 Fully Encrypted Drives: " + ", ".join(encrypted)
        elif not encrypted and not_encrypted:
            return "❌ Not Encrypted Drives: " + ", ".join(not_encrypted)
        elif encrypted and not_encrypted:
            return f"⚠️ Partially Encrypted — Encrypted: {encrypted}, Not Encrypted: {not_encrypted}"
        else:
            return "❓ No volumes found"

    except subprocess.CalledProcessError as e:
        error_msg = e.output.decode(errors='ignore')
        if "required resource was denied" in error_msg.lower():
            return (
                "❌ Unable to access BitLocker status: Access denied. "
                "This may be due to group policy, UAC, or BitLocker not being enabled. "
                "Try running as administrator or check your system settings."
            )
        return f"Error: {error_msg}"
    except Exception as e:
        return f"Unexpected error: {e}"

def check_macos_encryption():
    """Checks FileVault encryption status on macOS."""
    try:
        output = subprocess.check_output(['fdesetup', 'status'], stderr=subprocess.STDOUT).decode().strip()
        if "FileVault is On" in output:
            return "Fully Encrypted"
        elif "FileVault is Off" in output:
            return "Encryption Disabled"
        else:
            return output
    except:
        return "FileVault status unavailable or requires admin rights"

def check_linux_encryption():
    """Checks disk encryption status on Linux."""
    try:
        output = subprocess.check_output(['lsblk', '-o', 'NAME,TYPE,MOUNTPOINT'], stderr=subprocess.STDOUT).decode()
        if "crypt" in output:
            return "Fully Encrypted (LUKS)"
        elif "dm-" in output:
            return "Possibly Encrypted (device-mapper)"
        else:
            return "Not Encrypted"
    except:
        return "Unable to check encryption on Linux"

# ---------- Antivirus Check ----------
def basic_antivirus_check_windows():
    """Checks if Windows Defender is running."""
    try:
        output = subprocess.check_output(['sc', 'query', 'WinDefend'], shell=True).decode()
        if "RUNNING" in output:
            return "Windows Defender is running"
        else:
            return "Windows Defender is installed but not running"
    except:
        return "Could not check antivirus status"
import subprocess

def check_antivirus_status():
    """Checks for antivirus presence and status."""
    os_name = get_os()

    if os_name == "windows":
        try:
            command = [
                "wmic",
                "/namespace:\\\\root\\SecurityCenter2",
                "path",
                "AntiVirusProduct",
                "get",
                "displayName",
                "/format:table"
            ]
            result = subprocess.run(command, capture_output=True, text=True)
            if result.returncode == 0:
                output = result.stdout.strip()
              
                lines = output.splitlines()
                av_list = [line.strip() for line in lines[1:] if line.strip()]
                if av_list:
                    return "🛡️ Antivirus Found: " + "; ".join(av_list)
                else:
                    return "⚠️ No antivirus products found"
            else:
                return "⚠️ Failed to query antivirus using WMIC"
        except Exception as e:
            return f"❌ Error: {e}"
    else:
        return check_antivirus_unix()

# ---------- Inactivity Sleep Setting Check ----------
def check_inactivity_sleep_setting():
    """Checks inactivity sleep timeout settings."""
    """
    Returns a tuple (is_compliant, value, message)
    is_compliant: True if sleep timeout is <= 10 minutes (600 seconds), else False
    value: timeout value in seconds (or None if unavailable)
    message: human-readable status
    """
    os_name = get_os()
    try:
        if os_name == "windows":
            
            ac = subprocess.check_output(
                'powercfg /query SCHEME_CURRENT SUB_SLEEP STANDBYIDLE', shell=True
            ).decode(errors='ignore')
            import re
            match = re.search(r'Power Setting Index:\s*(0x[0-9a-fA-F]+)', ac)
            if match:
                seconds = int(match.group(1), 16)
                is_compliant = seconds <= 600
                return (is_compliant, seconds, f"Windows sleep timeout: {seconds//60} min")
            else:
                return (None, None, "Could not determine Windows sleep timeout")
        elif os_name == "macos":
          
            out = subprocess.check_output(['pmset', '-g']).decode()
            import re
            match = re.search(r'sleep\s+(\d+)', out)
            if match:
                minutes = int(match.group(1))
                is_compliant = minutes <= 10
                return (is_compliant, minutes*60, f"macOS sleep timeout: {minutes} min")
            else:
                return (None, None, "Could not determine macOS sleep timeout")
        elif os_name == "linux":
         
            try:
                out = subprocess.check_output(
                    ['gsettings', 'get', 'org.gnome.settings-daemon.plugins.power', 'sleep-inactive-ac-timeout']
                ).decode().strip()
                seconds = int(out)
                is_compliant = seconds <= 600
                return (is_compliant, seconds, f"Linux (GNOME) sleep timeout: {seconds//60} min")
            except Exception:
         
                try:
                    with open('/etc/systemd/logind.conf') as f:
                        for line in f:
                            if line.strip().startswith('IdleActionSec'):
                                val = line.split('=')[1].strip()
                                if val.endswith('min'):
                                    minutes = int(val[:-3])
                                    seconds = minutes * 60
                                elif val.endswith('s'):
                                    seconds = int(val[:-1])
                                else:
                                    seconds = int(val)
                                is_compliant = seconds <= 600
                                return (is_compliant, seconds, f"Linux (logind) sleep timeout: {seconds//60} min")
                except Exception:
                    pass
                return (None, None, "Could not determine Linux sleep timeout")
        else:
            return (None, None, "Unsupported OS for sleep check")
    except Exception as e:
        return (None, None, f"Error checking sleep timeout: {e}")

# ---------- MAIN ----------
def main():
    """Main entry point for system checks and reporting."""
    os_name = get_os()
    current_version = get_os_version()

    # Define latest versions manually
    latest_versions = {
        "windows": "10.0.19045",
        "macos": "14.5",
        "linux": "22.04"
    }
    latest_version = latest_versions.get(os_name, "unknown")
    up_to_date = is_up_to_date(current_version, latest_version)

    print(f"🖥️ OS: {os_name}")
    print(f"📦 Current Version: {current_version}")
    print(f"🆕 Latest Version: {latest_version}")
    print("✅ OS is up to date." if up_to_date else "⚠️ OS is outdated.")

    # Disk Encryption
    if os_name == "windows":
        encryption = check_windows_encryption()
    elif os_name == "macos":
        encryption = check_macos_encryption()
    elif os_name == "linux":
        encryption = check_linux_encryption()
    else:
        encryption = "Unsupported OS"
    print(f"🔐 Disk Encryption: {encryption}")

    # Antivirus
    av_status = check_antivirus_status()
    print(f"{av_status}")

    antivirus_basic = basic_antivirus_check_windows()
    print(f"Basic antivirus check: {antivirus_basic}")

    # Inactivity sleep setting
    sleep_compliant, sleep_value, sleep_message = check_inactivity_sleep_setting()
    print(f"💤 Inactivity Sleep: {sleep_message} (Compliant: {sleep_compliant})")

    # Build final payload
    system_id = get_system_id()
    system_status = {
        "id": system_id,
        "timestamp": datetime.now(ZoneInfo("Asia/Kolkata")).isoformat(),
        "os_name": os_name,
        "os_version": current_version,
        "is_up_to_date": up_to_date,
        "disk_encryption": encryption,
        "antivirus_status": av_status,
        "basic_antivirus_status": antivirus_basic,
        "inactivity_sleep": {
            "compliant": sleep_compliant,
            "value_seconds": sleep_value,
            "message": sleep_message
        }
    }

    send_status_to_api(system_status)

#  Updated to send data
def fetch_last_status_from_api(system_id):
    """Fetches last status for this system from API."""
    try:
        response = requests.get(f"http://localhost:8000/status/{system_id}")
        if response.status_code == 200:
            return response.json()
        else:
            return None
    except Exception:
        return None

def status_dict_for_comparison(status):
    """Removes timestamp for status comparison."""
    # Remove timestamp for comparison
    d = dict(status)
    d.pop("timestamp", None)
    return d

def send_status_to_api(system_status, method="post"):
    """Sends system status to API using POST or PUT."""
    try:
        url = f"http://localhost:8000/status"
        if method == "put":
            url = f"http://localhost:8000/status/{system_status['id']}"
            response = requests.put(url, json=system_status)
        else:
            response = requests.post(url, json=system_status)
        print(f"📤 API Response: {response.status_code} - {response.text}")
    except requests.RequestException as e:
        print(f"❌ Failed to send data to API: {e}")

def daemon_check(interval_minutes=15):
    """Daemon thread for periodic system checks and reporting."""
    system_id = get_system_id()
    while True:

        os_name = get_os()
        current_version = get_os_version()
        latest_versions = {
            "windows": "10.0.19045",
            "macos": "14.5",
            "linux": "22.04"
        }
        latest_version = latest_versions.get(os_name, "unknown")
        up_to_date = is_up_to_date(current_version, latest_version)

        if os_name == "windows":
            encryption = check_windows_encryption()
        elif os_name == "macos":
            encryption = check_macos_encryption()
        elif os_name == "linux":
            encryption = check_linux_encryption()
        else:
            encryption = "Unsupported OS"

        av_status = check_antivirus_status()
        antivirus_basic = basic_antivirus_check_windows()
        sleep_compliant, sleep_value, sleep_message = check_inactivity_sleep_setting()

        system_status = {
            "id": system_id,
            "timestamp": datetime.now(ZoneInfo("Asia/Kolkata")).isoformat(),
            "os_name": os_name,
            "os_version": current_version,
            "is_up_to_date": up_to_date,
            "disk_encryption": encryption,
            "antivirus_status": av_status,
            "basic_antivirus_status": antivirus_basic,
            "inactivity_sleep": {
                "compliant": sleep_compliant,
                "value_seconds": sleep_value,
                "message": sleep_message
            }
        }

        last_status = fetch_last_status_from_api(system_id)
        print(f"Last stored state for this system:\n{last_status}\n")  # Print last state
        if last_status is None:
            send_status_to_api(system_status, method="post")
        elif status_dict_for_comparison(system_status) != status_dict_for_comparison(last_status):
            send_status_to_api(system_status, method="put")

        
        time.sleep(max(1, min(interval_minutes, 60)))

def start_daemon(interval_minutes=15):
    """Starts the background daemon thread."""
    t = threading.Thread(target=daemon_check, args=(interval_minutes,), daemon=True)
    t.start()
    print(f"Daemon started: checking every {interval_minutes} minutes.")

def get_system_id():
    """Returns a stable, hashed MAC address as system ID."""
  
    mac = uuid.getnode()
  
    return hashlib.sha256(str(mac).encode()).hexdigest()

if __name__ == "__main__":
    main()

    start_daemon(interval_minutes=15)
    while True: time.sleep(3600) 
