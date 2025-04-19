import csv
from datetime import datetime
import os

DEFAULT_CSV_FILE = 'scan_results.csv'
HEADERS = ['Timestamp', 'IP', 'MAC', 'Vendor', 'Open Ports', 'Guessed OS']

def log_csv(ip, mac, vendor, open_ports, os_guess, file_path=DEFAULT_CSV_FILE):
    # Create file with headers if it doesn't exist
    if not os.path.exists(file_path):
        try:
            with open(file_path, 'w', newline='') as f:
                writer = csv.writer(f)
                writer.writerow(HEADERS)
        except Exception as e:
            print(f"[!] Failed to create CSV file: {e}")
            return

    # Append row
    try:
        with open(file_path, 'a', newline='') as f:
            writer = csv.writer(f)
            writer.writerow([
                datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                ip,
                mac,
                vendor,
                ','.join(map(str, open_ports)) if open_ports else "None",
                os_guess
            ])
    except Exception as e:
        print(f"[!] Failed to write to CSV: {e}")


# from datetime import datetime

# LOG_FILE = 'scan_results.txt'

# def log(text):
#     with open(LOG_FILE, 'a') as f:
#         f.write(f"{datetime.now()} - {text}\n")
