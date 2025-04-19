import csv
from datetime import datetime
import os

CSV_FILE = 'scan_results.csv'
HEADERS = ['Timestamp', 'IP', 'MAC', 'Vendor', 'Open Ports', 'Guessed OS']

if not os.path.exists(CSV_FILE):
    with open(CSV_FILE, 'w', newline='') as f:
        writer = csv.writer(f)
        writer.writerow(HEADERS)

def log_csv(ip, mac, vendor, open_ports, os_guess):
    with open(CSV_FILE, 'a', newline='') as f:
        writer = csv.writer(f)
        writer.writerow([datetime.now(), ip, mac, vendor, ','.join(map(str, open_ports)), os_guess])


# from datetime import datetime

# LOG_FILE = 'scan_results.txt'

# def log(text):
#     with open(LOG_FILE, 'a') as f:
#         f.write(f"{datetime.now()} - {text}\n")
