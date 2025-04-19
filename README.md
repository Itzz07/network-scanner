# 🕵️ Python Network Scanner (GUI)

A full-featured Python-based network scanner with a GUI. Built using Scapy, Tkinter, and Python standard libraries.

## 🔧 Features

- Detect devices on local subnet (IP, MAC)
- MAC vendor lookup (online API)
- Common port scanning
- OS guessing (based on TTL)
- Export results to CSV
- GUI with live output and auto-scheduling

## 🚀 How to Run (Windows)

```bash
pip install -r requirements.txt
python main.py

# To Build an .exe
# pip install pyinstaller
# pyinstaller --onefile --windowed main.py

# Add --icon=icon.ico to the build command:
# pyinstaller --onefile --windowed --icon=icon.ico main.py
