import tkinter as tk
from tkinter import scrolledtext, ttk
from datetime import datetime
from scanner.core import full_scan, get_local_subnet, get_my_info
import threading


DEFAULT_SUBNET = get_local_subnet()

def start_gui():
    def run_scan():
        subnet = subnet_entry.get()
        output_box.delete(1.0, tk.END)
        output_box.insert(tk.END, f"Scanning {subnet}...\n")
        results = full_scan(subnet)
        display_results(results)

    # def display_results(results):
    #     output_box.insert(tk.END, f"Scan complete at {datetime.now()}.\n\n")
    #     for dev in results:
    #         output_box.insert(tk.END,
    #             f"IP: {dev['ip']}\nMAC: {dev['mac']}\nVendor: {dev['vendor']}\n"
    #             f"OS: {dev['os']}\nPorts: {dev['open_ports']}\n\n"
    #         )
    def display_results(results):
        output_box.insert(tk.END, f"Scan complete at {datetime.now()}.\n\n")

        for dev in results:
            if dev['ip'] == your_ip or dev['mac'].lower() == your_mac.lower():
                label = " (YOU)"
            else:
                label = ""

            output_box.insert(tk.END,
                f"IP: {dev['ip']}{label}\nMAC: {dev['mac']}\nVendor: {dev['vendor']}\n"
                f"OS: {dev['os']}\nPorts: {dev['open_ports']}\n\n"
            )

    def start_scheduled_scan():
        interval = int(schedule_entry.get())
        subnet = subnet_entry.get()
        def loop():
            results = full_scan(subnet)
            display_results(results)
            threading.Timer(interval * 60, loop).start()
        loop()

    root = tk.Tk()
    root.title("Python Network Scanner")
    root.geometry("750x550")
    root.configure(bg="#1e1e1e")
 
    # Styling
    style = ttk.Style()
    style.theme_use('clam')
    style.configure("TLabel", foreground="white", background="#1e1e1e", font=('Segoe UI', 10))
    style.configure("TButton", font=('Segoe UI', 10), padding=6)

    # Get host details
    my_info = get_my_info()
    your_ip = my_info['ip']
    your_mac = my_info['mac']
    hostname = my_info['hostname']

    ttk.Label(root, text=f"Your Hostname: {hostname}").pack()
    ttk.Label(root, text=f"Your IP: {your_ip}").pack()
    ttk.Label(root, text=f"Your MAC: {your_mac}\n").pack()

    # Subnet input
    ttk.Label(root, text="Subnet (e.g., 192.168.1.0/24):").pack(pady=5)
    subnet_entry = ttk.Entry(root, width=30)
    subnet_entry.insert(0, DEFAULT_SUBNET)
    subnet_entry.pack()

    # Schedule input
    ttk.Label(root, text="Auto-scan every X minutes (optional):").pack(pady=5)
    schedule_entry = ttk.Entry(root, width=10)
    schedule_entry.insert(0, "0")  # 0 means disabled
    schedule_entry.pack()

    # Buttons
    ttk.Button(root, text="Start Scan Now", command=run_scan).pack(pady=10)
    ttk.Button(root, text="Enable Auto-Scan", command=start_scheduled_scan).pack()

    # Output display
    output_box = scrolledtext.ScrolledText(root, width=90, height=25, bg="#2e2e2e", fg="#00ffcc", insertbackground='white')
    output_box.pack(pady=10)

    root.mainloop()
