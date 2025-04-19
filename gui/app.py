import tkinter as tk
from tkinter import scrolledtext, ttk
from datetime import datetime
from scanner.core import full_scan, get_local_subnet, get_my_info, scan_network, scan_ports
import threading


DEFAULT_SUBNET = get_local_subnet()
scheduled_timer = None  # holds reference to the scheduled Timer
scheduled_running = False  # flag to track state

def start_gui():
    def run_scan():
        subnet = subnet_entry.get()
        output_box.delete(1.0, tk.END)
        output_box.insert(tk.END, f"Scanning {subnet}...\n")
        root.update()

        results = []
        devices = scan_network(subnet)

        if not devices:
            output_box.insert(tk.END, "⚠️ No devices found on this subnet.\n")
            return

        # Set up progress bar
        progress['maximum'] = len(devices)
        progress['value'] = 0
        status_label.config(text=f"Scanning ports on {len(devices)} device(s)...")

        for i, device in enumerate(devices):
            # Simulate or perform port scanning
            device['open_ports'] = scan_ports(device['ip'])  # <-- assuming this exists
            results.append(device)

            progress['value'] = i + 1
            status_label.config(text=f"Scanned {i + 1}/{len(devices)}")
            root.update_idletasks()

        display_results(results)
        status_label.config(text="✅ Scan complete!")
        

    # def run_scan():
    #     subnet = subnet_entry.get()
    #     output_box.delete(1.0, tk.END)
    #     output_box.insert(tk.END, f"Scanning {subnet}...\n")
    #     results = full_scan(subnet)

    #     if not results:
    #         output_box.insert(tk.END, "⚠️ No devices found on this subnet. Try checking your subnet or firewall settings.\n")
    #         return

    #     display_results(results)

    # def run_scan():
    #     subnet = subnet_entry.get()
    #     output_box.delete(1.0, tk.END)
    #     output_box.insert(tk.END, f"Scanning {subnet}...\n")
    #     results = full_scan(subnet)
    #     display_results(results)

    # def display_results(results):
        output_box.insert(tk.END, f"Scan complete at {datetime.now()}.\n\n")
        for dev in results:
            output_box.insert(tk.END,
                f"IP: {dev['ip']}\nMAC: {dev['mac']}\nVendor: {dev['vendor']}\n"
                f"OS: {dev['os']}\nPorts: {dev['open_ports']}\n\n"
            )
    
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
        global  scheduled_timer, scheduled_running

        if scheduled_running:
            output_box.insert(tk.END, "⚠️ Auto-scan is already running.\n")
            return

        try:
            interval = int(schedule_entry.get())
            if interval <= 0:
                output_box.insert(tk.END, "⚠️ Please enter a valid interval greater than 0.\n")
                return
        except ValueError:
            output_box.insert(tk.END, "⚠️ Invalid interval value.\n")
            return

        subnet = subnet_entry.get()
        scheduled_running = True
        output_box.insert(tk.END, f"✅ Auto-scan scheduled every {interval} minute(s).\n")

        def loop():
            global  scheduled_timer
            if not scheduled_running:
                return
            results = full_scan(subnet)
            display_results(results)
            scheduled_timer = threading.Timer(interval * 60, loop)
            scheduled_timer.start()

        loop()
    
    def stop_scheduled_scan():
        global  scheduled_timer, scheduled_running
        if scheduled_timer:
            scheduled_timer.cancel()
            scheduled_timer = None
        scheduled_running = False
        output_box.insert(tk.END, "⛔ Auto-scan stopped.\n")


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

    # Progress 
    progress = ttk.Progressbar(root, length=300, mode='determinate')
    progress.pack(pady=5)

    status_label = ttk.Label(root, text="")
    status_label.pack()

    # Buttons
    ttk.Button(root, text="Start Scan Now", command=run_scan).pack(pady=10)
    ttk.Button(root, text="Enable Auto-Scan", command=start_scheduled_scan).pack(pady=5)
    ttk.Button(root, text="Stop Auto-Scan", command=stop_scheduled_scan).pack(pady=5)

    # Output display
    output_box = scrolledtext.ScrolledText(root, width=90, height=25, bg="#2e2e2e", fg="#00ffcc", insertbackground='white')
    output_box.pack(pady=10)

    root.mainloop()
