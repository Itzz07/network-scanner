import ipaddress
from scapy.all import ARP, Ether, srp, IP, ICMP
import socket
from tqdm import tqdm
from .mac_lookup import get_mac_vendor
from .logger import log_csv
import socket
import uuid

COMMON_PORTS = [22, 80, 443, 3389, 8080]

def guess_os(ttl):
    if ttl >= 128:
        return "Windows"
    elif ttl >= 64:
        return "Linux / Unix"
    elif ttl >= 255:
        return "Cisco / Router"
    else:
        return "Unknown"
    
def get_local_subnet():
    ip = socket.gethostbyname(socket.gethostname())
    return str(ipaddress.ip_network(f"{ip}/24", strict=False))

def get_my_info():
    hostname = socket.gethostname()
    ip_address = socket.gethostbyname(hostname)
    mac_address = ':'.join(['{:02x}'.format((uuid.getnode() >> ele) & 0xff)
                            for ele in range(0,8*6,8)][::-1])
    return {
        'hostname': hostname,
        'ip': ip_address,
        'mac': mac_address
    }


def scan_network(subnet):
    arp = ARP(pdst=subnet)
    ether = Ether(dst="ff:ff:ff:ff:ff:ff")
    packet = ether / arp
    result = srp(packet, timeout=2, verbose=0)[0]

    devices = []
    for _, received in result:
        vendor = get_mac_vendor(received.hwsrc)
        ip = received.psrc
        ttl_guess = get_ttl(ip)
        os_guess = guess_os(ttl_guess)
        devices.append({
            'ip': ip,
            'mac': received.hwsrc,
            'vendor': vendor,
            'os': os_guess
        })
    return devices

def get_ttl(ip):
    try:
        pkt = IP(dst=ip)/ICMP()
        resp = srp(Ether(dst="ff:ff:ff:ff:ff:ff")/pkt, timeout=2, verbose=0)[0]
        if resp:
            return resp[0][1].ttl
    except:
        pass
    return 0

def scan_ports(ip):
    open_ports = []
    for port in COMMON_PORTS:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(0.5)
            if sock.connect_ex((ip, port)) == 0:
                open_ports.append(port)
            sock.close()
        except:
            pass
    return open_ports

def full_scan(subnet):
    devices = scan_network(subnet)
    for device in tqdm(devices, desc="Scanning Ports"):
        device['open_ports'] = scan_ports(device['ip'])
        log_csv(device['ip'], device['mac'], device['vendor'], device['open_ports'], device['os'])
    return devices


# from scapy.all import ARP, Ether, srp
# import socket
# from tqdm import tqdm
# from .mac_lookup import get_mac_vendor
# from .logger import log

# COMMON_PORTS = [22, 80, 443, 3389, 8080]

# def scan_network(subnet):
#     arp = ARP(pdst=subnet)
#     ether = Ether(dst="ff:ff:ff:ff:ff:ff")
#     packet = ether / arp
#     result = srp(packet, timeout=2, verbose=0)[0]

#     devices = []
#     for _, received in result:
#         vendor = get_mac_vendor(received.hwsrc)
#         devices.append({
#             'ip': received.psrc,
#             'mac': received.hwsrc,
#             'vendor': vendor
#         })
#         log(f"Device found - IP: {received.psrc}, MAC: {received.hwsrc}, Vendor: {vendor}")
#     return devices

# def scan_ports(ip):
#     open_ports = []
#     for port in COMMON_PORTS:
#         try:
#             sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
#             sock.settimeout(0.5)
#             if sock.connect_ex((ip, port)) == 0:
#                 open_ports.append(port)
#             sock.close()
#         except:
#             pass
#     return open_ports

# def full_scan(subnet):
#     devices = scan_network(subnet)
#     for device in tqdm(devices, desc="Scanning Ports"):
#         device['open_ports'] = scan_ports(device['ip'])
#         from .logger import log_csv

#         # inside the full_scan loop
#         log_csv(device['ip'], device['mac'], device['vendor'], device['open_ports'])

#         log(f"Open ports on {device['ip']}: {device['open_ports']}")
#     return devices

# def guess_os(ttl):
#     if ttl >= 128:
#         return "Windows"
#     elif ttl >= 64:
#         return "Linux / Unix"
#     elif ttl >= 255:
#         return "Cisco / Network Device"
#     else:
#         return "Unknown"
