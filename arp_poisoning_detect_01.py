import scapy.all as scapy
import netifaces
import psutil
from collections import defaultdict
from termcolor import colored
import time
from threading import Timer, Lock

welcome_message = colored("Welcome to...", "yellow")  # Print welcome sequence
version_message = colored("Version 0.1 by Nils Kruchem", "yellow")
placeholder = colored("", "cyan")
art_message = colored(
    r"""
    _   ___ ___   ___  ___ ___ ___  ___  _  _ ___ _  _  ___   ___  ___ _____ ___ ___ _____ 
   /_\ | _ \ _ \ | _ \/ _ \_ _/ __|/ _ \| \| |_ _| \| |/ __| |   \| __|_   _| __/ __|_   _|
  / _ \|   /  _/ |  _/ (_) | |\__ \ (_) | .` || || .` | (_ | | |) | _|  | | | _| (__  | |  
 /_/ \_\_|_\_|   |_|  \___/___|___/\___/|_|\_|___|_|\_|\___| |___/|___| |_| |___\___| |_|  
    """, "cyan")  # blue

# Print welcome sequence with delays
print(welcome_message)
time.sleep(2)
print(art_message.strip())
time.sleep(1)
print(version_message)
print(placeholder)
time.sleep(2)

# Dictionaries for saving arp mappings and attack information
ip_to_macs = defaultdict(set)
last_seen = {}
reported_ips = {}
last_activity = 0
lock = Lock()
attack_active = False
previous_attack = False

def update_arp_table(ip, mac):
    # Refresh ARP table and check duplicate IP addresses.
    global last_activity, attack_active, previous_attack
    current_time = time.time()
    
    with lock:
        ip_to_macs[ip].add(mac)
        last_seen[ip] = current_time
        last_activity = current_time

        if len(ip_to_macs[ip]) > 1:
            if ip not in reported_ips or (current_time - reported_ips[ip]) > 15:
                print(colored(f"[WARNING] Possible ARP poisoning attack detected: IP address {ip} is used by several MAC addresses: {', '.join(ip_to_macs[ip])}", "red"))
                reported_ips[ip] = current_time
                attack_active = True
                previous_attack = True

def detect_arp_poisoning(packet):
    # Detect ARP poisoning attack based on ARP packages.
    if packet.haslayer(scapy.ARP) and packet[scapy.ARP].op == 2:  # ARP reply (is-at)
        src_ip = packet[scapy.ARP].psrc
        src_mac = packet[scapy.ARP].hwsrc
        update_arp_table(src_ip, src_mac)

def get_interface_name_from_ip(ip):
    # Determine the actual name of the network adapter based on the IP address.
    for iface in netifaces.interfaces():
        addrs = netifaces.ifaddresses(iface)
        if netifaces.AF_INET in addrs:
            for addr in addrs[netifaces.AF_INET]:
                if addr['addr'] == ip:
                    return iface
    raise RuntimeError(f"No network interface with IP address {ip} was found.")

def get_interface_for_gateway(gateway_ip):
    # Determine the actual name of the network adapter that is connected to the gateway.
    for iface in netifaces.interfaces():
        addrs = netifaces.ifaddresses(iface)
        if netifaces.AF_INET in addrs:
            for addr in addrs[netifaces.AF_INET]:
                if 'addr' in addr and addr['addr'] == gateway_ip:
                    return iface
    return None

def get_internet_interface():
    # Determine the network adapter that is connected to the Internet.
    gateways = netifaces.gateways()
    default_gateway = gateways.get('default')
    if default_gateway:
        for gateway_info in default_gateway.values():
            gateway_ip = gateway_info[0]
            iface = get_interface_for_gateway(gateway_ip)
            if iface:
                return iface
    return None

def is_virtual_adapter(iface):
    # Check if the network adapter is virtual.
    for nic in psutil.net_if_addrs()[iface]:
        if nic.family == psutil.AF_LINK:
            # In Linux, virtual adapters often have “veth” or “docker” in their name
            if 'veth' in iface or 'docker' in iface or 'virbr' in iface:
                return True
            # In Windows, we can search for known virtual adapter types
            if 'Virtual' in nic.address or 'VMware' in nic.address:
                return True
    return False

def get_priority_interface():
    # Determine the prioritized physical network adapter based on connection type and speed.
    interfaces = psutil.net_if_addrs()
    ethernet_adapters = []
    wifi_adapters = []
    other_adapters = []

    for iface in interfaces:
        if not is_virtual_adapter(iface) and iface not in ['lo', 'Loopback']:
            stats = psutil.net_if_stats()[iface]
            speed = stats.speed if stats.isup else 0
            if 'eth' in iface.lower() or 'en' in iface.lower():
                ethernet_adapters.append((iface, speed))
            elif 'wlan' in iface.lower() or 'wi-fi' in iface.lower():
                wifi_adapters.append((iface, speed))
            else:
                other_adapters.append((iface, speed))

    if ethernet_adapters:
        sorted_ethernet_adapters = sorted(ethernet_adapters, key=lambda item: item[1], reverse=True)
        return sorted_ethernet_adapters[0][0]
    elif wifi_adapters:
        sorted_wifi_adapters = sorted(wifi_adapters, key=lambda item: item[1], reverse=True)
        return sorted_wifi_adapters[0][0]
    elif other_adapters:
        sorted_other_adapters = sorted(other_adapters, key=lambda item: item[1], reverse=True)
        return sorted_other_adapters[0][0]
    else:
        raise RuntimeError("Kein aktiver physischer Netzwerkadapter gefunden.")

def reset_ip(ip):
    # Reset the status of the IP address.
    with lock:
        if ip in last_seen:
            del last_seen[ip]
            del ip_to_macs[ip]

def check_inactivity():
    # Check the attack inactivity of the IP addresses.
    global last_activity, attack_active, previous_attack
    current_time = time.time()
    inactive_ips = [ip for ip, last in last_seen.items() if current_time - last > 20]
    
    for ip in inactive_ips:
        reset_ip(ip)

    if attack_active and current_time - last_activity > 20:
        print(colored("[INFO]The ARP poisoning attack ended.", "green"))
        attack_active = False

    Timer(20, check_inactivity).start()

def monitor_network(interface):
    # Monitor the network for ARP poisoning attacks.
    print(colored(f"[INFO] Start detection of ARP poisoning attacks on interface {interface}...", "green"))
    try:
        scapy.sniff(store=False, prn=detect_arp_poisoning, filter="arp", iface=interface)
    except PermissionError:
        print(colored("[ERROR] Sniffing requires elevated privileges. Please run as administrator or root.", "red"))

if __name__ == "__main__":
    try:
        # Ty to get the internet adapter
        interface = get_internet_interface()
        
        if not interface:
            # If no Internet interface was found, prioritize available adapters
            interface = get_priority_interface()

        # Start inactivity check
        Timer(20, check_inactivity).start()

        # Start network monitoring
        monitor_network(interface)
    except Exception as e:
        print(colored(f"[ERROR] {str(e)}", "red"))
    finally:
        input("Press any key to end the program...")