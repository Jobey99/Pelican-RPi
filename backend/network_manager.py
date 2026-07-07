import os
import subprocess
import psutil
import socket
import re
from scapy.all import ARP, Ether, srp

def get_interfaces():
    """
    Returns a dictionary of network interfaces with status, IP, and MAC address.
    """
    interfaces = {}
    addrs = psutil.net_if_addrs()
    stats = psutil.net_if_stats()

    for name, info_list in addrs.items():
        # Skip loopback interface
        if name == 'lo':
            continue

        ip_address = None
        mac_address = None
        netmask = None

        for info in info_list:
            if info.family == socket.AF_INET:
                ip_address = info.address
                netmask = info.netmask
            elif info.family == psutil.AF_LINK:
                mac_address = info.address

        is_up = stats[name].isup if name in stats else False
        speed = stats[name].speed if name in stats else 0

        interfaces[name] = {
            "name": name,
            "ip": ip_address,
            "netmask": netmask,
            "mac": mac_address,
            "status": "up" if is_up else "down",
            "speed": speed
        }
    return interfaces

def set_interface_ip_runtime(interface: str, ip_cidr: str):
    """
    Temporarily configures an interface's static IP at runtime using the 'ip' command.
    Example: set_interface_ip_runtime('eth0', '192.168.1.99/24')
    """
    try:
        # Validate format (e.g. 192.168.1.99/24)
        if not re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/\d{1,2}$", ip_cidr):
            return {"success": False, "error": "Invalid IP/CIDR format"}

        # Remove existing IP configurations (optional, but clean)
        subprocess.run(["sudo", "ip", "addr", "flush", "dev", interface], check=True)

        # Set new IP
        subprocess.run(["sudo", "ip", "addr", "add", ip_cidr, "dev", interface], check=True)
        # Ensure interface is UP
        subprocess.run(["sudo", "ip", "link", "set", interface, "up"], check=True)

        return {"success": True, "message": f"Successfully configured {interface} to {ip_cidr} (Runtime only)"}
    except Exception as e:
        return {"success": False, "error": str(e)}

def set_interface_dhcp_runtime(interface: str):
    """
    Triggers DHCP client on an interface.
    """
    try:
        subprocess.run(["sudo", "ip", "addr", "flush", "dev", interface], check=True)
        # Run dhclient or dhcpcd depending on availability
        # Modern RPi OS with NetworkManager handles this best via nmcli if possible
        # Check if nmcli exists
        if subprocess.run(["which", "nmcli"], stdout=subprocess.DEVNULL).returncode == 0:
            subprocess.run(["sudo", "nmcli", "device", "reapply", interface], check=False)
        else:
            subprocess.run(["sudo", "dhclient", interface], check=True)
        return {"success": True, "message": f"Interface {interface} set to DHCP mode"}
    except Exception as e:
        return {"success": False, "error": str(e)}

def arp_scan(interface: str, subnet: str):
    """
    Sends ARP requests to find active hosts in a given subnet (e.g., '192.168.1.0/24')
    using Scapy. Returns a list of discovered hosts.
    """
    try:
        # Create ARP Request Packet
        arp = ARP(pdst=subnet)
        ether = Ether(dst="ff:ff:ff:ff:ff:ff")
        packet = ether/arp

        # Send packet and receive responses
        result = srp(packet, timeout=2, iface=interface, verbose=False)[0]

        discovered_hosts = []
        for sent, received in result:
            discovered_hosts.append({
                "ip": received.psrc,
                "mac": received.hwsrc
            })
        return {"success": True, "hosts": discovered_hosts}
    except Exception as e:
        return {"success": False, "error": str(e)}
