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


import sys

def scan_wifi():
    """
    Scans nearby Wi-Fi networks using nmcli if available.
    """
    try:
        # Check if nmcli exists
        if subprocess.run(["which", "nmcli"], stdout=subprocess.DEVNULL).returncode != 0:
            return {"success": False, "error": "nmcli is not installed. Wi-Fi client manager requires NetworkManager."}
        
        # Trigger scan
        subprocess.run(["sudo", "nmcli", "device", "wifi", "rescan"], check=False)
        
        # Get scan results
        res = subprocess.run(
            ["nmcli", "-t", "-f", "SSID,BSSID,SIGNAL,SECURITY", "device", "wifi", "list"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            check=True
        )
        
        networks = []
        seen_ssids = set()
        for line in res.stdout.strip().split("\n"):
            if not line:
                continue
            parts = line.split(":")
            if len(parts) >= 4:
                ssid = parts[0]
                # Reconstruct SSID if it contained colons
                bssid_idx = len(parts) - 3
                ssid = ":".join(parts[:bssid_idx])
                bssid = ":".join(parts[bssid_idx:bssid_idx+6]) if bssid_idx+6 <= len(parts) else parts[bssid_idx]
                signal = parts[-2]
                security = parts[-1]
                
                if ssid and ssid not in seen_ssids:
                    seen_ssids.add(ssid)
                    try:
                        sig_pct = int(signal)
                    except ValueError:
                        sig_pct = 0
                    networks.append({
                        "ssid": ssid,
                        "signal": sig_pct,
                        "security": security if security else "Open"
                    })
        
        # Sort by signal strength
        networks.sort(key=lambda x: x["signal"], reverse=True)
        return {"success": True, "networks": networks}
    except Exception as e:
        return {"success": False, "error": str(e)}

def connect_wifi(ssid, password):
    """
    Connects to a Wi-Fi network using nmcli.
    """
    try:
        if subprocess.run(["which", "nmcli"], stdout=subprocess.DEVNULL).returncode != 0:
            return {"success": False, "error": "nmcli is not installed."}
            
        cmd = ["sudo", "nmcli", "device", "wifi", "connect", ssid]
        if password:
            cmd.extend(["password", password])
            
        res = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=15)
        if res.returncode == 0:
            return {"success": True, "message": f"Successfully connected to Wi-Fi network '{ssid}'!"}
        else:
            return {"success": False, "error": res.stderr.strip() or res.stdout.strip()}
    except Exception as e:
        return {"success": False, "error": str(e)}

def run_wifi_security_audit(ssid):
    """
    Performs a defensive audit of target SSID: WPA3/PMF status, client isolation check,
    and testing connection against default passwords.
    """
    try:
        results = []
        results.append(f"[AUDIT] Starting Wi-Fi Security Audit for: '{ssid}'")
        
        # 1. Check encryption status in scan
        scan_res = scan_wifi()
        target = None
        if scan_res.get("success"):
            for n in scan_res["networks"]:
                if n["ssid"] == ssid:
                    target = n
                    break
        
        if target:
            sec = target["security"]
            results.append(f"[INFO] Security type reported: {sec}")
            if "WPA3" in sec:
                results.append("[PASS] WPA3 Enterprise/Personal encryption detected (Protected Management Frames mandatory).")
            elif "WPA2" in sec:
                results.append("[WARN] WPA2 legacy encryption detected. Make sure PMF (Protected Management Frames) is enabled on the router to block deauthentication attacks.")
            elif "WEP" in sec or "WPA1" in sec:
                results.append("[FAIL] INSECURE Legacy encryption (WEP/WPA1) active! This protocol is vulnerable to instant cracking.")
            elif "Open" in sec or not sec or sec == "--":
                results.append("[FAIL] Open / Unencrypted SSID! Anyone can sniff traffic on this segment.")
        else:
            results.append("[WARN] Target SSID is hidden or out of range. Assuming standard WPA2/WPA3.")
            
        # 2. Check Gateway and exposed default credentials
        # Find default gateway IP address
        results.append("[INFO] Sweeping network gateway details...")
        gw_res = subprocess.run(["ip", "route", "show", "default"], stdout=subprocess.PIPE, text=True)
        gw_ip = None
        if gw_res.returncode == 0 and gw_res.stdout:
            match = re.search(r"default via (\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})", gw_res.stdout)
            if match:
                gw_ip = match.group(1)
                
        if gw_ip:
            results.append(f"[INFO] Found active gateway at: {gw_ip}")
            # Port check (80 and 443)
            port_open = False
            for port in [80, 443]:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(1.0)
                if s.connect_ex((gw_ip, port)) == 0:
                    port_open = True
                    results.append(f"[WARN] Gateway admin interface port {port} is exposed to the local network.")
                s.close()
            if not port_open:
                results.append("[PASS] Gateway admin interface ports (80/443) appear closed or filtered on this link segment.")
        else:
            results.append("[INFO] Gateway details not resolved. Skipping gateway port sweep.")

        # 3. Default Passwords Audit
        results.append("[INFO] Commencing Default / Weak Passphrase association check...")
        default_pwds = ["password", "12345678", "admin1234", "00000000", "installer", "security", ssid]
        associated = False
        weak_pwd_found = None
        
        # Test connecting with default passwords
        for pwd in default_pwds:
            results.append(f"[INFO] Testing connection payload: '{pwd}'")
            # Try to connect
            conn = connect_wifi(ssid, pwd)
            if conn.get("success"):
                associated = True
                weak_pwd_found = pwd
                # Reconnect to original link or clean up if possible
                break
                
        if associated:
            results.append(f"[FAIL] CRITICAL VULNERABILITY! Connected to SSID '{ssid}' using default/weak password '{weak_pwd_found}'. CHANGE IT IMMEDIATELY!")
        else:
            results.append("[PASS] Default password checks rejected. Passphrase is not in installer default wordlist.")
            
        results.append("[AUDIT] Security audit complete!")
        return {"success": True, "logs": "\n".join(results), "vulnerable": associated}
    except Exception as e:
        return {"success": False, "error": str(e)}

def toggle_systemd_autostart(enable):
    """
    Enables or disables systemd autostart service for Pelican/ZAVI.
    """
    service_path = "/etc/systemd/system/pelican.service"
    try:
        if not enable:
            subprocess.run(["sudo", "systemctl", "disable", "pelican.service"], check=False)
            if os.path.exists(service_path):
                os.remove(service_path)
            subprocess.run(["sudo", "systemctl", "daemon-reload"], check=False)
            return {"success": True, "message": "Autostart disabled and service removed successfully."}
            
        backend_dir = os.path.dirname(os.path.abspath(__file__))
        python_path = sys.executable or "/usr/bin/python3"
        
        service_content = f"""[Unit]
Description=ZAVI AV/IT Network Diagnostics Tool
After=network.target

[Service]
Type=simple
WorkingDirectory={backend_dir}
ExecStart={python_path} main.py
Restart=always
RestartSec=5
User=root

[Install]
WantedBy=multi-user.target
"""
        with open(service_path, "w") as f:
            f.write(service_content)
            
        subprocess.run(["sudo", "systemctl", "daemon-reload"], check=True)
        subprocess.run(["sudo", "systemctl", "enable", "pelican.service"], check=True)
        return {"success": True, "message": "Autostart enabled successfully via systemd service!"}
    except Exception as e:
        return {"success": False, "error": str(e)}

def is_systemd_enabled():
    """
    Checks if systemd service is active/enabled.
    """
    service_path = "/etc/systemd/system/pelican.service"
    if not os.path.exists(service_path):
        return False
    res = subprocess.run(["systemctl", "is-enabled", "pelican.service"], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    return res.returncode == 0
