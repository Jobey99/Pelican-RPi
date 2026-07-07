import threading
import time
import random
import subprocess
from scapy.all import sniff, sendp, Ether, IP, UDP, BOOTP, DHCP, get_if_hwaddr
# Suppress warnings
import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

class LocalDhcpServer:
    def __init__(self):
        self.thread = None
        self.running = False
        self.interface = "eth0"
        self.server_ip = "192.168.99.1"
        self.lease_ip = "192.168.99.100"
        self.client_mac = None
        self.leased = False
        self.original_ip_info = None

    def start(self, interface: str = "eth0"):
        if self.running:
            self.stop()
            
        self.interface = interface
        self.leased = False
        self.client_mac = None
        
        # 1. Store current interface IP to restore later if needed
        # We can flush eth0 and assign 192.168.99.1 dynamically
        try:
            # Dynamically set RPi interface to 192.168.99.1 so it can act as gateway
            subprocess.run(["sudo", "ip", "addr", "flush", "dev", interface], check=True)
            subprocess.run(["sudo", "ip", "addr", "add", "192.168.99.1/24", "dev", interface], check=True)
            subprocess.run(["sudo", "ip", "link", "set", interface, "up"], check=True)
        except Exception as e:
            return {"success": False, "error": f"Failed to configure RPi IP for DHCP Server: {e}"}

        self.running = True
        self.thread = threading.Thread(target=self._run_server, daemon=True)
        self.thread.start()
        return {"success": True, "message": "DHCP Server started on interface 192.168.99.1 (leases 192.168.99.100)"}

    def stop(self):
        self.running = False
        if self.thread:
            self.thread.join(timeout=1.0)
            self.thread = None
        
        # Reset interface addressing (flushing it)
        try:
            subprocess.run(["sudo", "ip", "addr", "flush", "dev", self.interface], check=False)
            # Re-trigger DHCP client to get normal IP
            if subprocess.run(["which", "nmcli"], stdout=subprocess.DEVNULL).returncode == 0:
                subprocess.run(["sudo", "nmcli", "device", "reapply", self.interface], check=False)
            else:
                subprocess.run(["sudo", "dhclient", self.interface], check=False)
        except Exception:
            pass
            
        return {"success": True, "message": "DHCP Server stopped and interface reset."}

    def get_status(self):
        return {
            "active": self.running,
            "interface": self.interface,
            "server_ip": self.server_ip,
            "lease_ip": self.lease_ip,
            "client_mac": self.client_mac or "None",
            "leased": self.leased
        }

    def _run_server(self):
        # Sniff for DHCP requests (UDP sport=68, dport=67)
        filter_str = "udp and port 67"
        while self.running:
            try:
                sniff(
                    iface=self.interface,
                    filter=filter_str,
                    prn=self._handle_dhcp_packet,
                    store=0,
                    timeout=2
                )
            except Exception:
                time.sleep(2)

    def _handle_dhcp_packet(self, pkt):
        if not pkt.haslayer(DHCP) or not pkt.haslayer(BOOTP):
            return

        # Get transaction ID and client MAC
        xid = pkt[BOOTP].xid
        client_mac = pkt[BOOTP].chaddr[:6] # First 6 bytes contain the MAC address
        client_mac_str = ":".join(f"{b:02x}" for b in client_mac)
        
        # Get server MAC
        try:
            server_mac_str = get_if_hwaddr(self.interface)
        except Exception:
            server_mac_str = "ff:ff:ff:ff:ff:ff"

        # Determine DHCP Message Type
        options = pkt[DHCP].options
        msg_type = None
        for opt in options:
            if isinstance(opt, tuple) and opt[0] == "message-type":
                msg_type = opt[1]
                break

        if msg_type == 1:  # DHCP DISCOVER
            # Craft DHCP OFFER
            self.client_mac = client_mac_str
            offer_pkt = (
                Ether(src=server_mac_str, dst="ff:ff:ff:ff:ff:ff") /
                IP(src=self.server_ip, dst="255.255.255.255") /
                UDP(sport=67, dport=68) /
                BOOTP(op=2, yiaddr=self.lease_ip, siaddr=self.server_ip, chaddr=client_mac, xid=xid) /
                DHCP(options=[
                    ("message-type", "offer"),
                    ("subnet_mask", "255.255.255.0"),
                    ("router", self.server_ip),
                    ("name_server", "8.8.8.8"),
                    ("lease_time", 7200),
                    ("server_id", self.server_ip),
                    "end"
                ])
            )
            sendp(offer_pkt, iface=self.interface, verbose=False)

        elif msg_type == 3:  # DHCP REQUEST
            # Craft DHCP ACK
            self.leased = True
            ack_pkt = (
                Ether(src=server_mac_str, dst="ff:ff:ff:ff:ff:ff") /
                IP(src=self.server_ip, dst="255.255.255.255") /
                UDP(sport=67, dport=68) /
                BOOTP(op=2, yiaddr=self.lease_ip, siaddr=self.server_ip, chaddr=client_mac, xid=xid) /
                DHCP(options=[
                    ("message-type", "ack"),
                    ("subnet_mask", "255.255.255.0"),
                    ("router", self.server_ip),
                    ("name_server", "8.8.8.8"),
                    ("lease_time", 7200),
                    ("server_id", self.server_ip),
                    "end"
                ])
            )
            sendp(ack_pkt, iface=self.interface, verbose=False)
