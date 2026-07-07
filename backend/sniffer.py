import os
import json
import threading
import time
from collections import defaultdict
from scapy.all import sniff, ARP, IP, UDP, DHCP, DNS, DNSQR
# For decoding LLDP and CDP if they arrive
from scapy.contrib.lldp import LLDPDU

class PassiveSniffer:
    def __init__(self):
        self.devices = {}  # mac -> {ip, hostname, vendor, protocols, last_seen}
        self.thread = None
        self.running = False
        self.interface = "eth0"
        self.oui_db = self._load_oui_db()

    def _load_oui_db(self):
        db_path = os.path.join(os.path.dirname(__file__), "oui_database.json")
        if os.path.exists(db_path):
            try:
                with open(db_path, "r") as f:
                    return json.load(f)
            except Exception:
                pass
        return {}

    def get_vendor(self, mac):
        if not mac:
            return "Unknown"
        mac_prefix = mac.lower().replace("-", ":")[:8]
        return self.oui_db.get(mac_prefix, "Unknown Vendor")

    def _packet_callback(self, pkt):
        mac = None
        ip = None
        hostname = None
        protocol = None

        # 1. Parse Link Layer (MAC)
        if pkt.haslayer(Ether):
            mac = pkt[Ether].src
        elif pkt.haslayer(ARP):
            mac = pkt[ARP].hwsrc

        if not mac:
            return

        # 2. Parse ARP (Direct IP discovery)
        if pkt.haslayer(ARP):
            protocol = "ARP"
            if pkt[ARP].op in [1, 2]: # Request or Reply
                ip = pkt[ARP].psrc

        # 3. Parse IPv4 Layer
        elif pkt.haslayer(IP):
            ip = pkt[IP].src
            protocol = "IP"

        # 4. Parse DHCP (Great for Hostnames!)
        if pkt.haslayer(DHCP):
            protocol = "DHCP"
            # Look through DHCP options for Hostname (Option 12)
            options = pkt[DHCP].options
            for opt in options:
                if isinstance(opt, tuple) and opt[0] == "hostname":
                    try:
                        hostname = opt[1].decode("utf-8", errors="ignore")
                    except Exception:
                        pass

        # 5. Parse mDNS/DNS queries (Hostnames)
        elif pkt.haslayer(UDP) and pkt[UDP].dport == 5353: # mDNS
            protocol = "mDNS"
            if pkt.haslayer(DNS) and pkt[DNS].qd:
                # Get the queried name
                qname = pkt[DNS].qd.qname.decode("utf-8", errors="ignore")
                # Remove trailing dot and look for host naming patterns
                if ".local" in qname:
                    hostname = qname.split(".local")[0] + ".local"

        # 6. Parse LLDP (Switch port info)
        elif pkt.haslayer(LLDPDU):
            protocol = "LLDP"
            # We can extract Chassis ID / Port ID if desired, but we'll mark protocol for now

        # Update devices dictionary
        if mac:
            mac_lower = mac.lower()
            if mac_lower not in self.devices:
                self.devices[mac_lower] = {
                    "mac": mac,
                    "ip": ip,
                    "hostname": hostname or "Unknown",
                    "vendor": self.get_vendor(mac_lower),
                    "protocols": {protocol} if protocol else set(),
                    "last_seen": time.time()
                }
            else:
                dev = self.devices[mac_lower]
                if ip and (not dev["ip"] or dev["ip"] == "0.0.0.0"):
                    dev["ip"] = ip
                if hostname and (dev["hostname"] == "Unknown" or not dev["hostname"]):
                    dev["hostname"] = hostname
                if protocol:
                    dev["protocols"].add(protocol)
                dev["last_seen"] = time.time()

    def _sniff_loop(self):
        while self.running:
            try:
                sniff(iface=self.interface, prn=self._packet_callback, store=0, timeout=2)
            except Exception as e:
                time.sleep(2)

    def start(self, interface="eth0"):
        if self.running:
            self.stop()
        self.interface = interface
        self.devices.clear()
        self.running = True
        self.thread = threading.Thread(target=self._sniff_loop, daemon=True)
        self.thread.start()

    def stop(self):
        self.running = False
        if self.thread:
            self.thread.join(timeout=2)
            self.thread = None

    def get_results(self):
        # Convert set of protocols to list for JSON serialization
        results = []
        for mac, dev in self.devices.items():
            results.append({
                "mac": dev["mac"],
                "ip": dev["ip"] or "Unknown",
                "hostname": dev["hostname"],
                "vendor": dev["vendor"],
                "protocols": list(dev["protocols"]),
                "last_seen": time.strftime('%H:%M:%S', time.localtime(dev["last_seen"]))
            })
        return results

    def get_subnet_guesses(self):
        """
        Analyzes discovered IPs and suggests subnets.
        E.g., if we see 192.168.10.5, we suggest 192.168.10.0/24
        """
        ips = [dev["ip"] for dev in self.devices.values() if dev["ip"] and dev["ip"] != "Unknown"]
        guesses = defaultdict(int)
        for ip in ips:
            octets = ip.split(".")
            if len(octets) == 4:
                subnet_class_c = f"{octets[0]}.{octets[1]}.{octets[2]}.0/24"
                guesses[subnet_class_c] += 1
        
        # Sort by frequency of IPs in that subnet
        sorted_guesses = sorted(guesses.items(), key=lambda x: x[1], reverse=True)
        return [{"subnet": s, "devices_count": c} for s, c in sorted_guesses]

# Explicitly import Ether since scapy lazy loads it sometimes
from scapy.layers.l2 import Ether
