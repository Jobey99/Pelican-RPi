import threading
import time
from scapy.all import sniff, ARP
# Suppress warnings
import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

class IpConflictDetector:
    def __init__(self):
        self.ip_map = {}  # ip -> (mac, last_seen)
        self.conflicts = {}  # ip -> {mac_a, mac_b, timestamp}
        self.thread = None
        self.running = False
        self.interface = "eth0"
        self.lock = threading.Lock()

    def start(self, interface: str = "eth0"):
        if self.running:
            self.stop()
        self.interface = interface
        self.running = True
        with self.lock:
            self.ip_map.clear()
            self.conflicts.clear()
        self.thread = threading.Thread(target=self._sniff_loop, daemon=True)
        self.thread.start()

    def stop(self):
        self.running = False
        if self.thread:
            self.thread.join(timeout=1.0)
            self.thread = None

    def get_conflicts(self):
        with self.lock:
            # Format conflicts as serializable list
            return [
                {
                    "ip": ip,
                    "mac_a": details["mac_a"],
                    "mac_b": details["mac_b"],
                    "time": time.strftime('%H:%M:%S', time.localtime(details["timestamp"]))
                }
                for ip, details in self.conflicts.items()
            ]

    def clear_conflicts(self):
        with self.lock:
            self.conflicts.clear()

    def _sniff_loop(self):
        # Sniff only ARP packets
        while self.running:
            try:
                sniff(
                    iface=self.interface,
                    filter="arp",
                    prn=self._parse_arp_packet,
                    store=0,
                    timeout=2
                )
            except Exception:
                time.sleep(2)

    def _parse_arp_packet(self, pkt):
        if not pkt.haslayer(ARP):
            return

        # We care about ARP requests and replies (op = 1 or 2)
        # psrc = source IP, hwsrc = source MAC
        arp_op = pkt[ARP].op
        if arp_op not in [1, 2]:
            return
            
        ip = pkt[ARP].psrc
        mac = pkt[ARP].hwsrc.lower()

        # Ignore invalid/broadcast placeholder IPs (like 0.0.0.0)
        if not ip or ip == "0.0.0.0":
            return

        with self.lock:
            current_time = time.time()
            if ip in self.ip_map:
                existing_mac, last_seen = self.ip_map[ip]
                if existing_mac != mac:
                    # Conflict detected! Two different MACs claimed the same IP.
                    # To prevent transient false-positives (e.g. DHCP lease rollover),
                    # we register it as a conflict if the last claim was recent (within 10 minutes)
                    if current_time - last_seen < 600:
                        self.conflicts[ip] = {
                            "mac_a": existing_mac,
                            "mac_b": mac,
                            "timestamp": current_time
                        }
                # Update MAC mapping and timestamp
                self.ip_map[ip] = (mac, current_time)
            else:
                self.ip_map[ip] = (mac, current_time)
