import threading
import time
from collections import defaultdict
from scapy.all import sniff, IP, UDP
# Suppress warnings
import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

class MulticastAuditor:
    def __init__(self):
        self.streams = {}  # ip -> {bytes_in_window, bps, packet_count, last_seen, flooding}
        self.thread = None
        self.running = False
        self.interface = "eth0"
        self.lock = threading.Lock()
        
        # Window variables for bitrate calculations
        self.bytes_counter = defaultdict(int)
        self.window_start = time.time()

    def start(self, interface: str = "eth0"):
        if self.running:
            self.stop()
        self.interface = interface
        self.running = True
        
        with self.lock:
            self.streams.clear()
            self.bytes_counter.clear()
            self.window_start = time.time()
            
        self.thread = threading.Thread(target=self._sniff_loop, daemon=True)
        self.thread.start()

    def stop(self):
        self.running = False
        if self.thread:
            self.thread.join(timeout=1.0)
            self.thread = None

    def get_status(self):
        with self.lock:
            # Recalculate bitrate for current window
            now = time.time()
            dt = now - self.window_start
            if dt >= 1.0:
                for ip, byte_count in self.bytes_counter.items():
                    # Calculate Mbps
                    mbps = round((byte_count * 8) / (dt * 1000000), 3)
                    
                    if ip not in self.streams:
                        self.streams[ip] = {
                            "ip": ip,
                            "bandwidth_mbps": mbps,
                            "packet_count": 0,
                            "flooding": False,
                            "last_seen": now
                        }
                    else:
                        self.streams[ip]["bandwidth_mbps"] = mbps
                        
                    # If stream bitrate is high (e.g. > 0.5 Mbps) and we haven't joined, 
                    # it means the switch is flooding this port.
                    self.streams[ip]["flooding"] = mbps > 0.5
                    self.streams[ip]["last_seen"] = now
                    
                # Reset window
                self.bytes_counter.clear()
                self.window_start = now

            # Filter out stale streams (> 10s old)
            active_streams = []
            for ip, stream in list(self.streams.items()):
                if now - stream["last_seen"] < 10:
                    active_streams.append({
                        "ip": stream["ip"],
                        "protocol": stream.get("protocol", "UDP Multicast"),
                        "bandwidth_mbps": stream["bandwidth_mbps"],
                        "packet_count": stream["packet_count"],
                        "flooding": stream["flooding"],
                        "last_seen": time.strftime('%H:%M:%S', time.localtime(stream["last_seen"]))
                    })
                else:
                    self.streams.pop(ip, None)
                    
            return {
                "active": self.running,
                "interface": self.interface,
                "streams": active_streams,
                "flooding_detected": any(s["flooding"] for s in active_streams)
            }

    def _sniff_loop(self):
        # Sniff only UDP multicast packets (Dst IPs in 224.0.0.0/4)
        filter_str = "udp and dst net 224.0.0.0/4"
        while self.running:
            try:
                sniff(
                    iface=self.interface,
                    filter=filter_str,
                    prn=self._handle_packet,
                    store=0,
                    timeout=2
                )
            except Exception:
                time.sleep(2)

    def _handle_packet(self, pkt):
        if not pkt.haslayer(IP) or not pkt.haslayer(UDP):
            return
            
        dst_ip = pkt[IP].dst
        dport = pkt[UDP].dport
        pkt_len = len(pkt)
        
        # Categorize protocol
        proto = "UDP Multicast"
        if 14300 <= dport <= 14600:
            proto = "Dante"
        elif dport == 5004:
            proto = "AES67"
        elif dport == 5961 or (5960 <= dport <= 5970):
            proto = "NDI"
        elif dport == 6454:
            proto = "Art-Net"
        elif dport == 5568:
            proto = "sACN"
        elif dst_ip.startswith("224.0.0.251") or dport == 5353:
            proto = "mDNS"
        
        with self.lock:
            self.bytes_counter[dst_ip] += pkt_len
            if dst_ip not in self.streams:
                self.streams[dst_ip] = {
                    "ip": dst_ip,
                    "protocol": proto,
                    "bandwidth_mbps": 0.0,
                    "packet_count": 1,
                    "flooding": False,
                    "last_seen": time.time()
                }
            else:
                self.streams[dst_ip]["packet_count"] += 1
                self.streams[dst_ip]["protocol"] = proto
