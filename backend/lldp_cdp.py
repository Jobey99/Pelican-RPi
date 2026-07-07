import threading
import time
from scapy.all import sniff, Ether, IP, Raw
# Suppress warnings
import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

class LldpCdpParser:
    def __init__(self):
        self.info = {
            "switch_name": "Listening...",
            "port_id": "Listening...",
            "vlan": "Listening...",
            "ip": "Listening...",
            "model": "Listening...",
            "protocol": "None",
            "last_updated": 0
        }
        self.thread = None
        self.running = False
        self.interface = "eth0"

    def start(self, interface: str = "eth0"):
        if self.running:
            self.stop()
        self.interface = interface
        self.running = True
        self.info = {
            "switch_name": "Listening...",
            "port_id": "Listening...",
            "vlan": "Listening...",
            "ip": "Listening...",
            "model": "Listening...",
            "protocol": "None",
            "last_updated": 0
        }
        self.thread = threading.Thread(target=self._sniff_loop, daemon=True)
        self.thread.start()

    def stop(self):
        self.running = False
        if self.thread:
            self.thread.join(timeout=1.0)
            self.thread = None

    def get_info(self):
        # If it's been more than 90 seconds without updates, clear or show stale
        if self.info["last_updated"] > 0 and (time.time() - self.info["last_updated"] > 90):
            self.info["switch_name"] = "Stale (No frames in >90s)"
        return self.info

    def _sniff_loop(self):
        # Sniff for LLDP (EtherType 0x88cc) or CDP (Dest MAC 01:00:0c:cc:cc:cc)
        # BPF filter: ether proto 0x88cc or ether dst 01:00:0c:cc:cc:cc
        filter_str = "ether proto 0x88cc or ether dst 01:00:0c:cc:cc:cc"
        while self.running:
            try:
                sniff(
                    iface=self.interface,
                    filter=filter_str,
                    prn=self._parse_packet,
                    store=0,
                    timeout=2
                )
            except Exception:
                time.sleep(2)

    def _parse_packet(self, pkt):
        try:
            # 1. Check for LLDP (EtherType 0x88cc)
            if pkt.haslayer(Ether) and pkt[Ether].type == 0x88cc:
                self._parse_lldp(bytes(pkt[Ether].payload))
            # 2. Check for CDP (often LLC / SNAP)
            elif pkt.haslayer(Ether) and pkt[Ether].dst == "01:00:0c:cc:cc:cc":
                # Convert packet to raw bytes and seek CDP header (usually starts with \x02\xbb or \x01\xbb)
                # CDP payload starts after SNAP header (usually 8 bytes offset after LLC)
                raw_bytes = bytes(pkt)
                # CDP standard header: Version (1 byte), TTL (1 byte), Checksum (2 bytes)
                # We search for CDP identifier
                self._parse_cdp(raw_bytes)
        except Exception:
            pass

    def _parse_lldp(self, payload: bytes):
        """
        Manually parses raw LLDP TLV bytes for maximum reliability.
        """
        idx = 0
        switch_name = None
        port_id = None
        vlan = None
        mgmt_ip = None
        model = None

        while idx < len(payload) - 2:
            # First 2 bytes contain Type (7 bits) and Length (9 bits)
            header = int.from_bytes(payload[idx:idx+2], byteorder='big')
            tlv_type = header >> 9
            tlv_len = header & 0x01FF
            
            idx += 2
            if idx + tlv_len > len(payload):
                break
                
            tlv_value = payload[idx:idx+tlv_len]
            idx += tlv_len
            
            if tlv_type == 0:  # End of LLDPDU
                break
            elif tlv_type == 1:  # Chassis ID
                # Subtype is first byte
                subtype = tlv_value[0]
                val = tlv_value[1:]
                if subtype == 4: # MAC address
                    switch_name = ":".join(f"{b:02x}" for b in val)
                elif subtype == 5: # Network address
                    switch_name = val.decode('utf-8', errors='ignore')
                elif subtype == 7: # Locally assigned string
                    switch_name = val.decode('utf-8', errors='ignore')
            elif tlv_type == 2:  # Port ID
                subtype = tlv_value[0]
                val = tlv_value[1:]
                if subtype == 3: # MAC
                    port_id = ":".join(f"{b:02x}" for b in val)
                elif subtype == 5: # Interface Name
                    port_id = val.decode('utf-8', errors='ignore')
                elif subtype == 7: # Local String
                    port_id = val.decode('utf-8', errors='ignore')
            elif tlv_type == 5:  # System Name
                switch_name = tlv_value.decode('utf-8', errors='ignore')
            elif tlv_type == 6:  # System Description
                model_full = tlv_value.decode('utf-8', errors='ignore')
                # Extract first line (usually contains model name)
                model = model_full.split("\r")[0].split("\n")[0].strip()
            elif tlv_type == 8:  # Management Address
                # First byte is address string length
                addr_len = tlv_value[0]
                # Second byte is subtype (1 is IPv4)
                addr_subtype = tlv_value[1]
                if addr_subtype == 1 and addr_len >= 5:
                    ip_bytes = tlv_value[2:6]
                    mgmt_ip = ".".join(str(b) for b in ip_bytes)
            elif tlv_type == 127:  # Org Specific
                # OUI is first 3 bytes (IEEE 802.1 is 00:80:c2)
                oui = tlv_value[0:3]
                subtype = tlv_value[3]
                # Subtype 1 under 00:80:c2 is Port VLAN ID
                if oui == b'\x00\x80\xc2' and subtype == 1:
                    vlan = int.from_bytes(tlv_value[4:6], byteorder='big')

        # Update if we parsed successfully
        if switch_name or port_id:
            self.info["switch_name"] = switch_name or self.info["switch_name"]
            self.info["port_id"] = port_id or self.info["port_id"]
            self.info["vlan"] = str(vlan) if vlan else self.info["vlan"]
            self.info["ip"] = mgmt_ip or self.info["ip"]
            self.info["model"] = model or self.info["model"]
            self.info["protocol"] = "LLDP"
            self.info["last_updated"] = time.time()

    def _parse_cdp(self, raw_bytes: bytes):
        """
        Manually parses raw Cisco Discovery Protocol bytes.
        """
        # Look for CDP header start. Standard Ethernet header = 14 bytes.
        # LLC header = 3 bytes. SNAP header = 5 bytes. Total offset = 22 bytes.
        # Let's verify we have at least 26 bytes and version is 1 or 2 (first byte of CDP)
        offset = 22
        if len(raw_bytes) < offset + 4:
            return
            
        cdp_version = raw_bytes[offset]
        if cdp_version not in [1, 2]:
            return
            
        # Parse fields starting from offset + 4 (skip version, ttl, checksum)
        idx = offset + 4
        switch_name = None
        port_id = None
        vlan = None
        mgmt_ip = None
        model = None

        while idx < len(raw_bytes) - 4:
            # TLV header is Type (2 bytes) and Length (2 bytes)
            tlv_type = int.from_bytes(raw_bytes[idx:idx+2], byteorder='big')
            tlv_len = int.from_bytes(raw_bytes[idx+2:idx+4], byteorder='big')
            
            if tlv_len < 4 or idx + tlv_len > len(raw_bytes):
                break
                
            tlv_value = raw_bytes[idx+4:idx+tlv_len]
            idx += tlv_len
            
            if tlv_type == 0x0001:  # Device ID (Switch name)
                switch_name = tlv_value.decode('utf-8', errors='ignore')
            elif tlv_type == 0x0002:  # Addresses
                # First 4 bytes are number of addresses
                num_addrs = int.from_bytes(tlv_value[0:4], byteorder='big')
                if num_addrs > 0 and len(tlv_value) >= 14:
                    # Each address entry starts with protocol type (1 byte), length (1 byte), etc.
                    # IPv4 address is usually located at offset 10 to 14 of the address block
                    # Let's parse it safely
                    protocol_type = tlv_value[4]
                    addr_len = tlv_value[9]
                    if addr_len == 4:
                        ip_bytes = tlv_value[10:14]
                        mgmt_ip = ".".join(str(b) for b in ip_bytes)
            elif tlv_type == 0x0003:  # Port ID
                port_id = tlv_value.decode('utf-8', errors='ignore')
            elif tlv_type == 0x0006:  # Platform
                model = tlv_value.decode('utf-8', errors='ignore')
            elif tlv_type == 0x000a:  # Native VLAN
                vlan = int.from_bytes(tlv_value[0:2], byteorder='big')

        # Update parsed info
        if switch_name or port_id:
            self.info["switch_name"] = switch_name or self.info["switch_name"]
            self.info["port_id"] = port_id or self.info["port_id"]
            self.info["vlan"] = str(vlan) if vlan else self.info["vlan"]
            self.info["ip"] = mgmt_ip or self.info["ip"]
            self.info["model"] = model or self.info["model"]
            self.info["protocol"] = "CDP"
            self.info["last_updated"] = time.time()
