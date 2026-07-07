import uuid
import random
from scapy.all import Ether, IP, UDP, BOOTP, DHCP, srp, get_if_raw_hwaddr
# Import logging to suppress warnings if scapy complains
import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

def detect_dhcp_servers(interface: str, timeout: int = 3):
    """
    Broadcasts a DHCP Discover packet on the specified interface
    and listens for DHCP Offer replies. Returns a list of found DHCP servers.
    """
    try:
        # Get raw MAC address of the interface
        raw_mac = get_if_raw_hwaddr(interface)[1]
        mac_str = ":".join(f"{b:02x}" for b in raw_mac)
        
        # Transaction ID
        xid = random.randint(1, 0xFFFFFFFF)
        
        # Craft DHCP Discover Packet
        dhcp_discover = (
            Ether(src=mac_str, dst="ff:ff:ff:ff:ff:ff") /
            IP(src="0.0.0.0", dst="255.255.255.255") /
            UDP(sport=68, dport=67) /
            BOOTP(chaddr=raw_mac, xid=xid) /
            DHCP(options=[("message-type", "discover"), "end"])
        )
        
        # Send packets and record answers
        # Using srp with multi=True to receive answers from multiple servers
        ans, unans = srp(
            dhcp_discover,
            iface=interface,
            timeout=timeout,
            multi=True,
            verbose=False
        )
        
        servers = []
        seen_ips = set()
        
        for req, resp in ans:
            if resp.haslayer(DHCP) and resp.haslayer(BOOTP):
                server_ip = resp[IP].src
                if server_ip in seen_ips:
                    continue
                seen_ips.add(server_ip)
                
                # Parse DHCP options
                options = resp[DHCP].options
                subnet_mask = "Unknown"
                router = "Unknown"
                dns_servers = []
                lease_time = "Unknown"
                message_type = "offer"
                
                for opt in options:
                    if not isinstance(opt, tuple):
                        continue
                    key, val = opt[0], opt[1]
                    if key == "subnet_mask":
                        subnet_mask = val
                    elif key == "router":
                        router = val
                    elif key == "name_server":
                        # Could be single string or list of IPs
                        if isinstance(val, list):
                            dns_servers = val
                        else:
                            dns_servers = [val]
                    elif key == "lease_time":
                        lease_time = f"{val}s ({round(val/3600, 1)} hrs)"
                    elif key == "message-type":
                        # Val is integer: 2 is offer
                        if val == 2:
                            message_type = "offer"
                        elif val == 5:
                            message_type = "ack"
                
                servers.append({
                    "server_ip": server_ip,
                    "type": message_type,
                    "subnet_mask": subnet_mask,
                    "gateway": router,
                    "dns": dns_servers,
                    "lease_time": lease_time,
                    "mac": resp[Ether].src
                })
                
        return {"success": True, "servers": servers}
    except Exception as e:
        return {"success": False, "error": str(e)}
