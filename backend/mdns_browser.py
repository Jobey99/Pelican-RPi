from scapy.all import IP, UDP, DNS, DNSQR, send, sniff
import json
import os
import threading
import time
import socket

def browse_mdns_services(interface="eth0", timeout=2.0):
    """
    Sends active mDNS PTR queries for all AV services inside mdns_database.json,
    sniffs responses on port 5353, and returns a list of discovered AV nodes.
    """
    db_path = os.path.join(os.path.dirname(__file__), "mdns_database.json")
    if os.path.exists(db_path):
        try:
            with open(db_path, "r") as f:
                db = json.load(f)
        except Exception:
            db = {}
    else:
        db = {}

    discovered = {}
    lock = threading.Lock()

    def packet_callback(pkt):
        if pkt.haslayer(DNS) and pkt.haslayer(UDP) and pkt.haslayer(IP):
            dns = pkt[DNS]
            ip = pkt[IP].src
            port = pkt[UDP].sport
            
            # Check answer records
            if dns.ancount > 0:
                for idx in range(dns.ancount):
                    try:
                        ans = dns.an[idx]
                        if ans.type == 12: # PTR record type
                            rdata = ans.rdata.decode("utf-8", errors="ignore") if isinstance(ans.rdata, bytes) else str(ans.rdata)
                            rrname = ans.rrname.decode("utf-8", errors="ignore") if isinstance(ans.rrname, bytes) else str(ans.rrname)
                            
                            # Standardize trailing dots
                            rrname_clean = rrname.rstrip(".")
                            rdata_clean = rdata.rstrip(".")
                            
                            # Match against service strings in the DB
                            match_key = None
                            for key in db.keys():
                                if key in rrname_clean or key in rdata_clean:
                                    match_key = key
                                    break
                                    
                            if match_key:
                                service_info = db[match_key]
                                # Clean up user facing device friendly name
                                friendly_name = rdata_clean.split("." + match_key)[0] if "." + match_key in rdata_clean else rdata_clean
                                
                                # Ignore generic types as device names, try to make it look clean
                                if friendly_name.startswith("_"):
                                    friendly_name = friendly_name.lstrip("_")
                                
                                with lock:
                                    if friendly_name not in discovered:
                                        discovered[friendly_name] = {
                                            "name": friendly_name,
                                            "service": service_info["name"],
                                            "vendor": service_info["vendor"],
                                            "ip": ip,
                                            "port": port,
                                            "record": rrname_clean
                                        }
                    except Exception:
                        pass

    # Start passive sniffer to catch multicast responses
    sniff_thread = threading.Thread(
        target=lambda: sniff(
            iface=interface,
            filter="udp port 5353",
            prn=packet_callback,
            timeout=timeout,
            store=0
        )
    )
    sniff_thread.start()

    # Brief pause to let sniffer setup sockets
    time.sleep(0.15)

    # Broadcast queries for each database key
    for service_name in db.keys():
        try:
            pkt = IP(dst="224.0.0.251")/UDP(sport=5353, dport=5353)/DNS(rd=1, qd=DNSQR(qname=service_name, qtype="PTR"))
            send(pkt, iface=interface, verbose=False)
        except Exception:
            pass

    # Join sniffer thread
    sniff_thread.join()

    return list(discovered.values())
