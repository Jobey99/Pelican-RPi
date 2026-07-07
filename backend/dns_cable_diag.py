import os
import time
import socket

def audit_cable_link(interface: str):
    """
    Reads Linux sysfs parameters for the given interface to audit
    its physical link speed, duplex mode, and carrier status.
    """
    sys_path = f"/sys/class/net/{interface}"
    if not os.path.exists(sys_path):
        return {"success": False, "error": f"Interface {interface} not found on this system"}
        
    try:
        # 1. Read carrier (cable plugged status)
        carrier_file = os.path.join(sys_path, "carrier")
        carrier = 0
        if os.path.exists(carrier_file):
            with open(carrier_file, "r") as f:
                carrier = int(f.read().strip())
                
        if carrier == 0:
            return {
                "success": True,
                "link_active": False,
                "speed": "Down",
                "duplex": "Down",
                "message": "No Ethernet cable detected (Carrier down)."
            }
            
        # 2. Read Speed (Mbps)
        speed_file = os.path.join(sys_path, "speed")
        speed = "Unknown"
        if os.path.exists(speed_file):
            try:
                with open(speed_file, "r") as f:
                    speed_val = int(f.read().strip())
                    if speed_val >= 1000:
                        speed = f"{speed_val / 1000} Gbps"
                    else:
                        speed = f"{speed_val} Mbps"
            except IOError:
                speed = "Link negotiating"

        # 3. Read Duplex
        duplex_file = os.path.join(sys_path, "duplex")
        duplex = "Unknown"
        if os.path.exists(duplex_file):
            try:
                with open(duplex_file, "r") as f:
                    duplex = f.read().strip().upper()
            except IOError:
                pass

        # Flag warnings (e.g. 100M or Half Duplex is a sign of bad cable crimping)
        status_warning = False
        warning_msg = ""
        if isinstance(speed, str) and "100 Mbps" in speed:
            status_warning = True
            warning_msg = "Warning: Negotiated at 100 Mbps. Gigabit connection expected."
        elif "10 Mbps" in speed:
            status_warning = True
            warning_msg = "Warning: Negotiated at 10 Mbps. Cable is likely damaged or too long."
        if duplex == "HALF":
            status_warning = True
            warning_msg += " Duplex negotiated at HALF. Potential collision issue."

        return {
            "success": True,
            "link_active": True,
            "speed": speed,
            "duplex": duplex,
            "warning": status_warning,
            "warning_message": warning_msg or "Link is healthy (Gigabit Full Duplex)."
        }
    except Exception as e:
        return {"success": False, "error": str(e)}

def measure_dns_latency(target_domain: str = "google.com"):
    """
    Resolves target domain name and measures DNS lookup response latency in milliseconds.
    """
    start_time = time.time()
    try:
        # Force a fresh DNS lookup
        socket.gethostbyname(target_domain)
        latency = (time.time() - start_time) * 1000
        return {
            "success": True,
            "domain": target_domain,
            "latency_ms": round(latency, 2),
            "status": "Healthy" if latency < 150 else "Slow DNS Resolution"
        }
    except Exception as e:
        return {
            "success": False,
            "domain": target_domain,
            "latency_ms": -1,
            "error": f"DNS Resolution failed: {e}"
        }
