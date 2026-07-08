import socket
import uuid
import re
import urllib.request
import urllib.error

# ONVIF WS-Discovery SOAP Probe XML
WS_DISCOVERY_PROBE = """<?xml version="1.0" encoding="utf-8"?>
<Envelope xmlns:tds="http://www.onvif.org/ver10/device/wsdl" xmlns:dn="http://www.onvif.org/ver10/network/wsdl" xmlns="http://www.w3.org/2003/05/soap-envelope" xmlns:wsa="http://schemas.xmlsoap.org/ws/2004/08/addressing">
  <Header>
    <wsa:MessageID>uuid:{uuid}</wsa:MessageID>
    <wsa:To>urn:schemas-xmlsoap-org:ws:2005:04:discovery</wsa:To>
    <wsa:Action>http://schemas.xmlsoap.org/ws/2005/04/discovery/Probe</wsa:Action>
  </Header>
  <Body>
    <Probe xmlns="http://schemas.xmlsoap.org/ws/2005/04/discovery">
      <Types>dn:NetworkVideoTransmitter</Types>
    </Probe>
  </Body>
</Envelope>
"""

COMMON_CREDS = [
    ("admin", "admin"),
    ("admin", "12345"),
    ("admin", "123456"),
    ("admin", "password"),
    ("admin", "camera123")
]

def scan_onvif_cameras(interface_ip: str, timeout: float = 3.0):
    """
    Sends an ONVIF WS-Discovery UDP multicast probe to find IP cameras on the link.
    Probes discovered cameras for default password vulnerabilities.
    """
    cameras = []
    seen_ips = set()
    
    try:
        # Create UDP socket
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
        sock.settimeout(timeout)
        
        # Set socket option to bind to specific interface IP (optional but good)
        if interface_ip and interface_ip != "0.0.0.0":
            try:
                sock.bind((interface_ip, 0))
            except Exception:
                pass
                
        # Send Multicast SOAP probe to 239.255.255.250:3702
        probe_xml = WS_DISCOVERY_PROBE.format(uuid=str(uuid.uuid4()))
        sock.sendto(probe_xml.encode('utf-8'), ('239.255.255.255', 3702))
        
        # Collect replies
        start_time = time.time()
        while time.time() - start_time < timeout:
            try:
                data, addr = sock.recvfrom(4096)
                ip = addr[0]
                if ip in seen_ips:
                    continue
                seen_ips.add(ip)
                
                # Parse XML payload for endpoints (XAddrs)
                xml_str = data.decode('utf-8', errors='ignore')
                xaddr_match = re.search(r'<[a-zA-Z0-9:]*XAddrs>([^<]+)</[a-zA-Z0-9:]*XAddrs>', xml_str)
                onvif_url = xaddr_match.group(1).strip() if xaddr_match else f"http://{ip}/onvif/device_service"
                
                # Double check url starts with http
                if not onvif_url.startswith("http"):
                    onvif_url = f"http://{ip}/onvif/device_service"
                
                # Extract manufacturer details if available
                scopes_match = re.search(r'<[a-zA-Z0-9:]*Scopes>([^<]+)</[a-zA-Z0-9:]*Scopes>', xml_str)
                vendor = "Unknown IP Camera"
                if scopes_match:
                    scopes = scopes_match.group(1)
                    # ONVIF scopes contain hardware names (e.g. onvif://www.onvif.org/name/Hikvision)
                    name_match = re.search(r'name/([^/\s]+)', scopes)
                    if name_match:
                        vendor = name_match.group(1).replace("_", " ")

                cameras.append({
                    "ip": ip,
                    "onvif_url": onvif_url,
                    "vendor": vendor,
                    "credentials": "Checking...",
                    "rtsp_url": f"rtsp://{ip}:554/live"
                })
            except socket.timeout:
                break
            except Exception:
                pass
        sock.close()
        
        # Probe discovered cameras for credential security status
        for cam in cameras:
            cam["credentials"] = _check_credentials(cam["ip"])
            
        return {"success": True, "cameras": cameras}
    except Exception as e:
        return {"success": False, "error": str(e)}

def _check_credentials(ip: str):
    """
    Tries basic HTTP auth on common camera endpoint ports (80, 8080)
    to verify if default passwords are active.
    """
    # Probe common camera ports
    ports = [80, 8080]
    for port in ports:
        # Check standard ONVIF or admin endpoints
        url = f"http://{ip}:{port}/"
        for user, pwd in COMMON_CREDS:
            try:
                # Use basic auth request handler
                password_mgr = urllib.request.HTTPPasswordMgrWithDefaultRealm()
                password_mgr.add_password(None, url, user, pwd)
                handler = urllib.request.HTTPBasicAuthHandler(password_mgr)
                opener = urllib.request.build_opener(handler)
                
                # Test connection (timeout 1s)
                req = opener.open(url, timeout=1.0)
                if req.getcode() == 200:
                    return f"Vulnerable! Default credentials: {user} / {pwd}"
            except urllib.error.HTTPError as e:
                # If it's a 401 Unauthorized, credentials failed.
                # If 404 or other, endpoint might be closed, continue.
                if e.code == 401:
                    continue
            except Exception:
                pass
                
    return "Secure (No default credentials found)"

import time
