import os
import asyncio
from fastapi import FastAPI, WebSocket, WebSocketDisconnect, HTTPException
from fastapi.responses import FileResponse, HTMLResponse
from fastapi.staticfiles import StaticFiles
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from typing import List, Optional

# Import custom modules
from network_manager import get_interfaces, set_interface_ip_runtime, set_interface_dhcp_runtime, arp_scan
from sniffer import PassiveSniffer
from serial_bridge import SerialBridge
from dhcp_diag import detect_dhcp_servers
from iperf_control import get_iperf_status, start_iperf_server, stop_iperf_server
from av_control import send_wol_packet, send_pjlink_command
from lldp_cdp import LldpCdpParser
from ip_conflict import IpConflictDetector
from dhcp_server import LocalDhcpServer
from dns_cable_diag import audit_cable_link, measure_dns_latency
from ping_logger import PingMonitor
from multicast_sniff import MulticastAuditor
from camera_inspect import scan_onvif_cameras
from report_gen import generate_commissioning_report

app = FastAPI(title="RPi AV/IT Network Powerhouse API")

# Enable CORS for development
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Instantiate background services
sniffer = PassiveSniffer()
serial_bridge = SerialBridge()
lldp_parser = LldpCdpParser()
conflict_detector = IpConflictDetector()
dhcp_server = LocalDhcpServer()
ping_monitor = PingMonitor()
multicast_auditor = MulticastAuditor()

# Pydantic models for request bodies
class InterfaceConfig(BaseModel):
    interface: str
    mode: str  # "static" or "dhcp"
    ip_cidr: Optional[str] = None

class SnifferControl(BaseModel):
    interface: str
    active: bool

class ArpScanRequest(BaseModel):
    interface: str
    subnet: str

class PortProbeRequest(BaseModel):
    ip: str
    ports: List[int]

class SerialConnectRequest(BaseModel):
    port: str
    baudrate: int

class SerialBridgeRequest(BaseModel):
    active: bool
    port: int = 23

class DhcpTestRequest(BaseModel):
    interface: str

class IperfControlRequest(BaseModel):
    active: bool

class WolRequest(BaseModel):
    mac: str

class PjLinkRequest(BaseModel):
    ip: str
    command: str
    password: Optional[str] = None

class DhcpServerControlRequest(BaseModel):
    active: bool
    interface: str

class DiagnosticRequest(BaseModel):
    interface: str

class StealthRequest(BaseModel):
    interface: str
    active: bool

class PingMonitorRequest(BaseModel):
    target: str
    interface: str
    active: bool

class PingTestRequest(BaseModel):
    target: str
    count: int = 8
    interface: str

class BeaconRequest(BaseModel):
    active: bool


# --- API ROUTES ---

@app.get("/api/interfaces")
def get_all_interfaces():
    return get_interfaces()

@app.post("/api/interfaces/configure")
def configure_interface(config: InterfaceConfig):
    if config.mode == "static":
        if not config.ip_cidr:
            raise HTTPException(status_code=400, detail="ip_cidr is required for static mode")
        result = set_interface_ip_runtime(config.interface, config.ip_cidr)
    else:
        result = set_interface_dhcp_runtime(config.interface)
        
    if not result["success"]:
        raise HTTPException(status_code=500, detail=result.get("error", "Failed to configure interface"))
    return result

@app.get("/api/sniffer/devices")
def get_sniffer_devices():
    return {
        "active": sniffer.running,
        "interface": sniffer.interface,
        "devices": sniffer.get_results()
    }

@app.get("/api/sniffer/subnets")
def get_sniffer_subnet_guesses():
    return sniffer.get_subnet_guesses()

@app.post("/api/sniffer/control")
def control_sniffer(config: SnifferControl):
    if config.active:
        sniffer.start(config.interface)
        return {"message": f"Sniffer started on {config.interface}"}
    else:
        sniffer.stop()
        return {"message": "Sniffer stopped"}

@app.post("/api/scan/arp")
def trigger_arp_scan(req: ArpScanRequest):
    result = arp_scan(req.interface, req.subnet)
    if not result["success"]:
        raise HTTPException(status_code=500, detail=result.get("error", "ARP scan failed"))
    return result

@app.post("/api/scan/ports")
async def trigger_port_probe(req: PortProbeRequest):
    results = []
    # Async socket connections to scan ports concurrently
    async def probe_port(port: int):
        try:
            # Create a socket connection with 1-second timeout
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(req.ip, port),
                timeout=1.0
            )
            writer.close()
            await writer.wait_closed()
            results.append({"port": port, "status": "open"})
        except Exception:
            results.append({"port": port, "status": "closed"})

    await asyncio.gather(*(probe_port(p) for p in req.ports))
    return {"ip": req.ip, "results": sorted(results, key=lambda x: x["port"])}

@app.get("/api/serial/ports")
def get_serial_ports():
    return serial_bridge.list_ports()

@app.post("/api/serial/connect")
def connect_serial(req: SerialConnectRequest):
    res = serial_bridge.connect(req.port, req.baudrate)
    if not res["success"]:
        raise HTTPException(status_code=500, detail=res["error"])
    return res

@app.post("/api/serial/disconnect")
def disconnect_serial():
    return serial_bridge.disconnect()

@app.post("/api/serial/bridge")
def configure_tcp_bridge(req: SerialBridgeRequest):
    if req.active:
        res = serial_bridge.start_tcp_bridge(req.port)
    else:
        res = serial_bridge.stop_tcp_bridge()
        
    if not res["success"]:
        raise HTTPException(status_code=500, detail=res.get("error", "TCP bridge error"))
    return res

@app.get("/api/serial/status")
def get_serial_status():
    return {
        "connected": serial_bridge.ser is not None and serial_bridge.ser.is_open,
        "port": serial_bridge.serial_port,
        "baudrate": serial_bridge.baudrate,
        "tcp_bridge_active": serial_bridge.tcp_server_socket is not None,
        "tcp_bridge_port": serial_bridge.tcp_port
    }

@app.post("/api/dhcp/test")
def trigger_dhcp_test(req: DhcpTestRequest):
    res = detect_dhcp_servers(req.interface)
    if not res["success"]:
        raise HTTPException(status_code=500, detail=res.get("error", "DHCP test failed"))
    return res

@app.get("/api/iperf/status")
def get_iperf_server_status():
    return get_iperf_status()

@app.post("/api/iperf/control")
def control_iperf_server(req: IperfControlRequest):
    if req.active:
        res = start_iperf_server()
    else:
        res = stop_iperf_server()
    if not res["success"]:
        raise HTTPException(status_code=500, detail=res.get("error", "iPerf3 control failed"))
    return res

@app.post("/api/control/pjlink")
def control_projector_pjlink(req: PjLinkRequest):
    res = send_pjlink_command(req.ip, req.command, req.password)
    if not res["success"]:
        raise HTTPException(status_code=500, detail=res.get("error", "PJLink transmission failed"))
    return res

@app.post("/api/control/wol")
def trigger_wake_on_lan(req: WolRequest):
    res = send_wol_packet(req.mac)
    if not res["success"]:
        raise HTTPException(status_code=500, detail=res.get("error", "Wake-on-LAN failed"))
    return res

# --- STARTUP / SHUTDOWN LIFECYCLE ---

@app.on_event("startup")
def startup_event():
    # Automatically start LLDP parser, IP Conflict sniffer, and Multicast auditor on eth0 by default
    lldp_parser.start("eth0")
    conflict_detector.start("eth0")
    multicast_auditor.start("eth0")

@app.on_event("shutdown")
def shutdown_event():
    lldp_parser.stop()
    conflict_detector.stop()
    dhcp_server.stop()
    sniffer.stop()
    ping_monitor.stop()
    multicast_auditor.stop()

# --- PHASE 2 DIAGNOSTICS ROUTES ---

@app.get("/api/network/lldp")
def get_lldp_info():
    return lldp_parser.get_info()

@app.get("/api/network/conflicts")
def get_ip_conflicts():
    return conflict_detector.get_conflicts()

@app.post("/api/network/conflicts/clear")
def clear_ip_conflicts():
    conflict_detector.clear_conflicts()
    return {"message": "IP conflicts cleared"}

@app.get("/api/dhcp/server/status")
def get_dhcp_server_status():
    return dhcp_server.get_status()

@app.post("/api/dhcp/server/control")
def control_dhcp_server(req: DhcpServerControlRequest):
    if req.active:
        res = dhcp_server.start(req.interface)
    else:
        res = dhcp_server.stop()
    if not res["success"]:
        raise HTTPException(status_code=500, detail=res["error"])
    return res

@app.post("/api/network/diagnostics")
def run_cable_and_dns_diagnostics(req: DiagnosticRequest):
    cable_res = audit_cable_link(req.interface)
    dns_res = measure_dns_latency()
    return {
        "interface": req.interface,
        "cable": cable_res,
        "dns": dns_res
    }

@app.post("/api/network/stealth")
def toggle_stealth_mode(req: StealthRequest):
    try:
        import subprocess
        if req.active:
            # Stealth mode ON: flush IP addresses from the interface
            # The interface remains UP and Scapy can still sniff packets,
            # but the RPi does not reply to ARP or IP traffic.
            subprocess.run(["sudo", "ip", "addr", "flush", "dev", req.interface], check=True)
            return {"success": True, "message": f"Stealth mode enabled on {req.interface} (Interface IPs flushed)"}
        else:
            # Stealth mode OFF: re-trigger DHCP client
            if subprocess.run(["which", "nmcli"], stdout=subprocess.DEVNULL).returncode == 0:
                subprocess.run(["sudo", "nmcli", "device", "reapply", req.interface], check=False)
            else:
                subprocess.run(["sudo", "dhclient", req.interface], check=False)
            return {"success": True, "message": f"Stealth mode disabled on {req.interface} (IP assignment restored)"}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/api/ping/monitor/status")
def get_ping_monitor_status():
    return ping_monitor.get_status()

@app.post("/api/ping/monitor/configure")
def configure_ping_monitor(req: PingMonitorRequest):
    if req.active:
        ping_monitor.start(req.target, req.interface)
        return {"success": True, "message": f"Ping monitor started on target {req.target}"}
    else:
        ping_monitor.stop()
        return {"success": True, "message": "Ping monitor stopped"}

@app.post("/api/ping/test")
def run_active_ping_test(req: PingTestRequest):
    import subprocess
    import platform
    import re

    # Formulate ping command based on OS
    system_os = platform.system().lower()
    if system_os == "windows":
        cmd = ["ping", "-n", str(req.count), "-w", "1000", req.target]
    else:
        # Linux: bind to interface if provided
        cmd = ["ping", "-c", str(req.count), "-W", "1"]
        if req.interface and req.interface.strip():
            cmd.extend(["-I", req.interface])
        cmd.append(req.target)

    try:
        res = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=12)
        stdout = res.stdout or ""
        
        loss_pct = 100.0
        avg_rtt = 0.0
        sent = req.count
        lost = req.count

        if system_os == "windows":
            # Match lost count
            loss_match = re.search(r"Lost = (\d+) \((\d+)% loss\)", stdout)
            if loss_match:
                lost = int(loss_match.group(1))
                loss_pct = float(loss_match.group(2))
            # Match average RTT
            rtt_match = re.search(r"Average = (\d+)ms", stdout)
            if rtt_match:
                avg_rtt = float(rtt_match.group(1))
        else:
            # Linux packet loss
            loss_match = re.search(r"(\d+)% packet loss", stdout)
            if loss_match:
                loss_pct = float(loss_match.group(1))
            # Linux received packets
            rx_match = re.search(r"(\d+) received", stdout)
            if rx_match:
                rx = int(rx_match.group(1))
                lost = max(0, sent - rx)
            # Linux RTT
            rtt_match = re.search(r"min/avg/max/(?:mdev|stddev) = [\d\.]+/([\d\.]+)/", stdout)
            if rtt_match:
                avg_rtt = float(rtt_match.group(1))

        return {
            "success": True,
            "target": req.target,
            "sent": sent,
            "lost": lost,
            "loss_percent": loss_pct,
            "avg_rtt": round(avg_rtt, 2),
            "output_snippet": stdout[-200:].strip()
        }
    except subprocess.TimeoutExpired:
        return {
            "success": False,
            "error": "Ping test timed out",
            "sent": req.count,
            "lost": req.count,
            "loss_percent": 100.0,
            "avg_rtt": 0.0
        }
    except Exception as e:
        return {
            "success": False,
            "error": str(e),
            "sent": req.count,
            "lost": req.count,
            "loss_percent": 100.0,
            "avg_rtt": 0.0
        }

@app.get("/api/ping/monitor/download")
def download_ping_log():
    if os.path.exists(ping_monitor.log_file):
        return FileResponse(
            path=ping_monitor.log_file,
            filename="ping_diagnostics.csv",
            media_type="text/csv"
        )
    raise HTTPException(status_code=404, detail="Ping diagnostics log file not found.")

# --- PHASE 4 COMMERCIAL DIAGNOSTICS ---

@app.get("/api/network/multicast")
def get_multicast_streams():
    return multicast_auditor.get_status()

@app.post("/api/network/cameras")
def run_camera_security_scan(req: DiagnosticRequest):
    # Grab the active IP address of the interface to bind socket correctly
    import socket
    iface_ip = "0.0.0.0"
    try:
        import fcntl
        import struct
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        iface_ip = socket.inet_ntoa(fcntl.ioctl(
            s.fileno(),
            0x8915,  # SIOCGIFADDR
            struct.pack('256s', req.interface[:15].encode('utf-8'))
        )[20:24])
    except Exception:
        pass
    return scan_onvif_cameras(iface_ip)

@app.get("/api/network/report/download")
def download_site_commission_report(client: str = "Default Project", tech: str = "Field Engineer", notes: str = ""):
    # Gather all telemetry databases
    lldp_info = lldp_parser.get_info()
    
    # Run a quick cable / DNS diagnostics call synchronously
    cable_res = audit_cable_link("eth0")
    dns_res = measure_dns_latency()
    diag_info = {
        "interface": "eth0",
        "cable": cable_res,
        "dns": dns_res
    }
    
    ping_status = ping_monitor.get_status()
    devices = sniffer.get_results()
    conflicts = conflict_detector.get_conflicts()
    dhcp_info = detect_dhcp_servers("eth0")
    
    # Generate standalone print-ready HTML
    report_html = generate_commissioning_report(
        client_name=client,
        technician=tech,
        notes=notes,
        lldp_info=lldp_info,
        diag_info=diag_info,
        ping_status=ping_status,
        devices=devices,
        conflicts=conflicts,
        dhcp_info=dhcp_info
    )
    
    return HTMLResponse(
        content=report_html,
        headers={"Content-Disposition": "attachment; filename=site_commissioning_report.html"}
    )

# --- WEBSOCKET FOR RS232 TERMINAL ---

@app.websocket("/ws/terminal")
async def websocket_endpoint(websocket: WebSocket):
    await websocket.accept()
    serial_bridge.register_websocket(websocket)
    try:
        while True:
            # Listen to text sent by the browser client
            data = await websocket.receive_text()
            # Forward straight to serial
            serial_bridge.write(data.encode("utf-8", errors="ignore"))
    except WebSocketDisconnect:
        pass
    finally:
        serial_bridge.unregister_websocket(websocket)

# --- SPECIALIZED AV FIELD SUITE ROUTES ---

@app.get("/api/network/wan_health")
def get_wan_health():
    import socket
    import time
    import platform
    import subprocess
    
    # 1. DNS check (Port 53 google.com lookup)
    dns_success = False
    dns_time = 0.0
    start = time.time()
    try:
        socket.gethostbyname("google.com")
        dns_time = round((time.time() - start) * 1000, 2)
        dns_success = True
    except Exception:
        pass

    # 2. HTTP/HTTPS Web access check (Port 443 socket connect to www.google.com)
    https_success = False
    https_time = 0.0
    start = time.time()
    try:
        s = socket.create_connection(("www.google.com", 443), timeout=2.0)
        s.close()
        https_time = round((time.time() - start) * 1000, 2)
        https_success = True
    except Exception:
        pass

    # 3. NTP Time check (Port 123 socket connect check to pool.ntp.org)
    ntp_success = False
    ntp_time = 0.0
    start = time.time()
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.settimeout(2.0)
        msg = b'\x1b' + 47 * b'\0'
        s.sendto(msg, ("pool.ntp.org", 123))
        data, server = s.recvfrom(1024)
        ntp_time = round((time.time() - start) * 1000, 2)
        ntp_success = True
        s.close()
    except Exception:
        pass

    # 4. Gateway Ping
    gateway_ip = "192.168.0.1"
    try:
        if platform.system().lower() != "windows":
            out = subprocess.check_output("ip route show | grep default", shell=True, text=True)
            parts = out.split()
            if "via" in parts:
                gateway_ip = parts[parts.index("via") + 1]
    except Exception:
        pass

    gateway_ping_success = False
    gateway_ping_time = 0.0
    system_os = platform.system().lower()
    ping_cmd = ["ping", "-n", "1", "-w", "1000", gateway_ip] if system_os == "windows" else ["ping", "-c", "1", "-W", "1", gateway_ip]
    try:
        start = time.time()
        res = subprocess.run(ping_cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=2.0)
        if res.returncode == 0:
            gateway_ping_time = round((time.time() - start) * 1000, 2)
            gateway_ping_success = True
    except Exception:
        pass

    # 5. WAN Ping (1.1.1.1)
    wan_ping_success = False
    wan_ping_time = 0.0
    wan_ping_cmd = ["ping", "-n", "1", "-w", "1000", "1.1.1.1"] if system_os == "windows" else ["ping", "-c", "1", "-W", "1", "1.1.1.1"]
    try:
        start = time.time()
        res = subprocess.run(wan_ping_cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=2.0)
        if res.returncode == 0:
            wan_ping_time = round((time.time() - start) * 1000, 2)
            wan_ping_success = True
    except Exception:
        pass

    return {
        "dns": {"success": dns_success, "latency_ms": dns_time},
        "https": {"success": https_success, "latency_ms": https_time},
        "ntp": {"success": ntp_success, "latency_ms": ntp_time},
        "gateway_ping": {"success": gateway_ping_success, "target_ip": gateway_ip, "latency_ms": gateway_ping_time},
        "wan_ping": {"success": wan_ping_success, "latency_ms": wan_ping_time}
    }

beacon_active = False

@app.post("/api/hardware/beacon")
def toggle_hardware_beacon(req: BeaconRequest):
    global beacon_active
    import platform
    import subprocess
    
    beacon_active = req.active
    system_os = platform.system().lower()
    
    if system_os == "windows":
        return {"success": True, "beacon_active": beacon_active, "message": f"Simulated beacon state: {beacon_active}"}
        
    try:
        if beacon_active:
            subprocess.run("echo timer > /sys/class/leds/eth0:green/trigger", shell=True)
            subprocess.run("echo 100 > /sys/class/leds/eth0:green/delay_on", shell=True)
            subprocess.run("echo 100 > /sys/class/leds/eth0:green/delay_off", shell=True)
            if os.path.exists("/sys/class/leds/eth0:amber/trigger"):
                subprocess.run("echo timer > /sys/class/leds/eth0:amber/trigger", shell=True)
                subprocess.run("echo 100 > /sys/class/leds/eth0:amber/delay_on", shell=True)
                subprocess.run("echo 100 > /sys/class/leds/eth0:amber/delay_off", shell=True)
        else:
            subprocess.run("echo netdev > /sys/class/leds/eth0:green/trigger", shell=True)
            subprocess.run("echo eth0 > /sys/class/leds/eth0:green/device_name", shell=True)
            subprocess.run("echo link tx rx > /sys/class/leds/eth0:green/link", shell=True)
            if os.path.exists("/sys/class/leds/eth0:amber/trigger"):
                subprocess.run("echo netdev > /sys/class/leds/eth0:amber/trigger", shell=True)
                subprocess.run("echo eth0 > /sys/class/leds/eth0:amber/device_name", shell=True)
                subprocess.run("echo link tx rx > /sys/class/leds/eth0:amber/link", shell=True)
                
        return {"success": True, "beacon_active": beacon_active, "message": f"Hardware beacon active state: {beacon_active}"}
    except Exception as e:
        return {"success": False, "error": str(e)}

@app.get("/api/network/health")
def get_av_network_health():
    score = 100
    alerts = []

    # 1. IP Conflict check
    conflicts = conflict_detector.get_conflicts()
    if conflicts:
        score -= 35
        for c in conflicts:
            alerts.append(f"❌ IP Conflict Active: IP {c.get('ip')} is bound to two separate MAC addresses!")

    # 2. Rogue DHCP Server check
    dhcp_res = detect_dhcp_servers("eth0", timeout=1)
    if dhcp_res.get("success"):
        servers = dhcp_res.get("servers", [])
        if len(servers) > 1:
            score -= 30
            server_ips = ", ".join([s.get("server_ip") for s in servers])
            alerts.append(f"❌ Rogue DHCP Conflict: {len(servers)} DHCP servers active ({server_ips})!")

    # 3. IGMP Multicast Flooding check
    multicast_status = multicast_auditor.get_status()
    if multicast_status.get("flooding_detected"):
        score -= 20
        alerts.append("⚠️ IGMP Flooding Detected: Multicast stream packets are flooding this port! (Enable IGMP Snooping & Querier on the switch).")

    # 4. Interface speed/duplex negotiation warning
    cable_res = audit_cable_link("eth0")
    if cable_res.get("success") and cable_res.get("warning"):
        score -= 15
        alerts.append(f"⚠️ Link Negotiation Issue: {cable_res.get('warning_message')}")

    # 5. DNS health resolution
    dns_res = measure_dns_latency()
    if not dns_res.get("success"):
        score -= 15
        alerts.append("❌ Local DNS Resolution Failed: Gateway DNS is unreachable or queries are failing.")
    elif dns_res.get("latency_ms") > 150:
        score -= 10
        alerts.append(f"⚠️ Slow DNS Lookup: Resolve time is slow ({dns_res.get('latency_ms')} ms). Check DNS WAN configurations.")

    score = max(0, score)

    return {
        "score": score,
        "alerts": alerts,
        "status": "Excellent" if score >= 90 else "Good" if score >= 75 else "Fair" if score >= 50 else "Poor"
    }

# --- STATIC FILES SERVING ---

frontend_path = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "frontend"))
if os.path.exists(frontend_path):
    app.mount("/", StaticFiles(directory=frontend_path, html=True), name="static")

if __name__ == "__main__":
    import uvicorn
    # In production, bind to all interfaces
    uvicorn.run("main:app", host="0.0.0.0", port=8000, reload=True)
