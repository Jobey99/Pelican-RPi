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
    
    # Generate standalone print-ready HTML
    report_html = generate_commissioning_report(
        client_name=client,
        technician=tech,
        notes=notes,
        lldp_info=lldp_info,
        diag_info=diag_info,
        ping_status=ping_status,
        devices=devices,
        conflicts=conflicts
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

# --- STATIC FILES SERVING ---

frontend_path = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "frontend"))
if os.path.exists(frontend_path):
    app.mount("/", StaticFiles(directory=frontend_path, html=True), name="static")

if __name__ == "__main__":
    import uvicorn
    # In production, bind to all interfaces
    uvicorn.run("main:app", host="0.0.0.0", port=8000, reload=True)
