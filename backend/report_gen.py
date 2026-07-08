import time
import os

HTML_TEMPLATE = """<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>AV/IT Network Site Commissioning Report</title>
    <style>
        body {{
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            color: #333;
            background-color: #fff;
            margin: 0;
            padding: 40px;
            line-height: 1.6;
        }}
        .header-table {{
            width: 100%;
            border-collapse: collapse;
            margin-bottom: 30px;
        }}
        .header-table td {{
            padding: 10px;
            vertical-align: top;
        }}
        .logo-area {{
            font-size: 1.8rem;
            font-weight: 700;
            color: #007bff;
        }}
        .title-area {{
            text-align: right;
            font-size: 1.5rem;
            font-weight: 700;
            text-transform: uppercase;
        }}
        .meta-box {{
            background: #f8f9fa;
            border: 1px solid #dee2e6;
            border-radius: 6px;
            padding: 20px;
            margin-bottom: 30px;
            display: grid;
            grid-template-columns: 1fr 1fr;
            gap: 15px;
        }}
        .meta-item strong {{
            color: #495057;
        }}
        h2 {{
            border-bottom: 2px solid #007bff;
            padding-bottom: 6px;
            color: #007bff;
            font-size: 1.3rem;
            text-transform: uppercase;
            margin-top: 40px;
            margin-bottom: 20px;
        }}
        table.data-table {{
            width: 100%;
            border-collapse: collapse;
            margin-bottom: 20px;
            font-size: 0.9rem;
        }}
        table.data-table th {{
            background-color: #f1f3f5;
            color: #495057;
            text-align: left;
            padding: 10px;
            border-bottom: 2px solid #dee2e6;
            font-weight: 600;
        }}
        table.data-table td {{
            padding: 10px;
            border-bottom: 1px solid #dee2e6;
        }}
        table.data-table tr:nth-child(even) {{
            background-color: #f8f9fa;
        }}
        .badge {{
            padding: 4px 8px;
            border-radius: 4px;
            font-size: 0.8rem;
            font-weight: 600;
        }}
        .badge-success {{ background-color: #d4edda; color: #155724; }}
        .badge-danger {{ background-color: #f8d7da; color: #721c24; }}
        .badge-warning {{ background-color: #fff3cd; color: #856404; }}
        .badge-info {{ background-color: #d1ecf1; color: #0c5460; }}
        
        .sparkline {{
            display: flex;
            align-items: flex-end;
            gap: 2px;
            height: 40px;
            border-bottom: 1px solid #dee2e6;
            padding-bottom: 2px;
            margin-top: 10px;
        }}
        .sparkbar {{
            flex-grow: 1;
            min-width: 2px;
        }}
        .notes-area {{
            border: 1px solid #dee2e6;
            border-radius: 6px;
            padding: 20px;
            background: #fff;
            min-height: 100px;
            white-space: pre-wrap;
        }}
        .signature-row {{
            margin-top: 80px;
            display: grid;
            grid-template-columns: 1fr 1fr;
            gap: 80px;
        }}
        .signature-line {{
            border-top: 1px solid #333;
            margin-top: 50px;
            text-align: center;
            font-size: 0.85rem;
            color: #6c757d;
        }}
        @media print {{
            body {{
                padding: 0;
            }}
            .no-print {{
                display: none;
            }}
            h2 {{
                page-break-after: avoid;
            }}
            table {{
                page-break-inside: auto;
            }}
            tr {{
                page-break-inside: avoid;
                page-break-after: auto;
            }}
        }}
    </style>
</head>
<body>
    <table class="header-table">
        <tr>
            <td class="logo-area">
                ZAVI NETWORK REPORT
            </td>
            <td class="title-area">
                Site Commissioning Report
            </td>
        </tr>
    </table>

    <div class="meta-box">
        <div class="meta-item"><strong>Client / Project:</strong> {client_name}</div>
        <div class="meta-item"><strong>Date:</strong> {date_str}</div>
        <div class="meta-item"><strong>Lead Technician:</strong> {technician}</div>
        <div class="meta-item"><strong>Jump-Box Hostname:</strong> {hostname}</div>
    </div>

    <h2>Switch Port Connection (LLDP/CDP)</h2>
    <table class="data-table">
        <thead>
            <tr>
                <th>Connected Switch</th>
                <th>Switch Port ID</th>
                <th>VLAN</th>
                <th>Management IP</th>
                <th>Source Protocol</th>
            </tr>
        </thead>
        <tbody>
            <tr>
                <td>{lldp_switch}</td>
                <td>{lldp_port}</td>
                <td>{lldp_vlan}</td>
                <td>{lldp_ip}</td>
                <td>{lldp_proto}</td>
            </tr>
        </tbody>
    </table>

    <h2>Interface Diagnostics</h2>
    <table class="data-table">
        <thead>
            <tr>
                <th>Interface</th>
                <th>Logical IP / Subnet</th>
                <th>Physical Negotiation</th>
                <th>DNS Resolution Latency</th>
                <th>Link Status</th>
            </tr>
        </thead>
        <tbody>
            <tr>
                <td>{iface}</td>
                <td>{ip_cidr}</td>
                <td>{speed_duplex}</td>
                <td>{dns_latency}</td>
                <td>{link_warning_badge}</td>
            </tr>
        </tbody>
    </table>

    <h2>QoS Network Performance (Last 60 Pings)</h2>
    <table class="data-table" style="margin-bottom: 5px;">
        <thead>
            <tr>
                <th>Target Host</th>
                <th>Packets Sent</th>
                <th>Packets Lost</th>
                <th>Packet Loss %</th>
                <th>Average Latency</th>
            </tr>
        </thead>
        <tbody>
            <tr>
                <td>{ping_target}</td>
                <td>{ping_sent}</td>
                <td>{ping_lost}</td>
                <td>{ping_loss_pct}%</td>
                <td>{ping_avg} ms</td>
            </tr>
        </tbody>
    </table>
    <div style="font-size: 0.8rem; font-weight: 600; color: #6c757d; margin-top: 15px;">Ping Latency Trend:</div>
    <div class="sparkline">
        {sparkline_html}
    </div>

    <h2>Passive Network Discovered Devices ({device_count})</h2>
    <table class="data-table">
        <thead>
            <tr>
                <th>IP Address</th>
                <th>MAC Address</th>
                <th>Vendor / Manufacturer</th>
                <th>Last Active Protocol</th>
            </tr>
        </thead>
        <tbody>
            {discovered_devices_rows}
        </tbody>
    </table>

    <h2>Automated Site Commissioning Checklist</h2>
    <table class="data-table">
        <thead>
            <tr>
                <th>Verification Test</th>
                <th>Measured Parameter</th>
                <th>Acceptance Status</th>
            </tr>
        </thead>
        <tbody>
            <tr>
                <td><strong>IP Address Conflict Scan</strong></td>
                <td>{checklist_conflict_param}</td>
                <td>{checklist_conflict_status}</td>
            </tr>
            <tr>
                <td><strong>Physical Link Negotiation</strong></td>
                <td>{checklist_link_param}</td>
                <td>{checklist_link_status}</td>
            </tr>
            <tr>
                <td><strong>Local DNS Health Lookup</strong></td>
                <td>{checklist_dns_param}</td>
                <td>{checklist_dns_status}</td>
            </tr>
            <tr>
                <td><strong>QoS Ping Stability</strong></td>
                <td>{checklist_ping_param}</td>
                <td>{checklist_ping_status}</td>
            </tr>
            <tr>
                <td><strong>Switch Port Discovery (LLDP/CDP)</strong></td>
                <td>{checklist_lldp_param}</td>
                <td>{checklist_lldp_status}</td>
            </tr>
            <tr>
                <td><strong>DHCP Server Security Audit</strong></td>
                <td>{checklist_dhcp_param}</td>
                <td>{checklist_dhcp_status}</td>
            </tr>
        </tbody>
    </table>

    <h2>Commissioning Notes</h2>
    <div class="notes-area">
        {notes}
    </div>

    <div class="signature-row">
        <div>
            <div class="signature-line">Lead Installer Signature</div>
        </div>
        <div>
            <div class="signature-line">Client Sign-off Signature / Date</div>
        </div>
    </div>
</body>
</html>

"""

def generate_commissioning_report(client_name: str, technician: str, notes: str, 
                                  lldp_info: dict, diag_info: dict, ping_status: dict, 
                                  devices: list, conflicts: list = None, dhcp_info: dict = None, hostname: str = "RPi4-JumpBox") -> str:
    """
    Interpolates active diagnostic databases into a print-friendly commissioning report.
    """
    date_str = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime())
    
    if conflicts is None:
        conflicts = []

    # Calculate DHCP Server Checklist status
    dhcp_success = (dhcp_info or {}).get("success", False)
    dhcp_servers = (dhcp_info or {}).get("servers", [])
    if dhcp_success and len(dhcp_servers) > 0:
        server_ips = ", ".join([srv.get("server_ip", "") for srv in dhcp_servers])
        if len(dhcp_servers) == 1:
            checklist_dhcp_param = f"1 DHCP server active ({server_ips})"
            checklist_dhcp_status = '<span class="badge badge-success">PASS</span>'
        else:
            checklist_dhcp_param = f"Rogue DHCP conflict! ({len(dhcp_servers)} active: {server_ips})"
            checklist_dhcp_status = '<span class="badge badge-danger">FAIL (Rogue Server)</span>'
    else:
        checklist_dhcp_param = "No DHCP offers received. Subnet is likely static."
        checklist_dhcp_status = '<span class="badge badge-warning">WARN (Static Subnet)</span>'

    # Calculate Checklist fields
    # 1. IP Conflict
    checklist_conflict_param = f"{len(conflicts)} IP conflict(s) active"
    if len(conflicts) == 0:
        checklist_conflict_status = '<span class="badge badge-success">PASS</span>'
    else:
        checklist_conflict_status = '<span class="badge badge-danger">FAIL</span>'

    # LLDP details
    lldp_switch = lldp_info.get("switch_name", "Not Detected")
    lldp_port = lldp_info.get("port_id", "Not Detected")
    lldp_vlan = lldp_info.get("vlan", "Not Detected")
    lldp_ip = lldp_info.get("ip", "Not Detected")
    lldp_proto = lldp_info.get("protocol", "Not Detected")

    # 2. Switch Discovery
    if lldp_proto and lldp_proto != "Not Detected" and lldp_proto != "None" and lldp_proto != "Listening...":
        checklist_lldp_param = f"Switch: {lldp_switch} | Port: {lldp_port}"
        checklist_lldp_status = '<span class="badge badge-success">PASS</span>'
    else:
        checklist_lldp_param = "No switch LLDP/CDP packets detected"
        checklist_lldp_status = '<span class="badge badge-warning">BYPASS (No LLDP)</span>'

    # Diagnostics details
    iface = diag_info.get("interface", "eth0")
    cable = diag_info.get("cable", {})
    dns = diag_info.get("dns", {})
    
    speed_duplex = "Not Audited"
    if cable.get("success"):
        speed_duplex = f"{cable.get('speed')} / {cable.get('duplex')}"
        
    dns_latency = "Failed"
    if dns.get("success"):
        dns_latency = f"{dns.get('latency_ms')} ms"

    # 3. Physical Link
    if not cable.get("success"):
        checklist_link_param = "Physical link diagnostics not run"
        checklist_link_status = '<span class="badge badge-danger">FAIL (Not Audited)</span>'
    elif cable.get("warning"):
        checklist_link_param = f"Negotiated: {speed_duplex} ({cable.get('warning_message')})"
        checklist_link_status = '<span class="badge badge-warning">WARN</span>'
    else:
        checklist_link_param = f"Negotiated: {speed_duplex} (healthy)"
        checklist_link_status = '<span class="badge badge-success">PASS</span>'

    # 4. DNS health
    if dns.get("success"):
        checklist_dns_param = f"Resolved google.com in {dns_latency}"
        checklist_dns_status = '<span class="badge badge-success">PASS</span>'
    else:
        checklist_dns_param = "DNS resolution failed or timed out"
        checklist_dns_status = '<span class="badge badge-danger">FAIL</span>'

    # Link warning badge
    if not cable.get("success"):
        link_warning_badge = '<span class="badge badge-danger">Not Audited</span>'
    elif cable.get("warning"):
        link_warning_badge = f'<span class="badge badge-warning">Warning: {cable.get("warning_message")}</span>'
    else:
        link_warning_badge = '<span class="badge badge-success">Healthy (1Gbps Full)</span>'

    # QoS/Ping details
    ping_target = ping_status.get("target", "None")
    ping_sent = ping_status.get("sent", 0)
    ping_lost = ping_status.get("lost", 0)
    ping_loss_pct = ping_status.get("loss_percent", 0.0)
    ping_avg = ping_status.get("avg_rtt", 0.0)
    
    # 5. QoS Ping checklist status
    if ping_sent > 0:
        checklist_ping_param = f"{ping_loss_pct}% loss | Avg latency: {ping_avg} ms"
        if ping_loss_pct < 2:
            checklist_ping_status = '<span class="badge badge-success">PASS</span>'
        elif ping_loss_pct < 5:
            checklist_ping_status = '<span class="badge badge-warning">WARN</span>'
        else:
            checklist_ping_status = '<span class="badge badge-danger">FAIL</span>'
    else:
        checklist_ping_param = "Ping QoS logger was not running"
        checklist_ping_status = '<span class="badge badge-warning">BYPASS (Not Logged)</span>'

    # Render Sparkline
    sparkline_html = ""
    history = ping_status.get("history", [])
    if history:
        for rtt in history:
            height = 0
            color = "#6c757d"  # Grey/Drop
            if rtt is not None:
                height = min(40, max(3, int((rtt / 200) * 40)))
                if rtt < 50:
                    color = "#28a745"  # Green
                elif rtt < 150:
                    color = "#ffc107"  # Yellow
                else:
                    color = "#dc3545"  # Red
            else:
                height = 40
                color = "#dc3545"
            sparkline_html += f'<div class="sparkbar" style="height: {height}px; background-color: {color};"></div>'
    else:
        sparkline_html = '<div style="color: #6c757d; font-size: 0.85rem;">No QoS ping history logged.</div>'

    # Interface logical IP (from system)
    ip_cidr = "Unknown"
    try:
        import socket
        # Get active IP of interface
        import fcntl
        import struct
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        ip_cidr = socket.inet_ntoa(fcntl.ioctl(
            s.fileno(),
            0x8915,  # SIOCGIFADDR
            struct.pack('256s', iface[:15].encode('utf-8'))
        )[20:24])
    except Exception:
        pass

    # Discovered devices rows
    devices_rows = ""
    for dev in devices:
        devices_rows += f"""
        <tr>
            <td>{dev.get('ip', '')}</td>
            <td style="font-family: monospace;">{dev.get('mac', '')}</td>
            <td>{dev.get('vendor', 'Unknown Vendor')}</td>
            <td><span class="badge badge-info">{dev.get('protocol', 'Passive Sniff')}</span></td>
        </tr>
        """
    if not devices_rows:
        devices_rows = '<tr><td colspan="4" style="text-align: center; color: #6c757d;">No passive devices sniffed on link yet.</td></tr>'

    return HTML_TEMPLATE.format(
        client_name=client_name,
        date_str=date_str,
        technician=technician,
        hostname=hostname,
        lldp_switch=lldp_switch,
        lldp_port=lldp_port,
        lldp_vlan=lldp_vlan,
        lldp_ip=lldp_ip,
        lldp_proto=lldp_proto,
        iface=iface,
        ip_cidr=ip_cidr,
        speed_duplex=speed_duplex,
        dns_latency=dns_latency,
        link_warning_badge=link_warning_badge,
        ping_target=ping_target,
        ping_sent=ping_sent,
        ping_lost=ping_lost,
        ping_loss_pct=ping_loss_pct,
        ping_avg=ping_avg,
        sparkline_html=sparkline_html,
        device_count=len(devices),
        discovered_devices_rows=devices_rows,
        checklist_conflict_param=checklist_conflict_param,
        checklist_conflict_status=checklist_conflict_status,
        checklist_link_param=checklist_link_param,
        checklist_link_status=checklist_link_status,
        checklist_dns_param=checklist_dns_param,
        checklist_dns_status=checklist_dns_status,
        checklist_ping_param=checklist_ping_param,
        checklist_ping_status=checklist_ping_status,
        checklist_lldp_param=checklist_lldp_param,
        checklist_lldp_status=checklist_lldp_status,
        checklist_dhcp_param=checklist_dhcp_param,
        checklist_dhcp_status=checklist_dhcp_status,
        notes=notes
    )
