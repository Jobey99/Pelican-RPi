const API_BASE = ""; // Same host
let activeTab = "dashboard-tab";
let devicePollInterval = null;
let interfacePollInterval = null;
let wsConn = null;

document.addEventListener("DOMContentLoaded", () => {
    initTabNavigation();
    initSnifferControls();
    initNetworkManager();
    initActiveProbes();
    initSerialControls();
    initDhcpAndIperf();
    initAvControls();
    initPhase2Features();
    initPhase3Features();
    initPhase4Features();
    initSpecializedAVSuite();
    initResponsiveAndHelp();
    
    // Initial fetch of configuration details
    fetchInterfaces();
    fetchSerialStatus();
    fetchIperfStatus();
    fetchLldpInfo();
    fetchConflicts();
    fetchDhcpServerStatus();
    fetchPingStatus();
    fetchMulticastStatus();
    
    // Poll active interface listings periodically
    interfacePollInterval = setInterval(fetchInterfaces, 5000);
    setInterval(fetchLldpInfo, 5000);
    setInterval(fetchConflicts, 3000);
    setInterval(fetchDhcpServerStatus, 5000);
    setInterval(fetchPingStatus, 1000);
    setInterval(fetchMulticastStatus, 3000);
});

// --- TAB NAVIGATION ---
function initTabNavigation() {
    const navButtons = document.querySelectorAll(".nav-btn");
    const tabs = document.querySelectorAll(".tab-content");
    const tabTitle = document.getElementById("tab-title");

    navButtons.forEach(btn => {
        btn.addEventListener("click", () => {
            const target = btn.getAttribute("data-tab");
            
            navButtons.forEach(b => b.classList.remove("active"));
            tabs.forEach(t => t.classList.remove("active"));
            
            btn.classList.add("active");
            document.getElementById(target).classList.add("active");
            activeTab = target;
            
            // Set dynamic titles
            switch(target) {
                case "dashboard-tab":
                    tabTitle.innerText = "Passive Network Auto-Discoverer";
                    break;
                case "active-tab":
                    tabTitle.innerText = "Active Diagnostics & Port Sweeps";
                    break;
                case "serial-tab":
                    tabTitle.innerText = "USB-to-Serial Console & Network Bridge";
                    break;
                case "network-tab":
                    tabTitle.innerText = "Linux Interface Configuration";
                    break;
            }
        });
    });
}

// --- MODULE 1: PASSIVE DISCOVERY ---
function initSnifferControls() {
    const toggleBtn = document.getElementById("toggle-sniffer-btn");
    const interfaceSelect = document.getElementById("sniffer-interface-select");
    const clearBtn = document.getElementById("clear-sniffer-btn");
    const statusIndicator = document.getElementById("sniffer-status-indicator");

    // Fetch initial status
    fetch(API_BASE + "/api/sniffer/devices")
        .then(r => r.json())
        .then(data => {
            if (data.active) {
                setSnifferUIActive(true, data.interface);
                startDevicePolling();
            }
        });

    toggleBtn.addEventListener("click", () => {
        const isRunning = toggleBtn.classList.contains("btn-danger");
        const selectedIface = interfaceSelect.value;

        fetch(API_BASE + "/api/sniffer/control", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ interface: selectedIface, active: !isRunning })
        })
        .then(r => r.json())
        .then(() => {
            setSnifferUIActive(!isRunning, selectedIface);
            if (!isRunning) {
                startDevicePolling();
            } else {
                stopDevicePolling();
            }
        })
        .catch(err => alert("Error toggling sniffer: " + err));
    });

    clearBtn.addEventListener("click", () => {
        // Just empty the DOM list - the daemon stores them, so to clear them from
        // the server we toggle off/on or we clear client-side for viewability.
        document.getElementById("devices-table-body").innerHTML = `
            <tr><td colspan="6" class="text-center">Cleared. Sniffer will discover new devices on activity...</td></tr>
        `;
    });
}

function setSnifferUIActive(active, interfaceName) {
    const toggleBtn = document.getElementById("toggle-sniffer-btn");
    const statusIndicator = document.getElementById("sniffer-status-indicator");
    const interfaceSelect = document.getElementById("sniffer-interface-select");

    if (active) {
        toggleBtn.innerText = "Stop Sniffing";
        toggleBtn.className = "btn btn-danger";
        statusIndicator.innerText = "Active (" + interfaceName + ")";
        statusIndicator.className = "badge badge-on";
        interfaceSelect.disabled = true;
    } else {
        toggleBtn.innerText = "Start Sniffing";
        toggleBtn.className = "btn btn-primary";
        statusIndicator.innerText = "Off";
        statusIndicator.className = "badge badge-off";
        interfaceSelect.disabled = false;
    }
}

function startDevicePolling() {
    if (devicePollInterval) clearInterval(devicePollInterval);
    pollDevices();
    devicePollInterval = setInterval(pollDevices, 2000);
}

function stopDevicePolling() {
    if (devicePollInterval) {
        clearInterval(devicePollInterval);
        devicePollInterval = null;
    }
}

function pollDevices() {
    fetch(API_BASE + "/api/sniffer/devices")
        .then(r => r.json())
        .then(data => {
            renderDevices(data.devices);
        });

    fetch(API_BASE + "/api/sniffer/subnets")
        .then(r => r.json())
        .then(subnets => {
            renderSubnetGuesses(subnets);
        });
}

function renderDevices(devices) {
    const tbody = document.getElementById("devices-table-body");
    if (!devices || devices.length === 0) {
        tbody.innerHTML = `<tr><td colspan="6" class="text-center">Waiting for passive network traffic...</td></tr>`;
        return;
    }

    tbody.innerHTML = devices.map(dev => `
        <tr>
            <td class="font-mono">${dev.ip}</td>
            <td class="font-mono">${dev.mac}</td>
            <td><strong>${dev.vendor}</strong></td>
            <td>${dev.hostname}</td>
            <td>${dev.protocols.map(p => `<span class="badge badge-on">${p}</span>`).join(" ")}</td>
            <td class="text-muted font-mono">${dev.last_seen}</td>
        </tr>
    `).join("");
}

function renderSubnetGuesses(subnets) {
    const container = document.getElementById("subnet-guesses-container");
    if (!subnets || subnets.length === 0) {
        container.innerHTML = `<div class="no-subnets-msg">No subnets detected yet. Start sniffing and plug into a live network!</div>`;
        return;
    }

    container.innerHTML = subnets.map(sub => `
        <div class="subnet-guess-box" onclick="prefillArpScan('${sub.subnet}')">
            <h4>${sub.subnet}</h4>
            <span>Found ${sub.devices_count} device(s) here</span>
        </div>
    `).join("");
}

function prefillArpScan(subnet) {
    document.getElementById("arp-subnet-input").value = subnet;
    // Switch to active tab automatically
    document.querySelector('[data-tab="active-tab"]').click();
}

// --- MODULE 2: ACTIVE PROBES ---
function initActiveProbes() {
    const scanBtn = document.getElementById("run-arp-scan-btn");
    const subnetInput = document.getElementById("arp-subnet-input");
    const scanBody = document.getElementById("arp-scan-body");

    scanBtn.addEventListener("click", () => {
        const subnet = subnetInput.value.trim();
        if (!subnet) {
            alert("Please enter a valid subnet CIDR");
            return;
        }

        const iface = document.getElementById("sniffer-interface-select").value;
        scanBody.innerHTML = `<tr><td colspan="3" class="text-center">Scanning subnet... please wait.</td></tr>`;
        scanBtn.disabled = true;

        fetch(API_BASE + "/api/scan/arp", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ interface: iface, subnet: subnet })
        })
        .then(r => r.json())
        .then(data => {
            scanBtn.disabled = false;
            if (data.hosts && data.hosts.length > 0) {
                scanBody.innerHTML = data.hosts.map(host => `
                    <tr class="clickable-row" onclick="setProbeTarget('${host.ip}')">
                        <td class="font-mono">${host.ip}</td>
                        <td class="font-mono">${host.mac}</td>
                        <td><span class="badge badge-on">Active</span></td>
                    </tr>
                `).join("");
            } else {
                scanBody.innerHTML = `<tr><td colspan="3" class="text-center">No active hosts replied to ARP.</td></tr>`;
            }
        })
        .catch(err => {
            scanBtn.disabled = false;
            scanBody.innerHTML = `<tr><td colspan="3" class="text-center text-danger">Error: ${err}</td></tr>`;
        });
    });

    // Port probe trigger
    const probeBtn = document.getElementById("run-port-probe-btn");
    probeBtn.addEventListener("click", () => {
        const targetIp = document.getElementById("probe-target-ip").value.trim();
        if (!targetIp) {
            alert("Please specify a target IP address");
            return;
        }

        const ports = [80, 443, 23, 22, 41794, 5900, 49152, 8080];
        
        // Reset chip views to 'Scanning...'
        document.querySelectorAll(".port-status-box").forEach(box => {
            box.className = "port-status-box";
            box.querySelector(".p-status").innerText = "Scanning...";
        });

        probeBtn.disabled = true;
        
        fetch(API_BASE + "/api/scan/ports", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ ip: targetIp, ports: ports })
        })
        .then(r => r.json())
        .then(data => {
            probeBtn.disabled = false;
            data.results.forEach(res => {
                const box = document.querySelector(`.port-status-box[data-port="${res.port}"]`);
                if (box) {
                    if (res.status === "open") {
                        box.classList.add("open");
                        box.querySelector(".p-status").innerText = "OPEN";
                    } else {
                        box.classList.add("closed");
                        box.querySelector(".p-status").innerText = "CLOSED";
                    }
                }
            });
        })
        .catch(err => {
            probeBtn.disabled = false;
            alert("Port scan failed: " + err);
        });
    });
}

function setProbeTarget(ip) {
    document.getElementById("probe-target-ip").value = ip;
}

// --- MODULE 3: USB SERIAL BRIDGE ---
function initSerialControls() {
    const portSelect = document.getElementById("serial-port-select");
    const baudSelect = document.getElementById("serial-baud-select");
    const connectBtn = document.getElementById("connect-serial-btn");
    const disconnectBtn = document.getElementById("disconnect-serial-btn");
    const sendBtn = document.getElementById("send-console-btn");
    const consoleInput = document.getElementById("console-input");
    const clearBtn = document.getElementById("clear-console-btn");
    const toggleBridgeBtn = document.getElementById("toggle-bridge-btn");
    const bridgePortInput = document.getElementById("bridge-tcp-port");

    // Populate serial ports list
    refreshSerialPorts();

    connectBtn.addEventListener("click", () => {
        const port = portSelect.value;
        const baud = parseInt(baudSelect.value);
        if (!port) {
            alert("No serial port selected");
            return;
        }

        fetch(API_BASE + "/api/serial/connect", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ port: port, baudrate: baud })
        })
        .then(r => r.json())
        .then(() => {
            connectBtn.classList.add("hidden");
            disconnectBtn.classList.remove("hidden");
            consoleInput.disabled = false;
            sendBtn.disabled = false;
            
            // Open WebSocket for Console
            openSerialWebSocket();
            appendConsoleLine("System: Connected to " + port + " at " + baud + " baud.", "system-line");
        })
        .catch(err => alert("Serial connection failed: " + err));
    });

    disconnectBtn.addEventListener("click", () => {
        fetch(API_BASE + "/api/serial/disconnect", { method: "POST" })
            .then(r => r.json())
            .then(() => {
                disconnectBtn.classList.add("hidden");
                connectBtn.classList.remove("hidden");
                consoleInput.disabled = true;
                sendBtn.disabled = true;
                
                closeSerialWebSocket();
                appendConsoleLine("System: Disconnected serial port.", "system-line");
            });
    });

    sendBtn.addEventListener("click", sendSerialCommand);
    consoleInput.addEventListener("keydown", (e) => {
        if (e.key === "Enter") sendSerialCommand();
    });

    clearBtn.addEventListener("click", () => {
        document.getElementById("console-output").innerHTML = "";
    });

    // TCP Bridge Controls
    toggleBridgeBtn.addEventListener("click", () => {
        const isCurrentlyActive = toggleBridgeBtn.classList.contains("btn-danger");
        const port = parseInt(bridgePortInput.value);

        fetch(API_BASE + "/api/serial/bridge", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ active: !isCurrentlyActive, port: port })
        })
        .then(r => r.json())
        .then(() => {
            fetchSerialStatus();
        })
        .catch(err => alert("Bridge modification failed: " + err));
    });
}

function refreshSerialPorts() {
    const portSelect = document.getElementById("serial-port-select");
    fetch(API_BASE + "/api/serial/ports")
        .then(r => r.json())
        .then(ports => {
            if (ports && ports.length > 0) {
                portSelect.innerHTML = ports.map(p => `
                    <option value="${p.device}">${p.device} (${p.description})</option>
                `).join("");
            } else {
                portSelect.innerHTML = `<option value="">No USB serial ports detected</option>`;
            }
        });
}

function fetchSerialStatus() {
    fetch(API_BASE + "/api/serial/status")
        .then(r => r.json())
        .then(data => {
            const toggleBridgeBtn = document.getElementById("toggle-bridge-btn");
            const bridgeStatusText = document.getElementById("bridge-status-text");

            if (data.tcp_bridge_active) {
                toggleBridgeBtn.innerText = "Disable TCP Bridge";
                toggleBridgeBtn.className = "btn btn-danger";
                bridgeStatusText.innerText = `Bridge active: Listening on TCP Port ${data.tcp_bridge_port}`;
                bridgeStatusText.className = "status-msg text-success";
            } else {
                toggleBridgeBtn.innerText = "Enable TCP Bridge";
                toggleBridgeBtn.className = "btn btn-secondary";
                bridgeStatusText.innerText = "Bridge status: Deactivated";
                bridgeStatusText.className = "status-msg text-muted";
            }
        });
}

function openSerialWebSocket() {
    const loc = window.location;
    const wsProto = loc.protocol === "https:" ? "wss:" : "ws:";
    const wsUrl = `${wsProto}//${loc.host}/ws/terminal`;
    
    wsConn = new WebSocket(wsUrl);
    wsConn.onmessage = (event) => {
        appendConsoleLine(event.data);
    };
    wsConn.onclose = () => {
        appendConsoleLine("System: Console terminal WebSocket disconnected.", "system-line");
    };
}

function closeSerialWebSocket() {
    if (wsConn) {
        wsConn.close();
        wsConn = null;
    }
}

function sendSerialCommand() {
    const inputField = document.getElementById("console-input");
    let cmd = inputField.value;
    if (!cmd) return;

    const cr = document.getElementById("console-append-cr").checked;
    const lf = document.getElementById("console-append-lf").checked;
    const isHex = document.getElementById("console-hex-mode").checked;

    appendConsoleLine(cmd, "tx-line");
    inputField.value = "";

    if (wsConn && wsConn.readyState === WebSocket.OPEN) {
        if (isHex) {
            // Hex parsing logic: e.g. "02 03 41 5A" -> hex bytes
            // A simple hex transmitter
            let bytes = cmd.split(" ").map(h => parseInt(h, 16));
            let binary = new Uint8Array(bytes);
            wsConn.send(binary);
        } else {
            if (cr) cmd += "\r";
            if (lf) cmd += "\n";
            wsConn.send(cmd);
        }
    }
}

function appendConsoleLine(text, className = "") {
    const consoleBox = document.getElementById("console-output");
    const div = document.createElement("div");
    div.className = "console-line " + className;
    div.innerText = text;
    consoleBox.appendChild(div);
    consoleBox.scrollTop = consoleBox.scrollHeight;
}

// --- MODULE 4: INTERFACE MANAGER ---
function initNetworkManager() {
    const closeModalBtn = document.getElementById("close-modal-btn");
    const applyBtn = document.getElementById("apply-network-btn");
    const ipModeSelect = document.getElementById("modal-ip-mode");
    const staticFields = document.getElementById("modal-static-fields");

    closeModalBtn.addEventListener("click", () => {
        document.getElementById("config-modal").classList.add("hidden");
    });

    ipModeSelect.addEventListener("change", () => {
        if (ipModeSelect.value === "static") {
            staticFields.classList.remove("hidden");
        } else {
            staticFields.classList.add("hidden");
        }
    });

    applyBtn.addEventListener("click", () => {
        const interfaceName = document.getElementById("modal-interface-name").innerText;
        const mode = ipModeSelect.value;
        const ipCidr = document.getElementById("modal-static-ip").value.trim();

        if (mode === "static" && !ipCidr) {
            alert("Please enter a valid IP address with CIDR (e.g. 192.168.1.99/24)");
            return;
        }

        applyBtn.disabled = true;
        applyBtn.innerText = "Applying...";

        fetch(API_BASE + "/api/interfaces/configure", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ interface: interfaceName, mode: mode, ip_cidr: ipCidr })
        })
        .then(r => r.json())
        .then(() => {
            alert("Network configured successfully!");
            document.getElementById("config-modal").classList.add("hidden");
            fetchInterfaces();
        })
        .catch(err => alert("Configuration failed: " + err))
        .finally(() => {
            applyBtn.disabled = false;
            applyBtn.innerText = "Apply Settings";
        });
    });
}

function fetchInterfaces() {
    fetch(API_BASE + "/api/interfaces")
        .then(r => r.json())
        .then(data => {
            renderInterfaces(data);
            
            // Populate sniffer interface choices
            const select = document.getElementById("sniffer-interface-select");
            const currentSelection = select.value;
            select.innerHTML = Object.keys(data).map(ifaceName => `
                <option value="${ifaceName}">${ifaceName} (${data[ifaceName].ip || "No IP"})</option>
            `).join("");
            if (data[currentSelection]) {
                select.value = currentSelection;
            }

            // Display active primary host IP in the sidebar status area
            const primaryIface = Object.values(data).find(iface => iface.ip && iface.name !== "lo");
            document.getElementById("host-ip-display").innerText = primaryIface ? primaryIface.ip : "Disconnected";
        });
}

function renderInterfaces(interfaces) {
    const tbody = document.getElementById("interfaces-table-body");
    tbody.innerHTML = Object.values(interfaces).map(iface => `
        <tr>
            <td><strong>${iface.name}</strong></td>
            <td>
                <span class="badge ${iface.status === 'up' ? 'badge-on' : 'badge-off'}">
                    ${iface.status.toUpperCase()}
                </span>
            </td>
            <td class="font-mono">${iface.ip || "No Assignment"}</td>
            <td class="font-mono text-muted">${iface.mac}</td>
            <td>
                <button class="btn btn-secondary btn-sm" onclick="openConfigModal('${iface.name}')">
                    Configure
                </button>
            </td>
        </tr>
    `).join("");
}

function openConfigModal(interfaceName) {
    document.getElementById("modal-interface-name").innerText = interfaceName;
    document.getElementById("modal-static-ip").value = "";
    document.getElementById("modal-ip-mode").value = "dhcp";
    document.getElementById("modal-static-fields").classList.add("hidden");
    document.getElementById("config-modal").classList.remove("hidden");
}

// --- DHCP & IPERF3 MODULE ---
function initDhcpAndIperf() {
    const dhcpBtn = document.getElementById("run-dhcp-test-btn");
    const dhcpBody = document.getElementById("dhcp-test-body");
    const toggleIperfBtn = document.getElementById("toggle-iperf-btn");

    dhcpBtn.addEventListener("click", () => {
        const iface = document.getElementById("sniffer-interface-select").value;
        dhcpBtn.disabled = true;
        dhcpBtn.innerText = "Scanning DHCP...";
        dhcpBody.innerHTML = `<tr><td colspan="5" class="text-center">Sending DHCP discover packets...</td></tr>`;

        fetch(API_BASE + "/api/dhcp/test", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ interface: iface })
        })
        .then(r => r.json())
        .then(data => {
            dhcpBtn.disabled = false;
            dhcpBtn.innerText = "Scan DHCP Servers";
            if (data.servers && data.servers.length > 0) {
                dhcpBody.innerHTML = data.servers.map(srv => `
                    <tr>
                        <td class="font-mono"><strong>${srv.server_ip}</strong></td>
                        <td class="font-mono">${srv.subnet_mask}</td>
                        <td class="font-mono">${srv.gateway}</td>
                        <td>${srv.dns.join(", ")}</td>
                        <td class="font-mono">${srv.lease_time}</td>
                    </tr>
                `).join("");
            } else {
                dhcpBody.innerHTML = `<tr><td colspan="5" class="text-center text-warning">No DHCP offers received. Subnet is likely fully static.</td></tr>`;
            }
        })
        .catch(err => {
            dhcpBtn.disabled = false;
            dhcpBtn.innerText = "Scan DHCP Servers";
            dhcpBody.innerHTML = `<tr><td colspan="5" class="text-center text-danger">Error: ${err}</td></tr>`;
        });
    });

    toggleIperfBtn.addEventListener("click", () => {
        const isCurrentlyRunning = toggleIperfBtn.classList.contains("btn-danger");
        toggleIperfBtn.disabled = true;

        fetch(API_BASE + "/api/iperf/control", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ active: !isCurrentlyRunning })
        })
        .then(r => r.json())
        .then(() => {
            fetchIperfStatus();
        })
        .catch(err => alert("iPerf3 control failed: " + err))
        .finally(() => {
            toggleIperfBtn.disabled = false;
        });
    });
}

function fetchIperfStatus() {
    fetch(API_BASE + "/api/iperf/status")
        .then(r => r.json())
        .then(data => {
            const toggleIperfBtn = document.getElementById("toggle-iperf-btn");
            const iperfStatusText = document.getElementById("iperf-status-text");

            if (data.running) {
                toggleIperfBtn.innerText = "Disable iPerf3 Server";
                toggleIperfBtn.className = "btn btn-danger";
                iperfStatusText.innerText = `Server active: Listening for bandwidth tests on Port ${data.port}`;
                iperfStatusText.className = "status-msg text-success";
            } else {
                toggleIperfBtn.innerText = "Enable iPerf3 Server";
                toggleIperfBtn.className = "btn btn-secondary";
                iperfStatusText.innerText = "Server status: Deactivated";
                iperfStatusText.className = "status-msg text-muted";
            }
        });
}

// --- AV CONTROLS ---
function initAvControls() {
    const sendPjlinkBtn = document.getElementById("send-pjlink-btn");
    const pjlinkOutput = document.getElementById("pjlink-output");
    
    sendPjlinkBtn.addEventListener("click", () => {
        const ip = document.getElementById("pjlink-ip").value.trim();
        const cmd = document.getElementById("pjlink-cmd-select").value;
        const pwd = document.getElementById("pjlink-password").value;

        if (!ip) {
            alert("Please enter target projector IP");
            return;
        }

        sendPjlinkBtn.disabled = true;
        pjlinkOutput.innerHTML = `<div class="console-line system-line">Connecting to projector and sending command...</div>`;

        fetch(API_BASE + "/api/control/pjlink", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ ip: ip, command: cmd, password: pwd || null })
        })
        .then(r => r.json())
        .then(data => {
            sendPjlinkBtn.disabled = false;
            pjlinkOutput.innerHTML = `
                <div class="console-line text-success">> Command Sent: ${cmd}</div>
                <div class="console-line system-line">Projector Banner: ${data.greeting}</div>
                <div class="console-line">Response: ${data.response}</div>
            `;
        })
        .catch(err => {
            sendPjlinkBtn.disabled = false;
            pjlinkOutput.innerHTML = `<div class="console-line text-danger">> Error: ${err}</div>`;
        });
    });

    const sendWolBtn = document.getElementById("send-wol-btn");
    const wolOutput = document.getElementById("wol-output");

    sendWolBtn.addEventListener("click", () => {
        const mac = document.getElementById("wol-mac").value.trim();
        if (!mac) {
            alert("Please enter target MAC address");
            return;
        }

        sendWolBtn.disabled = true;
        wolOutput.className = "status-msg text-muted";
        wolOutput.innerText = "Sending magic packet...";

        fetch(API_BASE + "/api/control/wol", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ mac: mac })
        })
        .then(r => r.json())
        .then(data => {
            sendWolBtn.disabled = false;
            wolOutput.className = "status-msg text-success";
            wolOutput.innerText = data.message;
        })
        .catch(err => {
            sendWolBtn.disabled = false;
            wolOutput.className = "status-msg text-danger";
            wolOutput.innerText = "Error: " + err;
        });
    });
}

// --- PHASE 2 ULTIMATE FLUKE SUITE ---

function initPhase2Features() {
    const clearConflictsBtn = document.getElementById("clear-conflicts-btn");
    const toggleDhcpServerBtn = document.getElementById("toggle-dhcp-server-btn");
    const runLinkAuditBtn = document.getElementById("run-link-audit-btn");

    clearConflictsBtn.addEventListener("click", () => {
        fetch(API_BASE + "/api/network/conflicts/clear", { method: "POST" })
            .then(r => r.json())
            .then(() => {
                document.getElementById("ip-conflict-alert").classList.add("hidden");
            });
    });

    toggleDhcpServerBtn.addEventListener("click", () => {
        const isCurrentlyActive = toggleDhcpServerBtn.classList.contains("btn-danger");
        const selectedIface = document.getElementById("sniffer-interface-select").value;
        toggleDhcpServerBtn.disabled = true;

        fetch(API_BASE + "/api/dhcp/server/control", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ active: !isCurrentlyActive, interface: selectedIface })
        })
        .then(r => r.json())
        .then(() => {
            fetchDhcpServerStatus();
        })
        .catch(err => alert("DHCP Server control failed: " + err))
        .finally(() => {
            toggleDhcpServerBtn.disabled = false;
        });
    });

    runLinkAuditBtn.addEventListener("click", () => {
        const selectedIface = document.getElementById("sniffer-interface-select").value;
        runLinkAuditBtn.disabled = true;
        runLinkAuditBtn.innerText = "Auditing Link...";

        document.getElementById("diag-link-speed").innerText = "Testing...";
        document.getElementById("diag-dns-time").innerText = "Testing...";
        const warningBox = document.getElementById("diag-link-warning");
        warningBox.innerText = "Running interface diagnostics...";
        warningBox.className = "status-msg margin-top-sm text-muted";

        fetch(API_BASE + "/api/network/diagnostics", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ interface: selectedIface })
        })
        .then(r => r.json())
        .then(data => {
            // Speed / Duplex
            const cable = data.cable;
            if (cable.success) {
                document.getElementById("diag-link-speed").innerText = `${cable.speed} / ${cable.duplex}`;
                if (cable.warning) {
                    warningBox.innerText = cable.warning_message;
                    warningBox.className = "status-msg margin-top-sm text-danger";
                } else {
                    warningBox.innerText = cable.warning_message;
                    warningBox.className = "status-msg margin-top-sm text-success";
                }
            } else {
                document.getElementById("diag-link-speed").innerText = "Error";
                warningBox.innerText = "Link Audit Error: " + cable.error;
                warningBox.className = "status-msg margin-top-sm text-danger";
            }

            // DNS
            const dns = data.dns;
            if (dns.success) {
                document.getElementById("diag-dns-time").innerText = `${dns.latency_ms} ms`;
            } else {
                document.getElementById("diag-dns-time").innerText = "Failed";
            }
        })
        .catch(err => {
            alert("Diagnostics failed: " + err);
        })
        .finally(() => {
            runLinkAuditBtn.disabled = false;
            runLinkAuditBtn.innerText = "Run Diagnostics";
        });
    });
}

function fetchLldpInfo() {
    fetch(API_BASE + "/api/network/lldp")
        .then(r => r.json())
        .then(data => {
            document.getElementById("lldp-switch-name").innerText = data.switch_name;
            document.getElementById("lldp-port-id").innerText = data.port_id;
            document.getElementById("lldp-vlan").innerText = data.vlan;
            document.getElementById("lldp-ip").innerText = data.ip;
            document.getElementById("lldp-proto").innerText = data.protocol;
            document.getElementById("lldp-model").innerText = data.model || "";
        });
}

function fetchConflicts() {
    fetch(API_BASE + "/api/network/conflicts")
        .then(r => r.json())
        .then(conflicts => {
            const alertBanner = document.getElementById("ip-conflict-alert");
            const detailsBox = document.getElementById("ip-conflict-details");

            if (conflicts && conflicts.length > 0) {
                alertBanner.classList.remove("hidden");
                detailsBox.innerHTML = conflicts.map(conf => `
                    <div>• Conflict on IP <strong>${conf.ip}</strong>: MAC <strong>${conf.mac_a}</strong> is fighting MAC <strong>${conf.mac_b}</strong> (Detected: ${conf.time})</div>
                `).join("");
            } else {
                alertBanner.classList.add("hidden");
            }
        });
}

function fetchDhcpServerStatus() {
    fetch(API_BASE + "/api/dhcp/server/status")
        .then(r => r.json())
        .then(data => {
            const toggleDhcpServerBtn = document.getElementById("toggle-dhcp-server-btn");
            const dhcpServerStatusText = document.getElementById("dhcp-server-status-text");

            if (data.active) {
                toggleDhcpServerBtn.innerText = "Disable DHCP Server";
                toggleDhcpServerBtn.className = "btn btn-danger";
                let msg = `Server active on 192.168.99.1. `;
                if (data.leased) {
                    msg += `<strong class="text-success">Active lease given to MAC: ${data.client_mac}</strong>`;
                } else {
                    msg += `<span class="text-warning">Listening for client requests...</span>`;
                }
                dhcpServerStatusText.innerHTML = msg;
                dhcpServerStatusText.className = "status-msg text-success";
            } else {
                toggleDhcpServerBtn.innerText = "Enable DHCP Server";
                toggleDhcpServerBtn.className = "btn btn-secondary";
                dhcpServerStatusText.innerText = "Server status: Deactivated";
                dhcpServerStatusText.className = "status-msg text-muted";
            }
        });
}

// --- PHASE 3 ADVANCED FEATURES ---

function initPhase3Features() {
    const stealthBtn = document.getElementById("toggle-stealth-btn");
    const pingBtn = document.getElementById("toggle-ping-monitor-btn");

    stealthBtn.addEventListener("click", () => {
        const isStealthActive = stealthBtn.classList.contains("btn-danger");
        const selectedIface = document.getElementById("sniffer-interface-select").value;
        stealthBtn.disabled = true;

        fetch(API_BASE + "/api/network/stealth", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ interface: selectedIface, active: !isStealthActive })
        })
        .then(r => r.json())
        .then(() => {
            if (!isStealthActive) {
                stealthBtn.innerText = "Stealth: On";
                stealthBtn.className = "btn btn-danger";
                // Trigger sniffer start in passive mode automatically
                document.getElementById("toggle-sniffer-btn").click();
            } else {
                stealthBtn.innerText = "Stealth: Off";
                stealthBtn.className = "btn btn-secondary";
            }
            fetchInterfaces();
        })
        .catch(err => alert("Stealth mode change failed: " + err))
        .finally(() => {
            stealthBtn.disabled = false;
        });
    });

    pingBtn.addEventListener("click", () => {
        const isRunning = pingBtn.classList.contains("btn-danger");
        const target = document.getElementById("ping-monitor-target").value.trim();
        const selectedIface = document.getElementById("sniffer-interface-select").value;

        if (!target && !isRunning) {
            alert("Please specify a target IP/host to ping");
            return;
        }

        pingBtn.disabled = true;

        fetch(API_BASE + "/api/ping/monitor/configure", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ target: target, interface: selectedIface, active: !isRunning })
        })
        .then(r => r.json())
        .then(() => {
            fetchPingStatus();
        })
        .catch(err => alert("Ping monitor control failed: " + err))
        .finally(() => {
            pingBtn.disabled = false;
        });
    });
}

function fetchPingStatus() {
    fetch(API_BASE + "/api/ping/monitor/status")
        .then(r => r.json())
        .then(data => {
            const pingBtn = document.getElementById("toggle-ping-monitor-btn");
            const sentEl = document.getElementById("ping-stat-sent");
            const lostEl = document.getElementById("ping-stat-lost");
            const lossPctEl = document.getElementById("ping-stat-loss-pct");
            const avgEl = document.getElementById("ping-stat-avg");
            const sparkline = document.getElementById("ping-sparkline");

            if (data.active) {
                pingBtn.innerText = "Stop Logging";
                pingBtn.className = "btn btn-danger";
                document.getElementById("ping-monitor-target").disabled = true;
            } else {
                pingBtn.innerText = "Start Logging";
                pingBtn.className = "btn btn-primary";
                document.getElementById("ping-monitor-target").disabled = false;
            }

            // Stats
            sentEl.innerText = data.sent;
            lostEl.innerText = data.lost;
            lossPctEl.innerText = data.loss_percent + "%";
            avgEl.innerText = data.avg_rtt + " ms";

            // Color coding loss ratio
            if (data.loss_percent > 10) {
                lossPctEl.style.color = "var(--danger)";
            } else if (data.loss_percent > 2) {
                lossPctEl.style.color = "var(--warning)";
            } else {
                lossPctEl.style.color = "var(--success)";
            }

            // Render live QoS Sparkline
            if (data.history && data.history.length > 0) {
                sparkline.innerHTML = data.history.map(rtt => {
                    let height = 0;
                    let color = "rgba(255,255,255,0.1)"; // packet drop / grey
                    
                    if (rtt !== null) {
                        // Max RTT scale is 200ms
                        height = Math.min(60, Math.max(5, (rtt / 200) * 60));
                        if (rtt < 50) {
                            color = "var(--success)";
                        } else if (rtt < 150) {
                            color = "var(--warning)";
                        } else {
                            color = "var(--danger)";
                        }
                    } else {
                        height = 60; // full height for drops
                        color = "var(--danger)";
                    }
                    
                    return `<div style="flex-grow: 1; min-width: 3px; max-width: 8px; height: ${height}px; background-color: ${color}; border-radius: 2px 2px 0 0;"></div>`;
                }).join("");
            } else {
                sparkline.innerHTML = `<div style="color: var(--text-muted); font-size: 0.8rem; text-align: center; width: 100%;">Monitor inactive. Click Start Logging to render graph.</div>`;
            }
        });
}

// --- PHASE 4 COMMERCIAL-GRADE SUITE ---

function initPhase4Features() {
    const refreshTopologyBtn = document.getElementById("refresh-topology-btn");
    const runCameraScanBtn = document.getElementById("run-camera-scan-btn");
    const generateReportBtn = document.getElementById("generate-report-btn");

    if (refreshTopologyBtn) {
        refreshTopologyBtn.addEventListener("click", () => {
            drawTopology();
        });
    }

    if (runCameraScanBtn) {
        runCameraScanBtn.addEventListener("click", () => {
            const selectedIface = document.getElementById("sniffer-interface-select").value;
            const tableBody = document.getElementById("camera-table-body");
            runCameraScanBtn.disabled = true;
            runCameraScanBtn.innerText = "Scanning CCTV Network...";
            tableBody.innerHTML = `<tr><td colspan="5" class="text-center"><span class="pulse-dot"></span> Searching for ONVIF devices and testing default credentials...</td></tr>`;

            fetch(API_BASE + "/api/network/cameras", {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify({ interface: selectedIface })
            })
            .then(r => r.json())
            .then(data => {
                if (data.success && data.cameras.length > 0) {
                    tableBody.innerHTML = data.cameras.map(cam => {
                        const isVulnerable = cam.credentials.includes("Vulnerable");
                        const statusClass = isVulnerable ? "text-danger" : "text-success";
                        return `
                            <tr>
                                <td><strong>${cam.ip}</strong></td>
                                <td>${cam.vendor}</td>
                                <td><a href="${cam.onvif_url}" target="_blank" style="color: var(--accent); text-decoration: underline; font-size: 0.82rem;">Endpoint Link</a></td>
                                <td class="${statusClass}"><strong>${cam.credentials}</strong></td>
                                <td><span style="font-family: var(--font-mono); font-size: 0.82rem; color: var(--text-secondary);">${cam.rtsp_url}</span></td>
                            </tr>
                        `;
                    }).join("");
                } else {
                    tableBody.innerHTML = `<tr><td colspan="5" class="text-center text-muted">No ONVIF IP Cameras discovered on this segment.</td></tr>`;
                }
            })
            .catch(err => {
                tableBody.innerHTML = `<tr><td colspan="5" class="text-center text-danger">Scan failed: ${err}</td></tr>`;
            })
            .finally(() => {
                runCameraScanBtn.disabled = false;
                runCameraScanBtn.innerText = "Scan & Audit Cameras";
            });
        });
    }

    if (generateReportBtn) {
        generateReportBtn.addEventListener("click", () => {
            const client = encodeURIComponent(document.getElementById("report-client-name").value.trim() || "Default Project");
            const tech = encodeURIComponent(document.getElementById("report-tech-name").value.trim() || "Field Engineer");
            const notes = encodeURIComponent(document.getElementById("report-notes").value.trim() || "");

            // Navigate to file download URL directly
            window.location.href = `${API_BASE}/api/network/report/download?client=${client}&tech=${tech}&notes=${notes}`;
        });
    }

    const runSweepBtn = document.getElementById("run-verification-sweep-btn");
    if (runSweepBtn) {
        runSweepBtn.addEventListener("click", () => {
            const testArea = document.getElementById("report-test-area");
            const progressBar = document.getElementById("verification-progress-bar");
            const progressPct = document.getElementById("verification-progress-pct");
            const statusText = document.getElementById("verification-status-text");
            const resultsBox = document.getElementById("verification-checklist-results");
            const selectedIface = document.getElementById("sniffer-interface-select").value;

            runSweepBtn.disabled = true;
            generateReportBtn.disabled = true;
            testArea.classList.remove("hidden");
            resultsBox.classList.add("hidden");
            resultsBox.innerHTML = "";

            const updateProgress = (percentage, text) => {
                progressBar.style.width = percentage + "%";
                progressPct.innerText = percentage + "%";
                statusText.innerText = text;
            };

            // 1. Switch Discovery (0% -> 15%)
            updateProgress(10, "Querying LLDP/CDP managed switch metadata...");
            
            fetch(API_BASE + "/api/network/lldp")
            .then(r => r.json())
            .then(lldp => {
                const lldpPassed = lldp.protocol && lldp.protocol !== "None" && lldp.protocol !== "Listening...";
                const lldpItem = `<div>${lldpPassed ? '<span style="color: var(--success); font-weight: bold;">[PASS]</span>' : '<span style="color: var(--warning); font-weight: bold;">[WARN]</span>'} Switch Discovery: ${lldpPassed ? `Connected to ${lldp.switch_name} on Port ${lldp.port_id}` : "No LLDP/CDP packets detected (Bypassed)"}</div>`;

                // 2. Link & DNS Diagnostics (15% -> 35%)
                setTimeout(() => {
                    updateProgress(30, "Auditing physical cable negotiation and local DNS lookup latency...");
                    
                    fetch(API_BASE + "/api/network/diagnostics", {
                        method: "POST",
                        headers: { "Content-Type": "application/json" },
                        body: JSON.stringify({ interface: selectedIface })
                    })
                    .then(r => r.json())
                    .then(diag => {
                        const linkPassed = diag.cable.success && !diag.cable.warning;
                        const linkItem = `<div>${linkPassed ? '<span style="color: var(--success); font-weight: bold;">[PASS]</span>' : '<span style="color: var(--warning); font-weight: bold;">[WARN]</span>'} Link Negotiation: ${diag.cable.success ? `${diag.cable.speed} / ${diag.cable.duplex}` : "Not audited"}</div>`;
                        
                        const dnsPassed = diag.dns.success;
                        const dnsItem = `<div>${dnsPassed ? '<span style="color: var(--success); font-weight: bold;">[PASS]</span>' : '<span style="color: var(--danger); font-weight: bold;">[FAIL]</span>'} DNS Health Lookup: ${dnsPassed ? `${diag.dns.latency_ms} ms` : "Failed or timed out"}</div>`;

                        // 3. DHCP Server Security Audit (35% -> 55%)
                        setTimeout(() => {
                            updateProgress(50, "Probing subnet for active DHCP servers and rogue leases...");
                            
                            fetch(API_BASE + "/api/scan/dhcp", {
                                method: "POST",
                                headers: { "Content-Type": "application/json" },
                                body: JSON.stringify({ interface: selectedIface })
                            })
                            .then(r => r.json())
                            .then(dhcp => {
                                const dhcpSuccess = dhcp.success;
                                const dhcpServers = dhcp.servers || [];
                                let dhcpItem = "";
                                if (dhcpSuccess && dhcpServers.length > 0) {
                                    const serverIps = dhcpServers.map(s => s.server_ip).join(", ");
                                    if (dhcpServers.length === 1) {
                                        dhcpItem = `<div><span style="color: var(--success); font-weight: bold;">[PASS]</span> DHCP Server Audit: 1 active server detected (${serverIps})</div>`;
                                    } else {
                                        dhcpItem = `<div><span style="color: var(--danger); font-weight: bold;">[FAIL]</span> DHCP Server Audit: Rogue DHCP servers detected! (${dhcpServers.length} active: ${serverIps})</div>`;
                                    }
                                } else {
                                    dhcpItem = `<div><span style="color: var(--warning); font-weight: bold;">[WARN]</span> DHCP Server Audit: No DHCP offers received. Subnet is static.</div>`;
                                }

                                // 4. IP Conflicts (55% -> 75%)
                                setTimeout(() => {
                                    updateProgress(70, "Scanning link for active IP address conflicts...");
                                    
                                    fetch(API_BASE + "/api/network/conflicts")
                                    .then(r => r.json())
                                    .then(conflicts => {
                                        const conflictPassed = conflicts.length === 0;
                                        const conflictItem = `<div>${conflictPassed ? '<span style="color: var(--success); font-weight: bold;">[PASS]</span>' : '<span style="color: var(--danger); font-weight: bold;">[FAIL]</span>'} IP Conflict Scan: ${conflictPassed ? "0 IP conflicts detected" : `${conflicts.length} conflict(s) active`}</div>`;

                                        // 5. Active QoS Ping Test (8 packets) (75% -> 95%)
                                        setTimeout(() => {
                                            updateProgress(85, "Executing live 8-packet QoS ping diagnostic...");
                                            
                                            fetch(API_BASE + "/api/ping/test", {
                                                method: "POST",
                                                headers: { "Content-Type": "application/json" },
                                                body: JSON.stringify({ target: "8.8.8.8", count: 8, interface: selectedIface })
                                            })
                                            .then(r => r.json())
                                            .then(ping => {
                                                const pingPassed = ping.success && ping.loss_percent < 2;
                                                const pingItem = `<div>${ping.success ? (pingPassed ? '<span style="color: var(--success); font-weight: bold;">[PASS]</span>' : '<span style="color: var(--danger); font-weight: bold;">[FAIL]</span>') : '<span style="color: var(--danger); font-weight: bold;">[FAIL]</span>'} QoS Ping Stability: ${ping.success ? `${ping.loss_percent}% packet loss (Avg: ${ping.avg_rtt} ms)` : `Ping test failed: ${ping.error}`}</div>`;

                                                // 6. Completion (100%)
                                                setTimeout(() => {
                                                    updateProgress(100, "Verification sweep complete!");
                                                    
                                                    // Render checklist results
                                                    resultsBox.innerHTML = `
                                                        <div style="font-weight: bold; margin-bottom: 8px; border-bottom: 1px solid rgba(255,255,255,0.1); padding-bottom: 6px; color: var(--accent);">AUTOMATED SITE VERIFICATION RESULTS:</div>
                                                        ${lldpItem}
                                                        ${linkItem}
                                                        ${dnsItem}
                                                        ${dhcpItem}
                                                        ${conflictItem}
                                                        ${pingItem}
                                                    `;
                                                    resultsBox.classList.remove("hidden");
                                                    
                                                    // Enable download and restore sweep button
                                                    generateReportBtn.disabled = false;
                                                    runSweepBtn.disabled = false;
                                                }, 400);
                                            })
                                            .catch(err => {
                                                updateProgress(100, "Ping test failed!");
                                                statusText.innerText = "Error running ping test: " + err;
                                                runSweepBtn.disabled = false;
                                            });
                                        }, 600);
                                    });
                                }, 600);
                            });
                        }, 600);
                    });
                }, 600);
            })
            .catch(err => {
                updateProgress(100, "Verification sweep failed!");
                statusText.innerText = "Error running verification sweep: " + err;
                runSweepBtn.disabled = false;
            });
        });
    }

    // Trigger topology redraw when Tab 3 is selected
    const navButtons = document.querySelectorAll(".nav-btn");
    navButtons.forEach(btn => {
        btn.addEventListener("click", () => {
            if (btn.getAttribute("data-tab") === "topology-tab") {
                // Quick delay to ensure tab is visible before calculating bounds
                setTimeout(drawTopology, 150);
            }
        });
    });
}

function fetchMulticastStatus() {
    const tableBody = document.getElementById("multicast-table-body");
    if (!tableBody) return;

    fetch(API_BASE + "/api/network/multicast")
        .then(r => r.json())
        .then(data => {
            const floodAlert = document.getElementById("igmp-flood-alert");
            if (data.flooding_detected) {
                floodAlert.classList.remove("hidden");
            } else {
                floodAlert.classList.add("hidden");
            }

            if (data.streams && data.streams.length > 0) {
                tableBody.innerHTML = data.streams.map(str => {
                    const badgeClass = str.flooding ? "badge-danger" : "badge-success";
                    const badgeText = str.flooding ? "Unsolicited Flood" : "Healthy IGMP";
                    return `
                        <tr>
                            <td><strong>${str.ip}</strong></td>
                            <td><span class="badge" style="background: rgba(var(--accent-rgb), 0.15); border: 1px solid rgba(var(--accent-rgb), 0.35); color: var(--accent); font-weight: 600; font-size: 0.8rem;">${str.protocol}</span></td>
                            <td><strong style="color: var(--accent);">${str.bandwidth_mbps} Mbps</strong></td>
                            <td>${str.packet_count}</td>
                            <td><span class="badge ${badgeClass}">${badgeText}</span></td>
                            <td style="font-family: var(--font-mono); font-size: 0.85rem;">${str.last_seen}</td>
                        </tr>
                    `;
                }).join("");
            } else {
                tableBody.innerHTML = `<tr><td colspan="5" class="text-center text-muted">No active multicast streams sniffed. Connecting/running IGMP...</td></tr>`;
            }
        })
        .catch(() => {});
}

function drawTopology() {
    const svg = document.getElementById("topology-svg");
    if (!svg) return;

    // Clear canvas
    svg.innerHTML = "";

    // Fetch Switch Port info (LLDP) and Discovered Devices
    Promise.all([
        fetch(API_BASE + "/api/network/lldp").then(r => r.json()),
        fetch(API_BASE + "/api/network/conflicts").then(r => r.json()) // Check if device list is empty
    ])
    .then(([lldp, conflicts]) => {
        // Fetch devices list from sniffer
        // Standard devices list will be fetched from current sniffer database if we trigger it,
        // but let's gather active devices directly.
        // For visual layout simplicity, we'll grab devices from local cache table or quickly hit API.
        fetch(API_BASE + "/api/interfaces")
            .then(r => r.json())
            .then(ifaces => {
                // Render tree node structure
                const svgNS = "http://www.w3.org/2000/svg";
                
                // Helper to create elements
                const createSVGElement = (type, attrs) => {
                    const el = document.createElementNS(svgNS, type);
                    for (let key in attrs) {
                        el.setAttribute(key, attrs[key]);
                    }
                    return el;
                };

                // Add background grid or effects
                // 1. Switch Node (Top Centre)
                const switchName = lldp.switch_name || "Unknown managed Switch";
                const switchIP = lldp.ip || "No Switch IP";
                const switchModel = lldp.model || "CDP/LLDP Listening...";
                const switchPort = lldp.port_id || "Unmapped Port";
                const switchVlan = lldp.vlan || "N/A";
                const switchProtocol = lldp.protocol || "No Protocol";

                // Draw Switch Box
                const swBox = createSVGElement("rect", {
                    x: 275, y: 20, width: 250, height: 80, rx: 8, ry: 8,
                    fill: "rgba(0,0,0,0.45)", stroke: "var(--accent)", "stroke-width": 2
                });
                svg.appendChild(swBox);

                // Switch label
                const swText1 = createSVGElement("text", { x: 400, y: 45, "text-anchor": "middle", fill: "#fff", "font-weight": "bold", "font-size": "14" });
                swText1.textContent = `🖥️ ${switchName}`;
                svg.appendChild(swText1);

                const swText2 = createSVGElement("text", { x: 400, y: 65, "text-anchor": "middle", fill: "var(--text-muted)", "font-size": "11" });
                swText2.textContent = `IP: ${switchIP} | Model: ${switchModel}`;
                svg.appendChild(swText2);

                const swText3 = createSVGElement("text", { x: 400, y: 82, "text-anchor": "middle", fill: "var(--text-secondary)", "font-size": "10", "font-weight": "bold" });
                swText3.textContent = `Source Protocol: ${switchProtocol}`;
                svg.appendChild(swText3);

                // 2. Port / Interface Connection Node (Middle Centre)
                // Draw connecting line from Switch to Port Node
                const linkLine1 = createSVGElement("line", {
                    x1: 400, y1: 100, x2: 400, y2: 170,
                    stroke: "rgba(255,255,255,0.25)", "stroke-width": 2, "stroke-dasharray": "4,4"
                });
                svg.appendChild(linkLine1);

                // Port / VLAN circle
                const portNode = createSVGElement("rect", {
                    x: 290, y: 170, width: 220, height: 60, rx: 6, ry: 6,
                    fill: "rgba(0,0,0,0.55)", stroke: "var(--success)", "stroke-width": 2
                });
                svg.appendChild(portNode);

                const portText1 = createSVGElement("text", { x: 400, y: 192, "text-anchor": "middle", fill: "var(--success)", "font-weight": "bold", "font-size": "12" });
                portText1.textContent = `🔌 Port: ${switchPort}`;
                svg.appendChild(portText1);

                const portText2 = createSVGElement("text", { x: 400, y: 215, "text-anchor": "middle", fill: "#fff", "font-size": "11" });
                portText2.textContent = `VLAN Tag: ${switchVlan}`;
                svg.appendChild(portText2);

                // 3. This Jumpbox Node (Bottom Centre Left)
                const linkLine2 = createSVGElement("line", {
                    x1: 400, y1: 230, x2: 250, y2: 320,
                    stroke: "rgba(255,255,255,0.25)", "stroke-width": 2
                });
                svg.appendChild(linkLine2);

                const rpiNode = createSVGElement("rect", {
                    x: 140, y: 320, width: 220, height: 75, rx: 6, ry: 6,
                    fill: "rgba(0,0,0,0.5)", stroke: "var(--accent)", "stroke-width": 2
                });
                svg.appendChild(rpiNode);

                const rpiText1 = createSVGElement("text", { x: 250, y: 342, "text-anchor": "middle", fill: "#fff", "font-weight": "bold", "font-size": "12" });
                rpiText1.textContent = `🍓 RPi4 Jump Box (This Host)`;
                svg.appendChild(rpiText1);

                // Find eth0 IP address to display
                let eth0Ip = "No IP Assigned";
                const eth0 = ifaces["eth0"] || Object.values(ifaces)[0];
                if (eth0) {
                    if (eth0.ip) eth0Ip = eth0.ip;
                    else if (eth0.addresses && eth0.addresses.length > 0) eth0Ip = eth0.addresses[0];
                }

                const rpiText2 = createSVGElement("text", { x: 250, y: 362, "text-anchor": "middle", fill: "var(--text-muted)", "font-size": "11" });
                rpiText2.textContent = `Interface: eth0 | IP: ${eth0Ip}`;
                svg.appendChild(rpiText2);

                const rpiText3 = createSVGElement("text", { x: 250, y: 380, "text-anchor": "middle", fill: "var(--text-secondary)", "font-size": "10" });
                rpiText3.textContent = `MAC: ${eth0 ? eth0.mac : 'N/A'}`;
                svg.appendChild(rpiText3);

                // 4. Other discovered Client Devices (Bottom Centre Right)
                // To display active devices, we scan the DOM for devices in the discovered devices table.
                // This makes it dynamic and guarantees we don't have to cache arrays on client!
                const rows = Array.from(document.querySelectorAll("#device-list-body tr"));
                const devices = [];
                rows.forEach(row => {
                    const cells = row.querySelectorAll("td");
                    if (cells.length >= 4) {
                        devices.push({
                            ip: cells[0].textContent.trim(),
                            mac: cells[1].textContent.trim(),
                            vendor: cells[2].textContent.trim(),
                            protocol: cells[3].textContent.trim()
                        });
                    }
                });

                // Display up to 3 other devices to prevent layout clutter
                const dispDevs = devices.slice(0, 3);
                if (dispDevs.length > 0) {
                    dispDevs.forEach((dev, index) => {
                        const dx = 550 + index * 180;
                        const dy = 320;

                        // Connection line
                        const cLine = createSVGElement("line", {
                            x1: 400, y1: 230, x2: dx + 80, y2: dy,
                            stroke: "rgba(255,255,255,0.18)", "stroke-width": 2
                        });
                        svg.appendChild(cLine);

                        // Device Box
                        const devBox = createSVGElement("rect", {
                            x: dx, y: dy, width: 160, height: 75, rx: 6, ry: 6,
                            fill: "rgba(0,0,0,0.35)", stroke: "var(--border-color)", "stroke-width": 1.5
                        });
                        svg.appendChild(devBox);

                        const devText1 = createSVGElement("text", { x: dx + 80, y: dy + 22, "text-anchor": "middle", fill: "#fff", "font-weight": "bold", "font-size": "11" });
                        devText1.textContent = dev.ip;
                        svg.appendChild(devText1);

                        const devText2 = createSVGElement("text", { x: dx + 80, y: dy + 40, "text-anchor": "middle", fill: "var(--text-muted)", "font-size": "10" });
                        devText2.textContent = dev.vendor.length > 18 ? dev.vendor.substring(0, 16) + "..." : dev.vendor;
                        svg.appendChild(devText2);

                        const devText3 = createSVGElement("text", { x: dx + 80, y: dy + 58, "text-anchor": "middle", fill: "var(--text-secondary)", "font-size": "9" });
                        devText3.textContent = `Via: ${dev.protocol}`;
                        svg.appendChild(devText3);
                    });
                } else {
                    // No other devices, connect to empty wire box
                    const dx = 550;
                    const dy = 320;

                    const cLine = createSVGElement("line", {
                        x1: 400, y1: 230, x2: dx + 80, y2: dy,
                        stroke: "rgba(255,255,255,0.18)", "stroke-dasharray": "2,2", "stroke-width": 2
                    });
                    svg.appendChild(cLine);

                    const devBox = createSVGElement("rect", {
                        x: dx, y: dy, width: 160, height: 75, rx: 6, ry: 6,
                        fill: "rgba(0,0,0,0.2)", stroke: "rgba(255,255,255,0.15)", "stroke-width": 1.5, "stroke-dasharray": "2,2"
                    });
                    svg.appendChild(devBox);

                    const devText1 = createSVGElement("text", { x: dx + 80, y: dy + 42, "text-anchor": "middle", fill: "var(--text-secondary)", "font-size": "10" });
                    devText1.textContent = "Listening for Devices...";
                    svg.appendChild(devText1);
                }
            });
    });
}

let beaconState = false;

function initSpecializedAVSuite() {
    const beaconBtn = document.getElementById("toggle-beacon-btn");
    const wanBtn = document.getElementById("run-wan-health-btn");

    if (beaconBtn) {
        beaconBtn.addEventListener("click", () => {
            beaconState = !beaconState;
            beaconBtn.disabled = true;
            beaconBtn.innerText = "Toggling...";

            fetch(API_BASE + "/api/hardware/beacon", {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify({ active: beaconState })
            })
            .then(r => r.json())
            .then(data => {
                if (data.success) {
                    if (data.beacon_active) {
                        beaconBtn.innerText = "Beacon: On";
                        beaconBtn.className = "btn btn-danger";
                    } else {
                        beaconBtn.innerText = "Beacon: Off";
                        beaconBtn.className = "btn btn-secondary";
                    }
                } else {
                    alert("Failed to toggle beacon: " + data.error);
                }
            })
            .catch(err => alert("Beacon toggle error: " + err))
            .finally(() => {
                beaconBtn.disabled = false;
            });
        });
    }

    if (wanBtn) {
        wanBtn.addEventListener("click", () => {
            wanBtn.disabled = true;
            wanBtn.innerText = "Running WAN Audits...";

            const setPending = (prefix) => {
                document.getElementById(`wan-${prefix}-latency`).innerText = "...";
                const badge = document.getElementById(`wan-${prefix}-badge`);
                badge.innerText = "Testing";
                badge.className = "badge badge-info";
            };
            setPending("dns");
            setPending("https");
            setPending("ntp");
            setPending("gw");
            setPending("ping");

            fetch(API_BASE + "/api/network/wan_health")
            .then(r => r.json())
            .then(data => {
                const updateRow = (prefix, res) => {
                    const latencyEl = document.getElementById(`wan-${prefix}-latency`);
                    const badge = document.getElementById(`wan-${prefix}-badge`);
                    if (res.success) {
                        latencyEl.innerText = res.latency_ms + " ms";
                        badge.innerText = "PASS";
                        badge.className = "badge badge-success";
                    } else {
                        latencyEl.innerText = "--";
                        badge.innerText = "BLOCKED";
                        badge.className = "badge badge-danger";
                    }
                };

                updateRow("dns", data.dns);
                updateRow("https", data.https);
                updateRow("ntp", data.ntp);
                updateRow("gw", data.gateway_ping);
                updateRow("ping", data.wan_ping);
            })
            .catch(err => alert("WAN health check failed: " + err))
            .finally(() => {
                wanBtn.disabled = false;
                wanBtn.innerText = "Run WAN Diagnostic";
            });
        });
    }

    fetchAVNetworkHealth();
    setInterval(fetchAVNetworkHealth, 5000);
}

function fetchAVNetworkHealth() {
    const scoreNum = document.getElementById("health-score-num");
    const ringFill = document.getElementById("health-ring-fill");
    const statusText = document.getElementById("health-score-status");
    const alertsList = document.getElementById("health-alerts-list");

    if (!scoreNum) return;

    fetch(API_BASE + "/api/network/health")
    .then(r => r.json())
    .then(data => {
        const score = data.score;
        scoreNum.innerText = score;

        const circumference = 326.7;
        const offset = circumference - (circumference * score) / 100;
        ringFill.style.strokeDashoffset = offset;

        if (score >= 90) {
            ringFill.style.stroke = "var(--success)";
            statusText.style.color = "var(--success)";
            statusText.innerText = "EXCELLENT";
        } else if (score >= 70) {
            ringFill.style.stroke = "var(--warning)";
            statusText.style.color = "var(--warning)";
            statusText.innerText = "FAIR / WARNINGS";
        } else {
            ringFill.style.stroke = "var(--danger)";
            statusText.style.color = "var(--danger)";
            statusText.innerText = "POOR / ACTION NEEDED";
        }

        if (data.alerts && data.alerts.length > 0) {
            alertsList.innerHTML = data.alerts.map(alert => `
                <div style="padding: 2px 0; border-bottom: 1px solid rgba(255,255,255,0.04); color: ${alert.includes('CRITICAL') ? 'var(--danger)' : 'var(--warning)'};">
                    ${alert}
                </div>
            `).join("");
        } else {
            alertsList.innerHTML = `<div style="color: var(--success); text-align: center; margin-top: 35px;">No network anomalies active.</div>`;
        }
    })
    .catch(err => {
        console.error("Failed to fetch network health:", err);
    });
}



function initResponsiveAndHelp() {
    // Help Modal
    const helpBtn = document.getElementById("help-btn");
    const helpModal = document.getElementById("help-modal");
    const closeHelpBtn = document.getElementById("close-help-btn");
    
    if (helpBtn && helpModal) {
        helpBtn.addEventListener("click", (e) => {
            e.preventDefault();
            e.stopPropagation();
            helpModal.classList.remove("hidden");
        });
    }
    
    if (closeHelpBtn && helpModal) {
        closeHelpBtn.addEventListener("click", (e) => {
            e.preventDefault();
            helpModal.classList.add("hidden");
        });
    }
    
    if (helpModal) {
        helpModal.addEventListener("click", (e) => {
            if (e.target === helpModal) {
                helpModal.classList.add("hidden");
            }
        });
    }

    // Mobile Navigation Toggle
    const mobileMenuBtn = document.getElementById("mobile-menu-btn");
    const glassContainer = document.querySelector(".glass-container");
    if (mobileMenuBtn && glassContainer) {
        mobileMenuBtn.addEventListener("click", (e) => {
            e.stopPropagation();
            glassContainer.classList.toggle("sidebar-open");
        });
        
        // Auto-close sidebar on navigation selection
        const navBtns = document.querySelectorAll(".nav-btn");
        navBtns.forEach(btn => {
            btn.addEventListener("click", () => {
                glassContainer.classList.remove("sidebar-open");
            });
        });
    }
}
