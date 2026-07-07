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
    
    // Initial fetch of configuration details
    fetchInterfaces();
    fetchSerialStatus();
    
    // Poll active interface listings periodically
    interfacePollInterval = setInterval(fetchInterfaces, 5000);
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
