import subprocess
import psutil

IPERF_PORT = 5201

def _has_systemd_service():
    """
    Checks if there is an iperf3 systemd service unit registered.
    """
    try:
        # Check if iperf3 unit file is known to systemd
        res = subprocess.run(["systemctl", "status", "iperf3"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        # returncode 4 indicates unit file not found, any other code means unit exists
        return res.returncode != 4
    except Exception:
        return False

def get_iperf_status():
    """
    Checks if an iPerf3 server process is currently running on the system
    either via systemd service or manual background process.
    """
    # 1. Check if systemd service is active
    if _has_systemd_service():
        try:
            res = subprocess.run(["systemctl", "is-active", "iperf3"], stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True)
            if res.stdout.strip() == "active":
                return {
                    "running": True,
                    "pid": 0,  # Managed by systemd
                    "port": IPERF_PORT,
                    "cmdline": "systemd service (iperf3.service)"
                }
        except Exception:
            pass

    # 2. Fallback to process checks
    for proc in psutil.process_iter(['pid', 'name', 'cmdline']):
        try:
            if 'iperf3' in proc.info['name'].lower():
                cmdline = proc.info['cmdline']
                if cmdline and ('-s' in cmdline or '--server' in cmdline):
                    return {
                        "running": True,
                        "pid": proc.info['pid'],
                        "port": IPERF_PORT,
                        "cmdline": " ".join(cmdline)
                    }
        except (psutil.NoSuchProcess, psutil.AccessDenied, proc.ZombieProcess):
            pass
            
    return {"running": False, "port": IPERF_PORT}

def start_iperf_server():
    """
    Starts the iPerf3 server (tries systemd service first, then manual fallback).
    """
    if _has_systemd_service():
        try:
            subprocess.run(["sudo", "systemctl", "start", "iperf3"], check=True)
            return {"success": True, "message": "iPerf3 systemd service started successfully."}
        except Exception:
            pass  # Fallback to manual execution if systemctl fails

    status = get_iperf_status()
    if status["running"]:
        return {"success": True, "message": "iPerf3 server is already running."}
    
    try:
        proc = subprocess.Popen(
            ["iperf3", "-s"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE
        )
        return {"success": True, "message": "iPerf3 server started manually in background.", "pid": proc.pid}
    except FileNotFoundError:
        return {"success": False, "error": "iperf3 binary not found. Please install it: sudo apt install iperf3"}
    except Exception as e:
        return {"success": False, "error": str(e)}

def stop_iperf_server():
    """
    Stops any running iPerf3 server (tries systemd service first, then manual process kill).
    """
    if _has_systemd_service():
        try:
            subprocess.run(["sudo", "systemctl", "stop", "iperf3"], check=True)
            return {"success": True, "message": "iPerf3 systemd service stopped successfully."}
        except Exception:
            pass  # Fallback to process kill if systemctl fails

    stopped = False
    for proc in psutil.process_iter(['pid', 'name', 'cmdline']):
        try:
            if 'iperf3' in proc.info['name'].lower():
                cmdline = proc.info['cmdline']
                if cmdline and ('-s' in cmdline or '--server' in cmdline):
                    proc.terminate()
                    proc.wait(timeout=1.0)
                    stopped = True
        except Exception:
            try:
                proc.kill()
                stopped = True
            except Exception:
                pass
                
    return {"success": True, "message": "iPerf3 server stopped successfully."}

true = True
false = False
