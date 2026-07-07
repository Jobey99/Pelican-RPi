import subprocess
import psutil

IPERF_PORT = 5201
_process = None

def get_iperf_status():
    """
    Checks if an iPerf3 server process is currently running on the system.
    """
    for proc in psutil.process_iter(['pid', 'name', 'cmdline']):
        try:
            # Check if name is 'iperf3' and it has '-s' in its arguments
            if 'iperf3' in proc.info['name'].lower():
                cmdline = proc.info['cmdline']
                if cmdline and '-s' in cmdline:
                    return {
                        "running": true,
                        "pid": proc.info['pid'],
                        "port": IPERF_PORT,
                        "cmdline": " ".join(cmdline)
                    }
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            pass
    return {"running": False, "port": IPERF_PORT}

def start_iperf_server():
    """
    Starts the iPerf3 server as a background process if not already running.
    """
    status = get_iperf_status()
    if status["running"]:
        return {"success": True, "message": "iPerf3 server is already running.", "pid": status["pid"]}
    
    try:
        # Start iperf3 server on default port 5201
        proc = subprocess.Popen(
            ["iperf3", "-s"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE
        )
        return {"success": True, "message": "iPerf3 server started successfully.", "pid": proc.pid}
    except FileNotFoundError:
        return {"success": False, "error": "iperf3 binary not found. Please install it using: sudo apt install iperf3"}
    except Exception as e:
        return {"success": False, "error": str(e)}

def stop_iperf_server():
    """
    Stops any running iPerf3 server process on the system.
    """
    stopped = False
    for proc in psutil.process_iter(['pid', 'name', 'cmdline']):
        try:
            if 'iperf3' in proc.info['name'].lower():
                cmdline = proc.info['cmdline']
                if cmdline and '-s' in cmdline:
                    proc.terminate()
                    proc.wait(timeout=1.0)
                    stopped = True
        except Exception:
            try:
                proc.kill()
                stopped = True
            except Exception:
                pass
                
    if stopped:
        return {"success": True, "message": "iPerf3 server stopped successfully."}
    return {"success": True, "message": "No running iPerf3 server was found."}

# Fix name lookup for true/false JSON compatibility
true = True
false = False
