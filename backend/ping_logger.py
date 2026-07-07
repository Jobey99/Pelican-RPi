import threading
import time
import subprocess
import re
import os
import csv

class PingMonitor:
    def __init__(self):
        self.target = "8.8.8.8"
        self.interface = "eth0"
        self.running = False
        self.thread = None
        self.history = []  # List of last 60 RTT values (float or None)
        self.lock = threading.Lock()
        
        # Stats counters
        self.sent = 0
        self.lost = 0
        self.total_rtt = 0.0
        self.min_rtt = float('inf')
        self.max_rtt = 0.0
        
        # Hourly logging tracking
        self.hourly_sent = 0
        self.hourly_lost = 0
        self.hourly_rtts = []
        self.last_log_hour = time.localtime().tm_hour
        
        # Log file path
        self.log_file = os.path.abspath(os.path.join(os.path.dirname(__file__), "ping_diagnostics.csv"))
        self._init_csv()

    def _init_csv(self):
        if not os.path.exists(self.log_file):
            try:
                with open(self.log_file, "w", newline="") as f:
                    writer = csv.writer(f)
                    writer.writerow(["Timestamp", "Target", "Sent", "Lost_Packets", "Loss_Percent", "Min_RTT_ms", "Avg_RTT_ms", "Max_RTT_ms"])
            except Exception:
                pass

    def start(self, target: str = "8.8.8.8", interface: str = "eth0"):
        if self.running:
            self.stop()
            
        self.target = target
        self.interface = interface
        self.running = True
        
        with self.lock:
            self.history.clear()
            self.sent = 0
            self.lost = 0
            self.total_rtt = 0.0
            self.min_rtt = float('inf')
            self.max_rtt = 0.0
            self.hourly_sent = 0
            self.hourly_lost = 0
            self.hourly_rtts.clear()
            self.last_log_hour = time.localtime().tm_hour
            
        self.thread = threading.Thread(target=self._monitor_loop, daemon=True)
        self.thread.start()

    def stop(self):
        self.running = False
        if self.thread:
            self.thread.join(timeout=1.5)
            self.thread = None

    def get_status(self):
        with self.lock:
            avg_rtt = 0
            success_count = self.sent - self.lost
            if success_count > 0:
                avg_rtt = round(self.total_rtt / success_count, 2)
                
            loss_percent = 0
            if self.sent > 0:
                loss_percent = round((self.lost / self.sent) * 100, 1)

            # Replace inf for JSON serialization
            show_min = round(self.min_rtt, 2) if self.min_rtt != float('inf') else 0
            show_max = round(self.max_rtt, 2)
            
            return {
                "active": self.running,
                "target": self.target,
                "sent": self.sent,
                "lost": self.lost,
                "loss_percent": loss_percent,
                "min_rtt": show_min,
                "avg_rtt": avg_rtt,
                "max_rtt": show_max,
                "history": self.history[-60:]  # Last 60 results
            }

    def _monitor_loop(self):
        # We can enforce interface binding by specifying ping's '-I' flag
        # Command syntax: ping -c 1 -W 1 -I <interface> <target>
        while self.running:
            start_tick = time.time()
            
            # Execute ping command
            rtt = self._ping_once()
            
            with self.lock:
                self.sent += 1
                self.hourly_sent += 1
                
                if rtt is not None:
                    self.history.append(rtt)
                    self.total_rtt += rtt
                    self.min_rtt = min(self.min_rtt, rtt)
                    self.max_rtt = max(self.max_rtt, rtt)
                    self.hourly_rtts.append(rtt)
                else:
                    self.history.append(None)
                    self.lost += 1
                    self.hourly_lost += 1
                    
                # Cap history size at 120 (keep double of what's shown)
                if len(self.history) > 120:
                    self.history.pop(0)

                # Check if the hour has rolled over to write to CSV log
                current_hour = time.localtime().tm_hour
                if current_hour != self.last_log_hour:
                    self._write_hourly_log()
                    self.last_log_hour = current_hour
                    
            # Ensure it checks exactly once per second
            elapsed = time.time() - start_tick
            sleep_time = max(0.1, 1.0 - elapsed)
            time.sleep(sleep_time)

    def _ping_once(self):
        try:
            # -c 1: send 1 packet, -W 1: wait 1 second response timeout
            cmd = ["ping", "-c", "1", "-W", "1", "-I", self.interface, self.target]
            # Suppress console output
            res = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True, timeout=1.5)
            
            if res.returncode == 0:
                # Find RTT string, e.g. "time=14.5 ms"
                match = re.search(r"time=([0-9.]+)\s*ms", res.stdout)
                if match:
                    return float(match.group(1))
            return None
        except Exception:
            return None

    def _write_hourly_log(self):
        """
        Appends an hourly statistics summary to the diagnostics CSV file.
        """
        try:
            timestamp = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime())
            total = self.hourly_sent
            lost = self.hourly_lost
            
            loss_percent = 0
            if total > 0:
                loss_percent = round((lost / total) * 100, 1)
                
            min_val = round(min(self.hourly_rtts), 2) if self.hourly_rtts else 0.0
            max_val = round(max(self.hourly_rtts), 2) if self.hourly_rtts else 0.0
            avg_val = round(sum(self.hourly_rtts) / len(self.hourly_rtts), 2) if self.hourly_rtts else 0.0
            
            with open(self.log_file, "a", newline="") as f:
                writer = csv.writer(f)
                writer.writerow([timestamp, self.target, total, lost, loss_percent, min_val, avg_val, max_val])
                
            # Reset hourly statistics counters
            self.hourly_sent = 0
            self.hourly_lost = 0
            self.hourly_rtts.clear()
        except Exception:
            pass
