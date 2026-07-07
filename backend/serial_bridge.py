import threading
import socket
import time
import serial
import serial.tools.list_ports
from fastapi import WebSocket

class SerialBridge:
    def __init__(self):
        self.serial_port = None
        self.baudrate = 9600
        self.ser = None
        self.running = False
        
        # TCP Server settings
        self.tcp_port = 23
        self.tcp_server_socket = None
        self.tcp_client_socket = None
        
        # Thread handles
        self.serial_read_thread = None
        self.tcp_server_thread = None
        
        # Active WebSockets for the UI terminal
        self.active_websockets = set()
        
        # Lock to prevent race conditions during write
        self.write_lock = threading.Lock()

    def list_ports(self):
        """
        Lists all available serial ports.
        """
        ports = serial.tools.list_ports.comports()
        return [{"device": p.device, "description": p.description} for p in ports]

    def connect(self, port: str, baudrate: int):
        """
        Connects to the specified serial port.
        """
        if self.ser and self.ser.is_open:
            self.disconnect()
            
        self.serial_port = port
        self.baudrate = baudrate
        
        try:
            self.ser = serial.Serial(port=port, baudrate=baudrate, timeout=0.1)
            self.running = True
            
            # Start serial reader thread
            self.serial_read_thread = threading.Thread(target=self._read_serial_loop, daemon=True)
            self.serial_read_thread.start()
            
            return {"success": True, "message": f"Connected to {port} at {baudrate} baud."}
        except Exception as e:
            return {"success": False, "error": str(e)}

    def disconnect(self):
        """
        Closes serial port and stops reading thread.
        """
        self.running = False
        if self.ser and self.ser.is_open:
            self.ser.close()
        
        if self.serial_read_thread:
            self.serial_read_thread.join(timeout=1.0)
            self.serial_read_thread = None
            
        self.ser = None
        return {"success": True, "message": "Disconnected serial port."}

    def start_tcp_bridge(self, port: int = 23):
        """
        Starts TCP Server bridge on specified port.
        """
        self.stop_tcp_bridge()
        self.tcp_port = port
        
        try:
            self.tcp_server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            # Allow reusing port instantly after closing
            self.tcp_server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.tcp_server_socket.bind(("0.0.0.0", port))
            self.tcp_server_socket.listen(1)
            
            self.tcp_server_thread = threading.Thread(target=self._tcp_server_loop, daemon=True)
            self.tcp_server_thread.start()
            
            return {"success": True, "message": f"TCP bridge started on port {port}"}
        except Exception as e:
            return {"success": False, "error": f"Failed to start TCP bridge: {e}"}

    def stop_tcp_bridge(self):
        """
        Stops TCP Server bridge and closes client connection.
        """
        if self.tcp_client_socket:
            try:
                self.tcp_client_socket.close()
            except Exception:
                pass
            self.tcp_client_socket = None
            
        if self.tcp_server_socket:
            try:
                self.tcp_server_socket.close()
            except Exception:
                pass
            self.tcp_server_socket = None
            
        if self.tcp_server_thread:
            self.tcp_server_thread.join(timeout=1.0)
            self.tcp_server_thread = None

        return {"success": True, "message": "TCP bridge stopped."}

    def write(self, data: bytes):
        """
        Writes raw bytes to the serial port.
        """
        if self.ser and self.ser.is_open:
            with self.write_lock:
                try:
                    self.ser.write(data)
                    return True
                except Exception:
                    return False
        return False

    def _read_serial_loop(self):
        """
        Background reader loop for the serial port.
        Broadcasts received bytes to active WebSockets and TCP Client.
        """
        while self.running:
            if self.ser and self.ser.is_open:
                try:
                    data = self.ser.read(1024)
                    if data:
                        # 1. Send to TCP connected client
                        if self.tcp_client_socket:
                            try:
                                self.tcp_client_socket.sendall(data)
                            except Exception:
                                self.tcp_client_socket = None # Connection dead
                        
                        # 2. Send to WebSockets (async websocket needs to be called from correct loop, 
                        # so we send raw string or trigger broadcast in backend main loop)
                        self._broadcast_to_websockets(data)
                except Exception:
                    time.sleep(0.5)
            else:
                time.sleep(0.1)

    def _tcp_server_loop(self):
        """
        Background loop accepting incoming TCP connections.
        Bridges socket packets to serial.
        """
        while self.tcp_server_socket:
            try:
                client_sock, addr = self.tcp_server_socket.accept()
                self.tcp_client_socket = client_sock
                
                # Listen to this client
                while self.tcp_client_socket:
                    try:
                        data = self.tcp_client_socket.recv(1024)
                        if not data:
                            break # Client disconnected
                        
                        # Forward to serial
                        self.write(data)
                    except Exception:
                        break
                        
                client_sock.close()
                self.tcp_client_socket = None
            except Exception:
                break

    def register_websocket(self, websocket: WebSocket):
        self.active_websockets.add(websocket)

    def unregister_websocket(self, websocket: WebSocket):
        self.active_websockets.discard(websocket)

    def _broadcast_to_websockets(self, data: bytes):
        if not self.active_websockets:
            return
        
        # Fast import of asyncio event loop utilities to schedule sending
        import asyncio
        loop = asyncio.get_event_loop()
        
        # Convert bytes to string (with lossy decoding) for standard JSON/Text WS transport,
        # or send binary.
        text_data = data.decode("utf-8", errors="ignore")
        
        async def send_all():
            disconnected = []
            for ws in list(self.active_websockets):
                try:
                    await ws.send_text(text_data)
                except Exception:
                    disconnected.append(ws)
            for ws in disconnected:
                self.active_websockets.discard(ws)
                
        if loop.is_running():
            asyncio.run_coroutine_threadsafe(send_all(), loop)
        else:
            asyncio.run(send_all())
