import socket
import hashlib
import re

def send_wol_packet(mac_address: str):
    """
    Sends a Wake-On-LAN magic packet to the target MAC address.
    """
    try:
        # Standardize MAC format
        clean_mac = re.sub(r'[^a-fA-F0-9]', '', mac_address)
        if len(clean_mac) != 12:
            return {"success": False, "error": "Invalid MAC address format (must be 12 hex characters)"}
            
        # Create magic packet payload: 6 bytes of 0xFF followed by MAC address repeated 16 times
        mac_bytes = bytes.fromhex(clean_mac)
        payload = b'\xff' * 6 + mac_bytes * 16
        
        # Broadcast over UDP port 9
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        sock.sendto(payload, ('255.255.255.255', 9))
        sock.close()
        
        return {"success": True, "message": f"Wake-on-LAN packet successfully broadcast to {mac_address}"}
    except Exception as e:
        return {"success": False, "error": str(e)}

def send_pjlink_command(ip: str, command: str, password: str = None, port: int = 49152):
    """
    Sends a raw PJLink command (e.g. '%1POWR 1') to the target projector.
    Handles MD5 authentication if the projector requests it.
    """
    try:
        # Connect to projector
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(3.0)
        sock.connect((ip, port))
        
        # Read the initial greeting line (e.g. "PJLINK 0" or "PJLINK 1 85a3c9b1")
        greeting = sock.recv(1024).decode('utf-8', errors='ignore').strip()
        
        if not greeting.startswith("PJLINK"):
            sock.close()
            return {"success": False, "error": "Target did not respond with valid PJLink greeting banner"}
            
        parts = greeting.split(" ")
        auth_mode = parts[1] # "0" = None, "1" = MD5 Auth
        
        # Standardize PJLink command ending with carriage return
        cmd_str = command.strip()
        if not cmd_str.endswith("\r"):
            cmd_str += "\r"
            
        payload = cmd_str.encode('utf-8')
        
        if auth_mode == "1":
            if not password:
                sock.close()
                return {"success": False, "error": "Projector requires MD5 password authentication, but no password was provided."}
                
            # Get 8-character hex salt
            salt = parts[2]
            
            # MD5 calculation: md5(salt + password)
            md5_str = salt + password
            hasher = hashlib.md5()
            hasher.update(md5_str.encode('utf-8'))
            auth_hash = hasher.hexdigest()
            
            # Prefix the hash to the payload
            payload = auth_hash.encode('utf-8') + payload
            
        # Send payload
        sock.sendall(payload)
        
        # Read response
        response = sock.recv(1024).decode('utf-8', errors='ignore').strip()
        sock.close()
        
        return {"success": True, "greeting": greeting, "response": response}
    except socket.timeout:
        return {"success": False, "error": "Connection timed out. Check IP and network paths."}
    except Exception as e:
        return {"success": False, "error": str(e)}
