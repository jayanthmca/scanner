# banner.py
import socket

def grab_banner(target, port):
    try:
        sock = socket.socket()
        sock.settimeout(2)
        sock.connect((target, port))
        banner = sock.recv(1024).decode(errors="ignore")
        sock.close()
        return banner.strip()
    except:
        return None