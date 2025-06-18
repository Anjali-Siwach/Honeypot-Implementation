import socket
import threading
import datetime
import json
import os
import time

# Set up log directory
LOG_DIR = "honeypot_logs"
os.makedirs(LOG_DIR, exist_ok=True)

class Honeypot:
    def __init__(self, bind_ip="0.0.0.0", ports=None):
        self.bind_ip = bind_ip
        self.ports = ports or [21, 22, 80, 443]  # Monitored ports
        self.log_file = os.path.join(LOG_DIR, f"honeypot_{datetime.datetime.now().strftime('%Y%m%d')}.json")

    def log_activity(self, port, remote_ip, data):
        """Log attack details with timestamp"""
        activity = {
            "timestamp": datetime.datetime.now().isoformat(),
            "remote_ip": remote_ip,
            "port": port,
            "data": data.decode('utf-8', errors='ignore')
        }
        with open(self.log_file, 'a') as f:
            json.dump(activity, f)
            f.write('\n')
        print(f"[*] Logged attack from {remote_ip} on port {port}")

    def handle_connection(self, client_socket, remote_ip, port):
        """Simulate real services (FTP, SSH, HTTP, HTTPS)"""
        service_banners = {
            21: "220 Fake FTP Server Ready\r\n",
            22: "SSH-2.0-OpenSSH_8.2p1 Ubuntu\r\n",
            80: "HTTP/1.1 200 OK\r\nServer: Fake Apache\r\n\r\n",
            443: "HTTP/1.1 200 OK\r\nServer: Fake Apache\r\n\r\n"
        }

        try:
            if port in service_banners:
                client_socket.send(service_banners[port].encode())

            while True:
                data = client_socket.recv(1024)
                if not data:
                    break
                self.log_activity(port, remote_ip, data)
                client_socket.send(b"Command not recognized.\r\n")

        except (ConnectionResetError, ConnectionAbortedError, BrokenPipeError):
            print(f"[!] Connection lost from {remote_ip}:{port}")
        except Exception as e:
            print(f"Error handling connection: {e}")
        finally:
            client_socket.close()

    def start_listener(self, port):
        """Start network listener for each port"""
        try:
            server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            server.bind((self.bind_ip, port))
            server.listen(5)
            print(f"[*] Honeypot listening on {self.bind_ip}:{port}")

            while True:
                client, addr = server.accept()
                print(f"[*] Connection from {addr[0]}:{addr[1]}")
                thread = threading.Thread(target=self.handle_connection, args=(client, addr[0], port))
                thread.start()

        except Exception as e:
            print(f"Error starting listener on port {port}: {e}")

def main():
    honeypot = Honeypot()

    for port in honeypot.ports:
        thread = threading.Thread(target=honeypot.start_listener, args=(port,))
        thread.daemon = True
        thread.start()

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\n[*] Shutting down honeypot...")
        sys.exit(0)

if __name__ == "__main__":
    main()
