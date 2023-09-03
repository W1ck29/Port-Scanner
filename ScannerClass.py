import socket
class Scanner():
    def __init__(self) -> None:
        self.socket_obj = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    def scan_ports(self, ips, port):
        # check if port is open
        for ip in ips:
            result = self.socket_obj.connect_ex((ip, port))
            if result == 0:
                print(f'{ip}:Port {port} is open')