import argparse
import socket
import threading

class NoIpToScan(Exception):
    pass

class RangeError(Exception):
    pass

class AlreadySpecified(Exception):
    pass

class Scanner():
    def __init__(self) -> None:
        self.socket_obj = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    def scan_ports(self, ips,port):
        for ip in ips:
            result = self.socket_obj.connect_ex((ip,port))
            if result ==0:
                print(f'{ip}:Port {port} is open')
    
def port_scan(ip,ports):
    threads = []
    for port in ports:
        scanner = Scanner()
        thread = threading.Thread(target=scanner.scan_ports,args=(ip,port))
        thread.start()
        threads.append(thread)
    for t in threads:
        t.join()

def ip_checker(arg):
    splited_ip = arg.split('.')
    
    if len(splited_ip) != 4:
        print('Invalid IP address: The IP address should consist of four parts.')
        return False
    
    if any(part == '' for part in splited_ip):
        print('Invalid IP address: Each part of the IP address should be non-empty.')
        return False

    if not all(part.isdigit() and 0 <= int(part) <= 255 for part in splited_ip):
        print('Invalid IP address: Each part of the IP address should be a number between 0 and 255.')
        return False

    if splited_ip[0] == '192' and splited_ip[1] == '168':
        return arg
    else:
        print('Invalid IP address: Only IP addresses from the local network (192.168.x.x) are allowed.')
        return False


def main():
    try:
        parser = argparse.ArgumentParser(
            prog='PortScanner',
            description='This program checks open ports',
            usage='\npython portscanner.py -ip 192.168.0.10 -min 22 -max 1000 \n \n'
        )

        parser.add_argument(
            '-ip',
            type=ip_checker,
            action='append',
            help='IP address(es) which will be scanned'
        )
        parser.add_argument(
            '-max',
            type=int,
            help='port scanner will end on this port (default 10,000)',
        )
        parser.add_argument(
            '-min',
            type=int,
            help='port scanner will start on this port (default 1)',
        )
        parser.add_argument(
            '-v',
            '--verbose',
            action='count',
            default=0
        )
        parser.add_argument(
            '-p',
            '--port',
            type=int,
            action='append',
            help='Declare ports by yourself'
        )
        args = parser.parse_args()
        if not args.ip:
            raise NoIpToScan('You didn\'t enter an IP to scan')
        if args.min and args.max:
            if args.min >= args.max:
                raise RangeError('Wrong usage of argument')
            if args.port:
                raise AlreadySpecified('You already specified range of ports')
            ports_to_scan = range(args.min, args.max + 1)
            port_scan(args.ip,ports_to_scan)
        elif args.port:
            port_scan(args.ip,args.port)
        else:
            ports_to_scan = range(1, 10000 + 1)
            port_scan(args.ip,ports_to_scan)
    except (AlreadySpecified, RangeError, NoIpToScan) as e:
        print(e)
    except AttributeError as atr:
        print(atr)
    except KeyboardInterrupt :
        print('Program has been interrupted by user')

if __name__ == '__main__':
    main()
