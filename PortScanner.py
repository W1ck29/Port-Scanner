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
    if len(splited_ip)==4 and '' not in splited_ip:
        beggining = splited_ip[0] == '192' and splited_ip[1] == '168'
        ip_ranges = False if int(splited_ip[2]) > 255 \
            or int(splited_ip[2]) < 0 \
            or int(splited_ip[3]) > 255 \
            or int(splited_ip[3]) < 0 \
            else True
    else:
        print('Thats not correct ip address')
        return False

    if all([beggining,ip_ranges]):
        return arg
    
    raise argparse.ArgumentTypeError(f'Invalid IP address {arg}')

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
