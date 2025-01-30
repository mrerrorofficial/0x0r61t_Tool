# modules/port_scanner.py
import nmap
from core.utils import validate_ip, validate_hostname, extract_hostname

def scan_ports(target, ports):
    """Scan specified ports on the target and identify versions and services."""
    hostname = extract_hostname(target)
    if not validate_ip(hostname) and not validate_hostname(hostname):
        raise ValueError("Invalid target IP or hostname")

    nm = nmap.PortScanner()
    port_str = ','.join(map(str, ports))
    nm.scan(hostname, port_str, arguments='-sV -A')

    open_ports = {}
    for host in nm.all_hosts():
        for proto in nm[host].all_protocols():
            lport = nm[host][proto].keys()
            for port in lport:
                open_ports[port] = {
                    'state': nm[host][proto][port]['state'],
                    'name': nm[host][proto][port]['name'],
                    'product': nm[host][proto][port]['product'],
                    'version': nm[host][proto][port]['version']
                }
    return open_ports
