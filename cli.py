# cli.py
import argparse
import time
import json
import threading
from termcolor import colored
from tabulate import tabulate
from threading import Thread
import pyfiglet  # Import pyfiglet for ASCII art text
from core import report
from modules import port_scanner, vulnerability_scanner, dir_brute_force, subdomain_enum, http_header_inspect, ssl_tls_check

# Helper function to display loading animation
def loading_animation(message):
    for char in '|/-\\':
        print(f'\r{message} {char}', end='', flush=True)
        time.sleep(0.1)

# Function to animate text
def animate_text(text):
    """Animate the text by printing one character at a time."""
    for char in text:
        print(char, end='', flush=True)
        time.sleep(0.1)
    print()

# Function to display ASCII art text using pyfiglet
def display_ascii_art(text):
    ascii_art = pyfiglet.figlet_format(text)
    for line in ascii_art.split('\n'):
        print(line)
        time.sleep(0.1)  # Add delay to create animation effect

# Function to run loading animation in a separate thread
def run_loading_animation(message, stop_event):
    while not stop_event.is_set():
        loading_animation(message)

def main():
    # Display ASCII art text with animation
    display_ascii_art("0x0r61t Tool")

    parser = argparse.ArgumentParser(description="Website Penetration Testing CLI Tool")
    
    # Attack Mode
    parser.add_argument("-a", "--attack", nargs='+', choices=["dir_brute_force", "subdomain_enum"], help="Select the attack mode(s) (dir_brute_force, subdomain_enum)")

    # Scanning Mode
    parser.add_argument("-s", "--scan", nargs='+', choices=["port_scan", "vuln_scan", "inspect_headers", "check_ssl"], help="Select the scanning mode(s) (port_scan, vuln_scan, inspect_headers, check_ssl)")

    # Common arguments
    parser.add_argument("-u", "--url", help="Target URL or IP/hostname", required=True)
    parser.add_argument("-p", "--ports", type=str, help="Ports to scan (default: specific ports)")
    parser.add_argument("-w", "--wordlist", help="Path to the wordlist file (required for directory brute forcing and subdomain enumeration)")
    parser.add_argument("-o", "--output", help="Output file to save the report (CSV or JSON)", required=True)

    args = parser.parse_args()

    # Handle comma-separated ports
    if args.ports:
        args.ports = [int(port.strip()) for port in args.ports.split(',')]

    results = {}

    stop_event = threading.Event()

    if args.scan:
        if "port_scan" in args.scan:
            loading_thread = Thread(target=run_loading_animation, args=("Scanning for open ports", stop_event))
            loading_thread.start()
            if not args.ports:
                # Use specified default ports if ports are not specified
                args.ports = [21, 22, 23, 25, 53, 80, 110, 135, 139, 443, 445, 3306, 3389]
            results['open_ports'] = port_scanner.scan_ports(args.url, args.ports)
            stop_event.set()
            loading_thread.join()
            print("\n")

            # Display port scan results in tabular format
            table_data = [[port, info['state'], info['name'], info['product'], info['version']] for port, info in results['open_ports'].items()]
            headers = ["Port", "State", "Service", "Product", "Version"]
            print(tabulate(table_data, headers, tablefmt='grid'))

    if "vuln_scan" in args.scan:
        stop_event.clear()
        loading_thread = Thread(target=run_loading_animation, args=("Scanning for vulnerabilities", stop_event))
        loading_thread.start()
        vulnerabilities = vulnerability_scanner.scan_vulnerabilities(args.url)
        results['vulnerabilities'] = vulnerabilities
        stop_event.set()
        loading_thread.join()
        print("\n")
        
        # Display vulnerabilities in tabular format
        if vulnerabilities:
            table_data = [[vuln] for vuln in vulnerabilities]
            headers = ["Vulnerabilities"]
            print(tabulate(table_data, headers, tablefmt='grid'))
        else:
            print("No vulnerabilities found.")

    if args.attack:
        if "dir_brute_force" in args.attack:
            if args.wordlist:
                stop_event.clear()
                loading_thread = Thread(target=run_loading_animation, args=("Brute forcing directories", stop_event))
                loading_thread.start()
                directories = dir_brute_force.brute_force_dirs(args.url, args.wordlist)
                results['directories'] = directories
                stop_event.set()
                loading_thread.join()
                print("\n")
                
                # Display directories in tabular format
                if directories:
                    table_data = [[directory] for directory in directories]
                    headers = ["Directories"]
                    print(tabulate(table_data, headers, tablefmt='grid'))
                else:
                    print("No directories found.")
            else:
                print("Wordlist is required for directory brute forcing. Use the -w flag to specify the wordlist.")
                return

        if "subdomain_enum" in args.attack:
            if args.wordlist:
                stop_event.clear()
                loading_thread = Thread(target=run_loading_animation, args=("Enumerating subdomains", stop_event))
                loading_thread.start()
                subdomains = subdomain_enum.enum_subdomains(args.url, args.wordlist)
                results['subdomains'] = subdomains
                stop_event.set()
                loading_thread.join()
                print("\n")
                
                # Display subdomains in a readable format
                if subdomains:
                    table_data = [[subdomain] for subdomain in subdomains]
                    headers = ["Subdomains"]
                    print(tabulate(table_data, headers, tablefmt='grid'))
                else:
                    print("No subdomains found.")
            else:
                print("Wordlist is required for subdomain enumeration. Use the -w flag to specify the wordlist.")
                return

    if "inspect_headers" in args.scan:
        stop_event.clear()
        loading_thread = Thread(target=run_loading_animation, args=("Inspecting HTTP headers", stop_event))
        loading_thread.start()
        headers = http_header_inspect.inspect_headers(args.url)
        results['headers'] = dict(headers)  # Convert CaseInsensitiveDict to regular dict
        stop_event.set()
        loading_thread.join()
        print("\n")
        
        # Display HTTP headers in tabular format
        table_data = [[key, value] for key, value in results['headers'].items()]
        headers = ["Header", "Value"]
        print(tabulate(table_data, headers, tablefmt='grid'))

    if "check_ssl" in args.scan:
        stop_event.clear()
        loading_thread = Thread(target=run_loading_animation, args=("Checking SSL/TLS information", stop_event))
        loading_thread.start()
        ssl_info = ssl_tls_check.check_ssl(args.url)
        results['ssl_info'] = ssl_info
        stop_event.set()
        loading_thread.join()
        print("\n")
        
        # Display SSL/TLS info in tabular format
        if 'error' in ssl_info:
            print(f"SSL/TLS check error: {ssl_info['error']}")
        else:
            # Flatten the subject and issuer dictionaries for tabular display
            subject_info = ssl_info['subject']
            issuer_info = ssl_info['issuer']
            ssl_info_flat = {**ssl_info, **subject_info, **issuer_info}
            for key in ['subject', 'issuer']:
                del ssl_info_flat[key]
            
            table_data = [[key, value] for key, value in ssl_info_flat.items()]
            headers = ["SSL/TLS Info", "Value"]
            print(tabulate(table_data, headers, tablefmt='grid'))

    # Save the report if output file is specified
    if args.output:
        report.save_report(args.output, results)

if __name__ == "__main__":
    main()