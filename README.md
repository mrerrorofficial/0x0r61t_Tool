# 0x0r61t Tool

0x0r61t Tool is a comprehensive website penetration testing CLI tool. It supports various scanning and attack modes, including port scanning, vulnerability scanning, inspecting HTTP headers, checking SSL/TLS information, directory brute forcing, and subdomain enumeration.

## Features

- **Port Scanning:** Scan for open ports on the target URL or IP/hostname.
- **Vulnerability Scanning:** Scan for known vulnerabilities on the target URL.
- **HTTP Header Inspection:** Inspect HTTP headers of the target URL.
- **SSL/TLS Information:** Check SSL/TLS information of the target URL.
- **Directory Brute Forcing:** Perform directory brute forcing using a wordlist.
- **Subdomain Enumeration:** Enumerate subdomains using a wordlist.

## Installation

To use 0x0r61t Tool, you need to have Python installed on your system. You can install the required dependencies using `pip` and the provided `requirements.txt` file.

### Steps to Install

1. **Clone the Repository:**

    ```sh
    git clone https://github.com/yourusername/0x0r61t-tool.git
    cd 0x0r61t-tool
    ```

2. **Install the Dependencies:**

    ```sh
    pip install -r requirements.txt
    ```

## Usage

The 0x0r61t Tool provides various scanning and attacking options. You can specify the target URL, choose the scanning and attack modes, and provide additional options like ports and wordlists.

### Command-Line Arguments

- `-u`, `--url` (required): Target URL or IP/hostname.
- `-s`, `--scan`: Select the scanning mode(s). Options: `port_scan`, `vuln_scan`, `inspect_headers`, `check_ssl`. Multiple modes can be specified.
- `-a`, `--attack`: Select the attack mode(s). Options: `dir_brute_force`, `subdomain_enum`. Multiple modes can be specified.
- `-p`, `--ports`: Ports to scan (default: specific ports).
- `-w`, `--wordlist`: Path to the wordlist file (required for directory brute forcing and subdomain enumeration).
- `-o`, `--output` (required): Output file to save the report (CSV or JSON).

### Example Commands

1. **Port Scanning and Vulnerability Scanning:**

    ```sh
    python3 cli.py -u https://example.com -s port_scan vuln_scan -o sec.json -p 80,443
    ```

2. **Inspect HTTP Headers and Check SSL/TLS Information:**

    ```sh
    python3 cli.py -u https://example.com -s inspect_headers check_ssl -o sec.json
    ```

3. **Directory Brute Forcing:**

    ```sh
    python3 cli.py -u https://example.com -a dir_brute_force -w footprinting-wordlist.txt -o sec.json
    ```

4. **Subdomain Enumeration:**

    ```sh
    python3 cli.py -u https://example.com -a subdomain_enum -w footprinting-wordlist.txt -o sec.json
    ```

5. **Full Scan and Attack:**

    ```sh
    python3 cli.py -u https://example.com -s port_scan vuln_scan inspect_headers check_ssl -a dir_brute_force subdomain_enum -w footprinting-wordlist.txt -o sec.json -p 80,443,8000,8080
    ```

### Output

The tool saves the results in the specified output file in CSV or JSON format, based on the file extension provided.
