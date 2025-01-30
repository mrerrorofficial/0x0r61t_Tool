# modules/ssl_tls_check.py
import ssl
import socket
from core.utils import extract_hostname

def check_ssl(url):
    """Check SSL/TLS information of the target URL."""
    target = extract_hostname(url)
    
    context = ssl.create_default_context()
    conn = context.wrap_socket(socket.socket(socket.AF_INET), server_hostname=target)
    
    try:
        conn.connect((target, 443))
        cert = conn.getpeercert()
        ssl_info = {
            'subject': dict(x[0] for x in cert['subject']),
            'issuer': dict(x[0] for x in cert['issuer']),
            'version': cert.get('version', ''),
            'serialNumber': cert.get('serialNumber', ''),
            'notBefore': cert.get('notBefore', ''),
            'notAfter': cert.get('notAfter', ''),
            'subjectAltName': cert.get('subjectAltName', [])
        }
        conn.close()
        return ssl_info
    except Exception as e:
        return {'error': str(e)}