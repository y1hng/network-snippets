from scapy.all import *
from concurrent.futures import ThreadPoolExecutor

COMMON_PORTS = {
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    53: "DNS",
    80: "HTTP",
    110: "POP3",
    139: "NetBIOS",
    143: "IMAP",
    443: "HTTPS",
    445: "SMB",
    1433: "MSSQL",
    1521: "Oracle",
    3306: "MySQL",
    3389: "RDP",
    5432: "PostgreSQL",
    5900: "VNC",
    6379: "Redis",
    8080: "HTTP-Proxy",
    8443: "HTTPS-Alt",
    27017: "MongoDB",
}

DST_IP = "192.168.56.101"


def scanner(ip, port):
    service = COMMON_PORTS.get(port, 'Unknown')
    pkt = IP(dst=ip) / TCP(dport=port, flags='S')
    ans = sr1(pkt, timeout=3, verbose=False)
    if ans is not None and ans.haslayer(TCP):
        flags = ans.getlayer(TCP).flags
        if flags == 0x12:
            return port, service, True
    return port, service, False

def main():
    print(f'Start scanning on target: {DST_IP}')
    OPEN_ports = []
    with ThreadPoolExecutor(max_workers=30) as exe:
        results = exe.map(lambda p: scanner(DST_IP, p), COMMON_PORTS.keys())
        for port, service, is_open in results:
            if is_open:
                print(f'PORT: {port} | Service: {service} ||OPEN')
                OPEN_ports.append(port)
    print("scan stop")
    print(f"len of ports OPEN: {len(OPEN_ports)}")

main()
