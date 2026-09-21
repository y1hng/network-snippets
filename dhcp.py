import time
from scapy.all import sniff, DHCP, Ether, IP

LOG_FILE = "dhcp_recon.log"

DHCP_TYPES = {
    1: "DISCOVER",
    2: "OFFER",
    3: "REQUEST",
    4: "DECLINE",
    5: "ACK",
    6: "NAK",
    7: "RELEASE",
    8: "INFORM"
}

def log_event(event_str):
    print(event_str)
    with open(LOG_FILE, "a", encoding="utf-8") as f:
        f.write(event_str + "\n")

def process_dhcp(packet):
    if not packet.haslayer(DHCP):
        return

    mac_address = packet[Ether].src if packet.haslayer(Ether) else "Unknown"
    ip_address = packet[IP].src if packet.haslayer(IP) else "0.0.0.0"

    options = dict([opt for opt in packet[DHCP].options if isinstance(opt, tuple)])

    raw_type = options.get('message-type')
    msg_type = DHCP_TYPES.get(raw_type, f"TYPE_{raw_type}")

    hostname = options.get('hostname', 'N/A')
    vendor = options.get('vendor_class_id', 'N/A')
    requested_ip = options.get('requested_addr', ip_address)

    if isinstance(hostname, bytes): hostname = hostname.decode(errors='ignore')
    if isinstance(vendor, bytes): vendor = vendor.decode(errors='ignore')

    t = time.strftime("%Y-%m-%d %H:%M:%S")
    
    log_line = f"[{t}] [{msg_type:<8}] MAC:{mac_address} | Req-IP:{requested_ip} | Host:{hostname} | Vendor:{vendor}"
    
    log_event(log_line)

init_msg = f"[*] [{time.strftime('%Y-%m-%d %H:%M:%S')}] Starting Passive DHCP Recon & Logging to '{LOG_FILE}'..."
log_event(init_msg)

sniff(filter="udp and (port 67 or port 68)", prn=process_dhcp, store=False)
