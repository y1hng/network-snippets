import ipaddress
from scapy.all import *
from concurrent.futures import ThreadPoolExecutor
import os

def arp_pkt(ip):
    ip_str = str(ip) #هنا نحن سنستخدم ipaddress و هي ترجع ip كائن ipvaddress وليس نص و نحن نحتاج نص
    pkt = Ether(dst='ff:ff:ff:ff:ff:ff') / ARP(pdst=ip_str)    
    try:
        ans, _ = srp(pkt,timeout=2 ,verbose=False)
        if ans: # ادا كان هناك رد
            for _, rcv in ans:
                return {"ip": rcv.psrc, "mac": rcv.src}
    except Exception as e:
        print(e)
    return None

def scan(host):
    Host_range = ipaddress.ip_network(host, strict=False)
    descoverd = [] # قائمة لجمع عنواين النشطة
    with ThreadPoolExecutor(max_workers=20) as exe:
        results = exe.map(lambda ip: arp_pkt(ip), Host_range.hosts())
        for res in results:
            if res and res not in descoverd:
                descoverd.append(res)
    return descoverd



def main():
    if os.getuid() != 0:
        print("Please use Root")
        exit()
    HOST = "192.168.56.0/24" #هدا الrange الخاص ب الشبكة اللتي سنجرب عليها 
    alive_devices = scan(HOST)
    for dev in alive_devices:
        print(f"[+] IP {dev['ip']}\tMAC {dev['mac']}")


main()
