#server 

import socket
import struct
import uuid

IP = '127.0.0.1'
PORT = 4443

FLAG = 'net_infra_socket_master_2026'
servmagic = 0x01
tcpsock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
tcpsock.bind((IP, PORT))
tcpsock.listen(1)
print(f"[*] Server listening on {IP}:{PORT}...")
conn, addr = tcpsock.accept()
print(f"[+] Connection accepted from {addr}")
try:
    header_data = conn.recv(3)
    magic, length = struct.unpack("!BH", header_data)
    if magic != servmagic:
        print("[-] Invalid Magic Byte! Closing connection.")
    else:
        payload = conn.recv(length)
        text = payload.decode("utf-8")
        if text == "Hello":
            unicid = uuid.uuid1()
            length = len(str(unicid))
            header = struct.pack("!BH", servmagic, length)
            packet = header + str(unicid).encode()
            conn.sendall(packet)
            header_data = conn.recv(3)
            magic, length = struct.unpack("!BH", header_data)
            payload = conn.recv(length)
            if payload.decode('utf-8') != str(unicid):
                print("[-] Invalid session! Closing connection.")
                tcpsock.close()
            else:
                w = 1 #win
                length = len(FLAG)
                header = struct.pack("!BBH", servmagic, w, length)
                packet = header + FLAG.encode('utf-8')
                conn.sendall(packet)
        else:
            print("[-] Invalid Handshake stating! Closing connection.")
except Exception as e:
    print(e)
    
tcpsock.close()
