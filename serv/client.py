#client
import socket
import struct

IP = '127.0.0.1'
PORT = 4443
magic = 0x01
PAYLOAD = 'Hello'.encode('utf-8')
length = len(PAYLOAD)
client_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
client_sock.connect((IP, PORT))

header = struct.pack("!BH", magic, length)
packet = header + PAYLOAD
try:
    client_sock.sendall(packet)
    header = client_sock.recv(3)
    _, length = struct.unpack('!BH', header)
    sesi = client_sock.recv(length).decode()
    print(f'[+] session created! My id {sesi}')
    length = len(sesi)
    header = struct.pack('!BH', magic, length)
    pyload = sesi.encode()
    packet = header + pyload
    client_sock.sendall(packet)
    header_data = client_sock.recv(4)
    _, status, length = struct.unpack('!BBH', header_data)
    if status == 1:
        print('I win')
        flag = client_sock.recv(length)
        print(flag.decode())
    else:
        print('I lost')
except Exception as e:
    print(e)

client_sock.close()

    
