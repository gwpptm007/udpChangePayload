# udp_server.py
import socket

# if need
# pip install scapy

sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
#sock.bind(('0.0.0.0', 16285))
sock.bind(('0.0.0.0', 8000))

while True:
    data, addr = sock.recvfrom(1024)
    hex_data = ' '.join('{:02x}'.format(ord(byte)) for byte in data)
    print("Received {} bytes from {}: {}".format(len(data), addr, hex_data))
