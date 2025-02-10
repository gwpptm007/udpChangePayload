# udp_server.py
import socket

# if need
# pip install scapy

packet_count = 0

sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
#sock.bind(('0.0.0.0', 16285))
sock.bind(('0.0.0.0', 8000))

while True:
    data, addr = sock.recvfrom(1024)
    hex_data = ' '.join('{:02x}'.format(ord(byte)) for byte in data)
    packet_count += 1
    print("Received packet #{} ({}) bytes from {}: {}".format(packet_count, len(data), addr, hex_data))
