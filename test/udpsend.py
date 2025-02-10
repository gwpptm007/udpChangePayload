'''
Author: wangqi wangqi@zhizhangyi.com
Date: 2024-12-10 18:29:18
LastEditors: wangqi wangqi@zhizhangyi.com
LastEditTime: 2024-12-18 17:14:36
FilePath: \1210\udp.py
Description: 这是默认设置,请设置`customMade`, 打开koroFileHeader查看配置 进行设置: https://github.com/OBKoro1/koro1FileHeader/wiki/%E9%85%8D%E7%BD%AE
'''
#!/usr/bin/python
# -*- coding: <encoding name> -*-
import socket
import time

udp_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
#target_host = "127.0.0.1"
target_host = "172.16.70.20"
#target_port = 16285
target_port = 8000

for i in range(1):

    message = "Hello, UDP!"
    bytes_sent = udp_socket.sendto(message.encode(), (target_host, target_port))
    #print(f"Sent {bytes_sent} bytes to {target_host}:{target_port}")
    print("send udp packet to changepayload test")
    time.sleep(2)

udp_socket.close()
