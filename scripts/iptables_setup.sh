#!/bin/bash

# 规则：将发往8000,8080,16285端口的UDP包引导到NFQUEUE 0:3进行负载均衡
PORT="8000,8080,16285"

# 清空原有规则   
#iptables -t mangle -F

# 设置NFQUEUE
#iptables -t mangle -A PREROUTING -p udp --dport $PORT -j NFQUEUE --queue-balance 0:3 --queue-bypass
iptables -t mangle -A PREROUTING -p udp -m multiport --dports $PORT -j NFQUEUE --queue-balance 0:3 --queue-bypass

echo "Iptables rules set for UDP port $PORT"



# iptables -t mangle -L -n -v 
