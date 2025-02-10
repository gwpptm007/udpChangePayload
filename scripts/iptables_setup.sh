#!/bin/bash

# 规则：将发往8000,8080,16285端口的UDP包引导到NFQUEUE 0:3进行负载均衡
PORT="8000,8080,8888"

# 删除可能存在的旧规则
iptables -t mangle -D PREROUTING -p udp -m multiport --dports $PORT -j NFQUEUE --queue-balance 0:3 --queue-bypass 2>/dev/null || true

# 设置NFQUEUE
#iptables -t mangle -A PREROUTING -p udp --dport $PORT -j NFQUEUE --queue-balance 0:3 --queue-bypass
iptables -t mangle -A PREROUTING -p udp -m multiport --dports $PORT -j NFQUEUE --queue-balance 0:3 --queue-bypass

echo "Iptables rules set for UDP port $PORT"



# iptables -t mangle -L -n -v 
