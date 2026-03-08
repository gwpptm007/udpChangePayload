# changepayload 项目

## 简介

`changepayload` 是一个用户态程序，通过 **NFQUEUE** 与 **iptables** 的方式对指定端口的入站 UDP 数据包进行修改，在 UDP payload 尾部追加源 IP 信息。程序默认处理端口 `16285,8080,8000`，并提供自定义端口和日志级别的可配置方式。

### 功能特性

1. **用户态执行**：程序以可执行文件方式运行（如：`sudo ./changepayload`）。
2. **端口可配置**：
   - 无参数运行：默认处理 `16285,8080,8000` 三个端口，日志级别为 `info`。
   - 一个参数（如 `sudo ./changepayload "16285,8080"`）：使用指定的端口列表，日志级别仍为 `info`。
   - 两个参数（如 `sudo ./changepayload "16285,8080,8000" debug`）：第一个参数为端口列表，第二个参数为日志级别（`info`, `error`, `debug`）。
3. **日志组件完善**：
   - 默认日志输出到 `/tmp/changepayload.log` 文件。
   - 支持简单的日志轮转（按大小轮转），超过设定大小后重命名日志文件，并重新创建新的日志文件。
   - 程序以后台方式运行（daemonize），ctrl+c 不会终止程序，而是通过kill停止。
4. **IPv4/IPv6 支持**：
   - IPv4数据包：追加 `0x28 + (str)src_ip + 0x29`。
   - IPv6数据包：追加 `0x28 + (str)src_ip + 0x29`。
5. **帮助信息**：`-h` 或 `-H` 显示帮助。

### 多队列多线程
通过 `iptables --queue-balance 0:3` 将数据包分配至4个队列，并启用4个线程并行处理，提升高流量环境下的吞吐量。

**nfq_create_queue 全部创建成功**
- 每个队列使用独立的 `nfq_handle`（避免多线程共享同一个 netlink fd 导致的丢包/创建失败）。
- callback 的任意分支都必须下发 verdict（不修改时使用 `nfq_set_verdict(..., NF_ACCEPT, 0, NULL)` 放行原始包）。
- `recv()` 缓冲区至少 64KB，并尝试增大 netlink socket 的 `SO_RCVBUF`，降低 `user_dropped`。

---

## 目录结构

changepayload/  
├── build.sh  
├── Makefile  
├── README.md  
├── include/  
│   └── logging.h  
├── src/  
│   ├── changepayload.c  
│   └── logging.c  
└── scripts/  
│   ├── iptables_setup.sh  
│   └── run_test.sh  
└── test/  
│   ├── udpsend.py  
│   └── udprecv.py 

- **build.sh**：编译脚本，用于本地编译。
- **Makefile**：编译规则，生成用户态可执行文件 `changepayload`。
- **include/logging.h** 和 **src/logging.c**：日志组件实现，支持日志记录功能。
- **src/changepayload.c**：主程序代码，处理 UDP 数据包并修改 payload。
- **scripts/iptables_setup.sh**：设置 iptables 规则的脚本。
- **test/udpsend.py**：发送udp包到changepayload服务器。
- **test/udprecv.py**：changepayload服务器接收修改后的udp包。
- **README.md**：项目说明文档。

## 环境准备

在编译和运行 `changepayload` 之前，需确保系统具备以下依赖：

```bash
sudo apt-get update
sudo apt-get install -y build-essential libnetfilter-queue-dev
```
build-essential：包含 gcc、make 等编译工具。  
libnetfilter-queue-dev：提供 libnetfilter_queue 库，用于与 NFQUEUE 交互

---

<h2 id="501ce0f6">配置与运行</h2>
<h3 id="1e278cd1">iptables 规则示例</h3>
`iptables_setup.sh` 脚本示例（默认处理 UDP 8000,8080,16285 端口）：

```plain
#!/bin/bash

PORT="8000,8080,16285"
# 设置NFQUEUE
iptables -t mangle -A PREROUTING -p udp -m multiport --dports $PORT -j NFQUEUE --queue-balance 0:3 --queue-bypass
echo "Iptables rules set for UDP port $PORT"

# iptables -t mangle -L -n -v 
```

执行：

```plain
chmod +x scripts/iptables_setup.sh
sudo ./scripts/iptables_setup.sh
```

<h3 id="a2a5fee6">运行程序</h3>
+ 无参数（默认端口 `8000,8080,16285`，日志级别 `info`）：

```plain
sudo ./changepayload
```

+ 指定端口列表,日志默认为 `info`：

```plain
sudo ./changepayload "8000,8888"
```

+ 指定端口列表和日志级别：

```plain
sudo ./changepayload "8000,8888,7777" debug
```

+ 查看帮助：

```plain
sudo ./changepayload -h
Usage: sudo ./changepayload ["port1,port2,..."] [log_level]
No arguments: default ports=8000,8080,16285, log_level=info.
One argument (e.g. "8000,8080"): sets ports, log_level=info.
Two arguments (e.g. "7777,8080,16285" debug): sets ports and log_level.
log_level: info, error, debug. logfile: /tmp/changepayload.log
-h or -H: show this help
```

+ 常见问题处理
```plain
1. 异常退出后，再启动失败报错 Another instance of changepayload is running.
单实例锁卡住的问题
ls -l /dev/shm | grep changepayload
系统会把信号量映射到 /dev/shm 下的文件 /dev/shm/sem.changepayload_sem
删除 sudo rm /dev/shm/sem.changepayload_sem 即可

2. 排查 NFQUEUE 队列是否都被订阅（--queue-balance 0:3 必须 0/1/2/3 都有订阅者）
cat /proc/net/netfilter/nfnetlink_queue

示例：
0  29091     0 2 65531     0     0        0  1
1  29091     0 2 65531     0     0        0  1
2  29091     0 2 65531     0     0        0  1
3  29091     0 2 65531     0     0        0  1

每行代表一个队列，列含义如下：
(1) queue_id：队列号（对应 iptables 的 --queue-num / --queue-balance）
(2) portid：订阅该队列的 netlink port id（通常可用于定位是哪个进程在消费）
(3) queue_total：当前在队列里等待用户态处理的包数量
(4) copy_mode：拷贝模式，1=仅元数据，2=拷贝 payload
(5) copy_range：最多拷贝多少字节到用户态
(6) queue_dropped：内核因队列等待 verdict 的包太多而丢弃的计数（常见原因：用户态处理慢/未下发 verdict）
(7) user_dropped：netlink 子系统丢弃的计数（常见原因：socket buffer 满，用户态收包不够快；可增大 SO_RCVBUF）
(8) id_sequence：最近一次入队的包序号（单调递增）
最后一列恒为 1（兼容字段，可忽略）
```
---