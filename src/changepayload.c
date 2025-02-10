#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <linux/netfilter.h>
#include <libnetfilter_queue/libnetfilter_queue.h>
#include <pthread.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>
#include <sys/types.h>
#include <linux/ipv6.h>
#include <linux/version.h>
#include <signal.h>
#include <pthread.h>
#include <errno.h>
#include <semaphore.h>
#include <signal.h>
#include <arpa/inet.h>
#include <sys/file.h>

#include "logging.h"
#define NUM_QUEUES 4
#define DEFAULT_PORTS "8000,8080,8888"


// 全局变量
static __u16 *port_list = NULL;
static int port_count = 0;

static pthread_mutex_t log_mutex = PTHREAD_MUTEX_INITIALIZER;

// PID 文件路径
#define PID_FILE "/tmp/changepayload.pid"

// 文件描述符用于 PID 文件锁定
static int pid_fd = -1;

struct thread_args {
    struct nfq_handle *h;
    int queue_id;
};

static void print_help() {
    printf("Usage: sudo ./changepayload [\"port1,port2,...\"] [log_level]\n");
    printf("No arguments: default ports=%s, log_level=info.\n", DEFAULT_PORTS);
    printf("One argument (e.g. \"8000,8080\"): sets ports, log_level=info.\n");
    printf("Two arguments (e.g. \"7777,8080,8888\" debug): sets ports and log_level.\n");
    printf("log_level: info, error, debug. logfile: /tmp/changepayload.log\n");
    printf("-h or -H: show this help\n");
}

// 必须以root运行检查
static void check_root() {
    if (getuid() != 0) {
        fprintf(stderr, "This program must be run as root!\n");
        fflush(stderr);
        exit(1);
    }
}

// 单实例运行检查，使用 PID 文件和 flock
void ensure_single_instance() {
    pid_fd = open(PID_FILE, O_RDWR | O_CREAT, 0644);
    if (pid_fd < 0) {
        fprintf(stderr, "Failed to open PID file %s: %s\n", PID_FILE, strerror(errno));
        exit(1);
    }

    // 尝试锁定 PID 文件
    if (flock(pid_fd, LOCK_EX | LOCK_NB) == -1) {
        if (errno == EWOULDBLOCK) {
            // 锁定失败，读取 PID 文件中的 PID
            char pid_buf[16];
            ssize_t len = read(pid_fd, pid_buf, sizeof(pid_buf) - 1);
            if (len > 0) {
                pid_buf[len] = '\0';
                pid_t pid = atoi(pid_buf);
                if (pid > 0) {
                    // 检查进程是否存在
                    if (kill(pid, 0) == 0) {
                        fprintf(stderr, "Another instance of changepayload is running (PID %d).\n", pid);
                        LOG_ERR("Another instance of changepayload is running (PID %d).", pid);
                        close(pid_fd);
                        exit(1);
                    }
                }
            }
            // 无效 PID，认为 PID 文件是陈旧的，清理并重新锁定
            fprintf(stderr, "Stale PID file found. Cleaning up.\n");
            LOG_ERR("Stale PID file found. Cleaning up.");
            // 清理 PID 文件
            ftruncate(pid_fd, 0);
            lseek(pid_fd, 0, SEEK_SET);
            // 再次尝试锁定
            if (flock(pid_fd, LOCK_EX | LOCK_NB) == -1) {
                fprintf(stderr, "Failed to acquire lock on PID file.\n");
                LOG_ERR("Failed to acquire lock on PID file.");
                close(pid_fd);
                exit(1);
            }
        } else {
            fprintf(stderr, "Failed to lock PID file: %s\n", strerror(errno));
            LOG_ERR("Failed to lock PID file: %s", strerror(errno));
            close(pid_fd);
            exit(1);
        }
    }

    // 不在此阶段写入 PID 文件
    // 守护进程化后由守护进程写入 PID
}

// 信号处理函数，用于正常终止时清理 PID 文件
void handle_signal(int sig) {
    if (pid_fd != -1) {
        // 删除 PID 文件
        unlink(PID_FILE);
        // 关闭文件描述符
        close(pid_fd);
    }
    exit(0);
}

void setup_signal_handler() {
    struct sigaction sa;
    sa.sa_handler = handle_signal;
    sa.sa_flags = 0; // 不使用 SA_RESTART
    sigemptyset(&sa.sa_mask);

    // 捕获 SIGTERM 和 SIGINT 信号
    if (sigaction(SIGTERM, &sa, NULL) == -1) {
        perror("sigaction");
        exit(1);
    }
    if (sigaction(SIGINT, &sa, NULL) == -1) {
        perror("sigaction");
        exit(1);
    }
}


// UDP校验和计算(IPv4)
// static uint16_t udp_checksum_ipv4(const struct iphdr *iph, const struct udphdr *udph, int udp_len) {
//     // udp_len为UDP头+payload长度（网络序已转化为主机序的值）
//     // 确保使用ntohs(udp_len)获得主机序长度，并在求和时使用正确的值。
//     uint32_t sum = 0;
//     const uint16_t *src = (const uint16_t*)&iph->saddr;
//     const uint16_t *dst = (const uint16_t*)&iph->daddr;

//     // 伪首部加和
//     sum += src[0]; sum += src[1];
//     sum += dst[0]; sum += dst[1];
//     sum += htons(IPPROTO_UDP);
//     sum += htons((uint16_t)udp_len);

//     // UDP 头部和数据求和
//     const uint16_t *udp_ptr = (const uint16_t *)udph;
//     int nwords = udp_len / 2;
//     for (int i = 0; i < nwords; i++) {
//         sum += udp_ptr[i];
//     }
//     // 若长度为奇数，补齐最后一个字节
//     if (udp_len & 1) {
//         sum += ((const uint8_t*)udph)[udp_len - 1] << 8;
//     }

//     while (sum >> 16) sum = (sum & 0xffff) + (sum >> 16);
//     return (uint16_t)(~sum);
// }

/** 
static uint16_t udp_checksum_ipv4(const struct iphdr *iph, const struct udphdr *udph, int udp_len) {
    uint32_t sum = 0;

    // IP地址作为16位字加和
    const uint16_t *src = (const uint16_t*)&iph->saddr;
    const uint16_t *dst = (const uint16_t*)&iph->daddr;
    sum += src[0]; sum += src[1];
    sum += dst[0]; sum += dst[1];

    // 协议和UDP长度(网络序添加)
    sum += htons(IPPROTO_UDP);
    // udph->len是网络序的UDP长度字段
    sum += udph->len;

    // UDP头和payload
    const uint16_t *udp_ptr = (const uint16_t*)udph;
    int words = udp_len / 2;
    for (int i = 0; i < words; i++) sum += udp_ptr[i];
    if (udp_len & 1) {
        sum += ((const uint8_t*)udph)[udp_len-1]<<8;
    }

    return checksum_fold(sum);
}
*/

static uint16_t checksum_fold(uint32_t sum) {
    while (sum >> 16) sum = (sum & 0xffff) + (sum >> 16);
    return (uint16_t)(~sum);
}

static uint16_t calculate_ip_checksum(struct iphdr *iph) {
    iph->check = 0;
    int nwords = iph->ihl * 2;
    uint32_t sum = 0;
    uint16_t *buf = (uint16_t*)iph;
    for (int i = 0; i < nwords; i++) sum += buf[i];
    return checksum_fold(sum);
}


// UDP校验和计算(IPv6)
static uint16_t udp_checksum_ipv6(struct ipv6hdr *ip6h, struct udphdr *udph, int udp_len) {
    uint32_t sum = 0;
    uint16_t *src = (uint16_t*)&ip6h->saddr;
    uint16_t *dst = (uint16_t*)&ip6h->daddr;
    for (int i = 0; i < 8; i++) sum += src[i];
    for (int i = 0; i < 8; i++) sum += dst[i];

    sum += htons(udp_len);
    sum += htons(IPPROTO_UDP);

    udph->check = 0;
    uint16_t *udp_ptr = (uint16_t*)udph;
    for (int i = 0; i < udp_len/2; i++) sum += udp_ptr[i];
    if (udp_len & 1) sum += ((uint8_t*)udph)[udp_len - 1] << 8;

    while (sum >> 16) sum = (sum & 0xffff) + (sum >> 16);
    return (uint16_t)(~sum);
}

static log_level_t str_to_level(const char *s) {
    if (strcmp(s, "info") == 0) return LOG_LEVEL_INFO;
    if (strcmp(s, "error") == 0) return LOG_LEVEL_ERROR;
    if (strcmp(s, "debug") == 0) return LOG_LEVEL_DEBUG;
    return LOG_LEVEL_INFO;
}

static void print_packet_hex(const unsigned char *packet, int len) {
    if (log_get_level() == LOG_LEVEL_DEBUG) {
        pthread_mutex_lock(&log_mutex);  // 加锁
        // 打印到日志文件
        char line[128];
        int idx = 0;
        for (int i = 0; i < len; i++) {
            idx += snprintf(line+idx, sizeof(line)-idx, "%02x ", packet[i]);
            if ((i + 1) % 16 == 0) {
                LOG_DEBUG("%s", line);
                idx = 0;
            }
        }
        if (len % 16 != 0 && idx > 0) {
            LOG_DEBUG("%s", line);
        }

        pthread_mutex_unlock(&log_mutex);  // 解锁
    }
}

static int parse_ports(const char *port_str) {
    if (!port_str || strlen(port_str) == 0) {
        LOG_ERR("No ports specified");
        return -1;
    }

    char *copy = strdup(port_str);
    if (!copy) {
        LOG_ERR("Memory allocation failed");
        return -1;
    }

    int count = 0;
    {
        char *p = copy;
        char *token;
        while ((token = strsep(&p, ",")) != NULL) {
            if (*token == '\0') continue;
            count++;
        }
    }

    if (count == 0) {
        LOG_ERR("No valid ports in %s", port_str);
        free(copy);
        return -1;
    }

    port_list = malloc(sizeof(__u16) * count);
    if (!port_list) {
        LOG_ERR("Memory allocation failed for port_list");
        free(copy);
        return -1;
    }

    {
        char *p2 = strdup(port_str);
        char *pp = p2;
        char *token;
        int idx = 0;
        while ((token = strsep(&pp, ",")) != NULL) {
            if (*token == '\0') continue;
            unsigned long port = strtoul(token, NULL, 10);
            if (port == 0 || port > 65535) {
                LOG_ERR("Invalid port: %s", token);
                free(copy);
                free(p2);
                free(port_list);
                return -1;
            }
            port_list[idx++] = (__u16)port;
        }
        port_count = idx;
        free(p2);
    }

    free(copy);
    LOG_INFO("Parsed %d ports: %s", port_count, port_str);
    return 0;
}

static int is_target_port(__u16 dest_port) {
    for (int i = 0; i < port_count; i++) {
        if (dest_port == port_list[i]) return 1;
    }
    return 0;
}

// 后台运行
static void daemonize() {
    pid_t pid = fork();
    if (pid < 0) {
        perror("fork failed");
        exit(1);
    }
    if (pid > 0) exit(0);

    if (setsid() < 0) {
        perror("setsid failed");
        exit(1);
    }

    pid = fork();
    if (pid < 0) exit(1);
    if (pid > 0) exit(0);

    umask(0);
    chdir("/");

    int fd = open("/dev/null", O_RDWR);
    if (fd >= 0) {
        dup2(fd, STDIN_FILENO);
        dup2(fd, STDOUT_FILENO);
        dup2(fd, STDERR_FILENO);
        if (fd > STDERR_FILENO) close(fd);
    }
}

// 回调函数处理数据包
static int cb(struct nfq_q_handle *qh, struct nfgenmsg *nfmsg,
              struct nfq_data *nfa, void *data) {
    struct nfqnl_msg_packet_hdr *ph = nfq_get_msg_packet_hdr(nfa);
    if (!ph) return NF_ACCEPT;

    u_int32_t id = ntohl(ph->packet_id);

    unsigned char *payload;
    int len = nfq_get_payload(nfa, &payload);
    if (len <= 0) return NF_ACCEPT;

    uint8_t ip_version = payload[0] >> 4;
    int append_len = 0;
    unsigned char *packet_data = NULL;
    int packet_len = len;

    if (ip_version == 4) {
        struct iphdr *iph = (struct iphdr *)payload;
        if (iph->protocol != IPPROTO_UDP) return NF_ACCEPT;

        struct udphdr *udph = (struct udphdr *)(payload + iph->ihl * 4);
        if ((unsigned char *)(udph + 1) > payload + len) return NF_ACCEPT;

        __u16 dest_port = ntohs(udph->dest);
        if (!is_target_port(dest_port)) return NF_ACCEPT;

        __be32 src_ip = iph->saddr;
        char ip_str[INET_ADDRSTRLEN]; 
        if (!inet_ntop(AF_INET, &src_ip, ip_str, sizeof(ip_str))) {
            LOG_ERR("inet_ntop IPv4 failed");
            return NF_ACCEPT;
        }
        // 计算追加长度：'(' + ip_str + ')' 
        append_len = 1 + (int)strlen(ip_str) + 1; // '('  + ip_str长度 + ')'


        packet_len = len + append_len;
        packet_data = malloc(packet_len);
        if (!packet_data) {
            LOG_ERR("Memory allocation failed");
            return NF_ACCEPT;
        }
        memcpy(packet_data, payload, len);

        int udp_payload_len = ntohs(udph->len) - sizeof(struct udphdr);
        unsigned char *udp_payload = packet_data + iph->ihl * 4 + sizeof(struct udphdr);
        udp_payload += udp_payload_len;
        // 二进制格式添加注释
        // udp_payload[0] = 0x28;
        // memcpy(udp_payload + 1, &src_ip, 4);
        // udp_payload[1+4] = 0x29;

        // 添加 '('
        *udp_payload = 0x28; 
        udp_payload++;

        // 添加 ip_str
        memcpy(udp_payload, ip_str, strlen(ip_str));
        udp_payload += strlen(ip_str);

        // 添加 ')'
        *udp_payload = 0x29;

        struct iphdr *new_iph = (struct iphdr *)packet_data;
        struct udphdr *new_udph = (struct udphdr *)(packet_data + new_iph->ihl * 4);
        new_udph->len = htons(ntohs(new_udph->len) + append_len);

        // 重算IP校验和
        new_iph->tot_len = htons(ntohs(new_iph->tot_len) + append_len);
        new_iph->check = calculate_ip_checksum(new_iph);

        // 重算UDP校验和  
        // 2024-12-10 此处udp_checksum_ipv4计算的不对，先设置为0处理
        //int new_udp_len = ntohs(new_udph->len);
        //new_udph->check = udp_checksum_ipv4(new_iph, new_udph, new_udp_len);
        new_udph->check = 0;

        LOG_DEBUG("Modified IPv4 packet id=%u, append_len=%d", id, append_len);
        print_packet_hex(packet_data, packet_len);

    } else if (ip_version == 6) {
        struct ipv6hdr *ip6h = (struct ipv6hdr *)payload;
        if (ip6h->nexthdr != IPPROTO_UDP) return NF_ACCEPT;
        struct udphdr *udph = (struct udphdr *)(payload + sizeof(struct ipv6hdr));
        if ((unsigned char *)(udph + 1) > payload + len) return NF_ACCEPT;

        __u16 dest_port = ntohs(udph->dest);
        if (!is_target_port(dest_port)) return NF_ACCEPT;

        struct in6_addr src_addr = ip6h->saddr;
        char ip_str[INET6_ADDRSTRLEN];
        if (!inet_ntop(AF_INET6, &src_addr, ip_str, sizeof(ip_str))) {
            LOG_ERR("inet_ntop IPv6 failed");
            return NF_ACCEPT;
        }

        //append_len = 1 + 16 + 1;
        append_len = 1 + (int)strlen(ip_str) + 1; // '('  + ip_str长度 + ')'

        packet_len = len + append_len;
        packet_data = malloc(packet_len);
        if (!packet_data) {
            LOG_ERR("Memory allocation failed");
            return NF_ACCEPT;
        }
        memcpy(packet_data, payload, len);

        int udp_payload_len = ntohs(udph->len) - sizeof(struct udphdr);
        unsigned char *udp_payload = packet_data + sizeof(struct ipv6hdr) + sizeof(struct udphdr);
        udp_payload += udp_payload_len;

        // udp_payload[0] = 0x28;
        // memcpy(udp_payload + 1, &src_addr, 16);
        // udp_payload[1+16] = 0x29;

        // '('
        *udp_payload = 0x28;
        udp_payload++;

        memcpy(udp_payload, ip_str, strlen(ip_str));
        udp_payload += strlen(ip_str);

        // ')'
        *udp_payload = 0x29;

        struct ipv6hdr *new_ip6h = (struct ipv6hdr *)packet_data;
        struct udphdr *new_udph = (struct udphdr *)(packet_data + sizeof(struct ipv6hdr));
        new_udph->len = htons(ntohs(new_udph->len) + append_len);

        // 更新IPv6 payload_len
        new_ip6h->payload_len = htons(ntohs(new_ip6h->payload_len) + append_len);

        int new_udp_len = ntohs(new_udph->len);
        new_udph->check = udp_checksum_ipv6(new_ip6h, new_udph, new_udp_len);

        LOG_DEBUG("Modified IPv6 packet id=%u, append_len=%d", id, append_len);
        print_packet_hex(packet_data, packet_len);

    } else {
        return NF_ACCEPT;
    }

    int ret = nfq_set_verdict(qh, id, NF_ACCEPT, packet_len, packet_data);
    free(packet_data);
    return ret;
}

void* process_queue(void* arg) {
    struct thread_args *args = (struct thread_args *)arg;
    struct nfq_handle *h = args->h;
    int queue_id = args->queue_id;

    struct nfq_q_handle *qh = nfq_create_queue(h, queue_id, &cb, &args->queue_id);
    if (!qh) {
        LOG_ERR("Error creating queue %d", queue_id);
        return NULL;
    }
    nfq_set_mode(qh, NFQNL_COPY_PACKET, 0xffff);
    LOG_INFO("Thread for Queue %d started", queue_id);

    int fd = nfq_fd(h);
    char buf[1500];

    while (1) {
        int rv = recv(fd, buf, sizeof(buf), 0);
        if (rv >= 0) {
            nfq_handle_packet(h, buf, rv);
        } else {
            if (errno == EINTR) continue;
            LOG_ERR("recv failed: %s", strerror(errno));
            break;
        }
    }

    nfq_destroy_queue(qh);
    return NULL;
}

int main(int argc, char *argv[]) {

    check_root();

    const char *port_str = DEFAULT_PORTS;
    log_level_t level = LOG_LEVEL_INFO;

    // 参数解析
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-h") == 0 || strcmp(argv[i], "-H") == 0) {
            print_help();
            return 0;
        }
    }

    if (argc > 1) {
        port_str = argv[1];
    }

    if (argc > 2) {
        level = str_to_level(argv[2]);
    }

    log_init(level);

    // 设置信号处理器
    setup_signal_handler();

    //单实例
    ensure_single_instance();

    // 后台化运行
    daemonize();

    // 现在处于守护进程中，写入守护进程的 PID 到 PID 文件
    char pid_str[16];
    snprintf(pid_str, sizeof(pid_str), "%ld\n", (long)getpid());

    // 清空 PID 文件并写入新的 PID
    if (ftruncate(pid_fd, 0) != 0) {
        LOG_ERR("Failed to truncate PID file: %s", strerror(errno));
        unlink(PID_FILE);
        close(pid_fd);
        exit(1);
    }
    if (lseek(pid_fd, 0, SEEK_SET) == -1) {
        LOG_ERR("Failed to seek PID file: %s", strerror(errno));
        unlink(PID_FILE);
        close(pid_fd);
        exit(1);
    }
    ssize_t written = write(pid_fd, pid_str, strlen(pid_str));
    if (written != (ssize_t)strlen(pid_str)) {
        LOG_ERR("Failed to write full PID to PID file: %s", strerror(errno));
        unlink(PID_FILE);
        close(pid_fd);
        exit(1);
    }
    // 强制刷新到磁盘
    fsync(pid_fd);

    // 记录守护进程启动信息
    LOG_INFO("ChangPayload daemon started with PID %ld", (long)getpid());

    if (parse_ports(port_str) < 0) {
        LOG_ERR("Failed to parse ports");
        // 清理 PID 文件
        unlink(PID_FILE);
        close(pid_fd);
        return 1;
    }

    struct nfq_handle *h = nfq_open();
    if (!h) {
        LOG_ERR("nfq_open() failed");
        // 清理 PID 文件
        unlink(PID_FILE);
        close(pid_fd);
        return 1;
    }

    if (nfq_unbind_pf(h, AF_INET) < 0) {
        LOG_ERR("nfq_unbind_pf() failed");
        nfq_close(h);
        // 清理 PID 文件
        unlink(PID_FILE);
        close(pid_fd);
        return 1;
    }
    if (nfq_bind_pf(h, AF_INET) < 0) {
        LOG_ERR("nfq_bind_pf() failed");
        nfq_close(h);
        // 清理 PID 文件
        unlink(PID_FILE);
        close(pid_fd);
        return 1;
    }

    pthread_t threads[NUM_QUEUES];
    struct thread_args args[NUM_QUEUES];

    int success_queues = 0;
    for (int i = 0; i < NUM_QUEUES; i++) {
        args[i].h = h;
        args[i].queue_id = i;
        if (pthread_create(&threads[i], NULL, process_queue, (void*)&args[i]) == 0) {
            success_queues++;
        } else {
            LOG_ERR("Failed to create thread for queue %d", i);
        }
    }

    if (success_queues == 0) {
        LOG_ERR("No queues successfully started, exiting.");
        nfq_close(h);
        free(port_list);
        // 清理 PID 文件
        unlink(PID_FILE);
        close(pid_fd);
        return 1;
    }

    for (int i = 0; i < NUM_QUEUES; i++) {
        pthread_join(threads[i], NULL);
    }

    nfq_close(h);
    free(port_list);
    //cleanup_single_instance();

    // 清理 PID 文件
    unlink(PID_FILE);
    close(pid_fd);
    log_close();
    return 0;
}