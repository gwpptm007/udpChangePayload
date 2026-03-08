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
#include <time.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <unistd.h>
#include <sys/types.h>
#include <linux/ipv6.h>
#include <linux/version.h>
#include <signal.h>
#include <errno.h>
#include <semaphore.h>


#include "logging.h"
#define NUM_QUEUES 4
#define DEFAULT_PORTS "8000,8080,16285"


// 全局变量
static __u16 *port_list = NULL;
static int port_count = 0;

static pthread_mutex_t log_mutex = PTHREAD_MUTEX_INITIALIZER;

struct thread_args {
    int queue_id;
};

// 队列状态：确保所有队列都成功
static volatile int g_queue_ready[NUM_QUEUES] = {0};
static pthread_mutex_t g_ready_mutex = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t  g_ready_cond  = PTHREAD_COND_INITIALIZER;

static void print_help() {
    printf("Usage: sudo ./changepayload [\"port1,port2,...\"] [log_level]\n");
    printf("No arguments: default ports=%s, log_level=info.\n", DEFAULT_PORTS);
    printf("One argument (e.g. \"8000,8080\"): sets ports, log_level=info.\n");
    printf("Two arguments (e.g. \"7777,8080,16285\" debug): sets ports and log_level.\n");
    printf("log_level: info, error, debug. logfile: /tmp/changepayload.log\n");
    printf("Timeout missing queues: Check /proc/net/netfilter/nfnetlink_queue\n");
    printf("Another instance of changepayload is running. Please sudo rm /dev/shm/sem.changepayload_sem\n");
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

static sem_t *sem;
// 单实例运行
void ensure_single_instance() {
    // 创建一个命名的信号量
    sem = sem_open("/changepayload_sem", O_CREAT, 0644, 1);
    if (sem == SEM_FAILED) {
        perror("sem_open");
        exit(1);
    }

    // 尝试获取信号量
    if (sem_trywait(sem) == -1) {
        if (errno == EAGAIN) {
            // 信号量已被其他实例持有
            fprintf(stderr, "Another instance of changepayload is running.\n");
            LOG_ERR("Another instance of changepayload is running.");
            exit(1);
        } else {
            perror("sem_trywait");
            exit(1);
        }
    }
    // 成功获取信号量，程序可以继续运行
}

void cleanup_single_instance() {
    // 释放信号量
    if (sem_post(sem) == -1) {
        perror("sem_post");
    }

    // 关闭信号量
    if (sem_close(sem) == -1) {
        perror("sem_close");
    }

    // 删除信号量
    if (sem_unlink("/changepayload_sem") == -1) {
        perror("sem_unlink");
    }
}

void signal_handler(int sig) {
    cleanup_single_instance();
    exit(1);
}

void setup_signal_handler() {
    struct sigaction sa;
    sa.sa_handler = signal_handler;
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

static inline int verdict_accept(struct nfq_q_handle *qh, u_int32_t id) {
    // 不修改包场景，len=0, buf=NULL 放行原始包
    return nfq_set_verdict(qh, id, NF_ACCEPT, 0, NULL);
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
    if (!ph) {
        LOG_ERR("nfq_get_msg_packet_hdr() returned NULL");
        return 0;
    }

    u_int32_t id = ntohl(ph->packet_id);

    int queue_id = -1;
    if (data) {
        queue_id = *(int*)data;
    }

    unsigned char *payload;
    int len = nfq_get_payload(nfa, &payload);
    if (len <= 0 || payload == NULL) {
        if (log_get_level() == LOG_LEVEL_DEBUG) {
            LOG_DEBUG("Q%d ACCEPT id=%u at cb:%d", queue_id, id, __LINE__);
        }
        return verdict_accept(qh, id);
}

    uint8_t ip_version = payload[0] >> 4;
    int append_len = 0;
    unsigned char *packet_data = NULL;
    int packet_len = len;

    if (ip_version == 4) {
        struct iphdr *iph = (struct iphdr *)payload;
        if (len < (int)sizeof(struct iphdr)) {
        if (log_get_level() == LOG_LEVEL_DEBUG) {
            LOG_DEBUG("Q%d ACCEPT id=%u at cb:%d", queue_id, id, __LINE__);
        }
        return verdict_accept(qh, id);
}
        if (iph->ihl < 5) {
        if (log_get_level() == LOG_LEVEL_DEBUG) {
            LOG_DEBUG("Q%d ACCEPT id=%u at cb:%d", queue_id, id, __LINE__);
        }
        return verdict_accept(qh, id);
}
        if ((int)(iph->ihl * 4) + (int)sizeof(struct udphdr) > len) {
        if (log_get_level() == LOG_LEVEL_DEBUG) {
            LOG_DEBUG("Q%d ACCEPT id=%u at cb:%d", queue_id, id, __LINE__);
        }
        return verdict_accept(qh, id);
}
        if (iph->protocol != IPPROTO_UDP) {
        if (log_get_level() == LOG_LEVEL_DEBUG) {
            LOG_DEBUG("Q%d ACCEPT id=%u at cb:%d", queue_id, id, __LINE__);
        }
        return verdict_accept(qh, id);
}

        struct udphdr *udph = (struct udphdr *)(payload + iph->ihl * 4);
        if ((unsigned char *)(udph + 1) > payload + len) {
        if (log_get_level() == LOG_LEVEL_DEBUG) {
            LOG_DEBUG("Q%d ACCEPT id=%u at cb:%d", queue_id, id, __LINE__);
        }
        return verdict_accept(qh, id);
}

        __u16 dest_port = ntohs(udph->dest);
        if (!is_target_port(dest_port)) {
        if (log_get_level() == LOG_LEVEL_DEBUG) {
            LOG_DEBUG("Q%d ACCEPT id=%u at cb:%d", queue_id, id, __LINE__);
        }
        return verdict_accept(qh, id);
}

        __be32 src_ip = iph->saddr;
        char ip_str[INET_ADDRSTRLEN]; 
        if (!inet_ntop(AF_INET, &src_ip, ip_str, sizeof(ip_str))) {
            LOG_ERR("inet_ntop IPv4 failed");
        if (log_get_level() == LOG_LEVEL_DEBUG) {
            LOG_DEBUG("Q%d ACCEPT id=%u at cb:%d", queue_id, id, __LINE__);
        }
        return verdict_accept(qh, id);
}
        // 计算追加长度：'(' + ip_str + ')' 
        append_len = 1 + (int)strlen(ip_str) + 1; // '('  + ip_str长度 + ')'


        packet_len = len + append_len;
        packet_data = malloc(packet_len);
        if (!packet_data) {
            LOG_ERR("Memory allocation failed");
        if (log_get_level() == LOG_LEVEL_DEBUG) {
            LOG_DEBUG("Q%d ACCEPT id=%u at cb:%d", queue_id, id, __LINE__);
        }
        return verdict_accept(qh, id);
}
        memcpy(packet_data, payload, len);

        int udp_payload_len = ntohs(udph->len) - sizeof(struct udphdr);
        if (udp_payload_len < 0) {
            free(packet_data);
        if (log_get_level() == LOG_LEVEL_DEBUG) {
            LOG_DEBUG("Q%d ACCEPT id=%u at cb:%d", queue_id, id, __LINE__);
        }
        return verdict_accept(qh, id);
}
        unsigned char *udp_payload = packet_data + iph->ihl * 4 + sizeof(struct udphdr);
        if (udp_payload + udp_payload_len > packet_data + len) {
            free(packet_data);
        if (log_get_level() == LOG_LEVEL_DEBUG) {
            LOG_DEBUG("Q%d ACCEPT id=%u at cb:%d", queue_id, id, __LINE__);
        }
        return verdict_accept(qh, id);
}
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
        if (len < (int)sizeof(struct ipv6hdr) + (int)sizeof(struct udphdr)) {
            LOG_DEBUG("IPv6 packet too short: len=%d", len);
        if (log_get_level() == LOG_LEVEL_DEBUG) {
            LOG_DEBUG("Q%d ACCEPT id=%u at cb:%d", queue_id, id, __LINE__);
        }
        return verdict_accept(qh, id);
}
        if (ip6h->nexthdr != IPPROTO_UDP) {
        if (log_get_level() == LOG_LEVEL_DEBUG) {
            LOG_DEBUG("Q%d ACCEPT id=%u at cb:%d", queue_id, id, __LINE__);
        }
        return verdict_accept(qh, id);
}
        struct udphdr *udph = (struct udphdr *)(payload + sizeof(struct ipv6hdr));
        if ((unsigned char *)(udph + 1) > payload + len) {
        if (log_get_level() == LOG_LEVEL_DEBUG) {
            LOG_DEBUG("Q%d ACCEPT id=%u at cb:%d", queue_id, id, __LINE__);
        }
        return verdict_accept(qh, id);
}

        __u16 dest_port = ntohs(udph->dest);
        if (!is_target_port(dest_port)) {
        if (log_get_level() == LOG_LEVEL_DEBUG) {
            LOG_DEBUG("Q%d ACCEPT id=%u at cb:%d", queue_id, id, __LINE__);
        }
        return verdict_accept(qh, id);
}

        struct in6_addr src_addr = ip6h->saddr;
        char ip_str[INET6_ADDRSTRLEN];
        if (!inet_ntop(AF_INET6, &src_addr, ip_str, sizeof(ip_str))) {
            LOG_ERR("inet_ntop IPv6 failed");
        if (log_get_level() == LOG_LEVEL_DEBUG) {
            LOG_DEBUG("Q%d ACCEPT id=%u at cb:%d", queue_id, id, __LINE__);
        }
        return verdict_accept(qh, id);
}

        //append_len = 1 + 16 + 1;
        append_len = 1 + (int)strlen(ip_str) + 1; // '('  + ip_str长度 + ')'

        packet_len = len + append_len;
        packet_data = malloc(packet_len);
        if (!packet_data) {
            LOG_ERR("Memory allocation failed");
        if (log_get_level() == LOG_LEVEL_DEBUG) {
            LOG_DEBUG("Q%d ACCEPT id=%u at cb:%d", queue_id, id, __LINE__);
        }
        return verdict_accept(qh, id);
}
        memcpy(packet_data, payload, len);

        int udp_payload_len = ntohs(udph->len) - sizeof(struct udphdr);
        if (udp_payload_len < 0) {
            free(packet_data);
        if (log_get_level() == LOG_LEVEL_DEBUG) {
            LOG_DEBUG("Q%d ACCEPT id=%u at cb:%d", queue_id, id, __LINE__);
        }
        return verdict_accept(qh, id);
}
        unsigned char *udp_payload = packet_data + sizeof(struct ipv6hdr) + sizeof(struct udphdr);
        if (udp_payload + udp_payload_len > packet_data + len) {
            free(packet_data);
        if (log_get_level() == LOG_LEVEL_DEBUG) {
            LOG_DEBUG("Q%d ACCEPT id=%u at cb:%d", queue_id, id, __LINE__);
        }
        return verdict_accept(qh, id);
}
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
        if (log_get_level() == LOG_LEVEL_DEBUG) {
            LOG_DEBUG("Q%d ACCEPT id=%u at cb:%d", queue_id, id, __LINE__);
        }
        return verdict_accept(qh, id);
}

    // 修改成功：带 payload 下发
    int ret = nfq_set_verdict(qh, id, NF_ACCEPT, packet_len, packet_data);
    free(packet_data);
    return ret;
}

void* process_queue(void* arg) {
    struct thread_args *args = (struct thread_args *)arg;
    int queue_id = args->queue_id;

    // 每个队列一个独立 nfq_handle，避免多线程共享 fd/handle 引起的丢包/创建失败
    struct nfq_handle *h = NULL;
    struct nfq_q_handle *qh = NULL;

    for (;;) {
        h = nfq_open();
        if (h) break;
        LOG_ERR("nfq_open() failed for queue %d, retrying...", queue_id);
        sleep(1);
    }

    // 绑定 PF_INET（iptables PREROUTING 使用 IPv4）
    nfq_unbind_pf(h, AF_INET); // 忽略返回值：有的环境可能没绑定过
    if (nfq_bind_pf(h, AF_INET) < 0) {
        LOG_ERR("nfq_bind_pf(AF_INET) failed for queue %d", queue_id);
        nfq_close(h);
        return NULL;
    }

    // 保证nfq_create_queue都成功，否则会导致 queue 上的流量无法转发
    for (int attempt = 1; attempt <= 30; attempt++) {
        qh = nfq_create_queue(h, queue_id, &cb, &args->queue_id);
        if (qh) break;
        LOG_ERR("Error creating queue %d (attempt %d/30), retrying...", queue_id, attempt);
        sleep(1);
    }
    if (!qh) {
        LOG_ERR("Error creating queue %d, giving up.", queue_id);
        nfq_close(h);
        return NULL;
    }
    nfq_set_mode(qh, NFQNL_COPY_PACKET, 0xffff);

    // 标记队列已就绪
    pthread_mutex_lock(&g_ready_mutex);
    g_queue_ready[queue_id] = 1;
    pthread_cond_broadcast(&g_ready_cond);
    pthread_mutex_unlock(&g_ready_mutex);

    LOG_INFO("Thread for Queue %d started", queue_id);

    int fd = nfq_fd(h);

    // 增大 netlink socket 缓冲，降低 user_dropped
    int rcvbuf = 1 * 1024 * 1024;
    (void)setsockopt(fd, SOL_SOCKET, SO_RCVBUF, &rcvbuf, sizeof(rcvbuf));

    unsigned char buf[65536];

    while (1) {
        int rv = recv(fd, buf, sizeof(buf), 0);
        if (rv < 0) {
            if (errno == EINTR) continue;
            LOG_ERR("recv() failed on queue %d: %s", queue_id, strerror(errno));
            continue;
        }
        if (rv == 0) continue;

        if (nfq_handle_packet(h, (char*)buf, rv) < 0) {
            LOG_ERR("nfq_handle_packet() failed on queue %d", queue_id);
        }
    }

    nfq_destroy_queue(qh);
    nfq_close(h);
    return NULL;
}

int main(int argc, char *argv[]) {

    check_root();

    const char *port_str=DEFAULT_PORTS;
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

    //单实例 信号量
    setup_signal_handler();
    ensure_single_instance();

    if (parse_ports(port_str) < 0) {
        LOG_ERR("Failed to parse ports");
        return 1;
    }

    // 后台化运行
    daemonize();

    pthread_t threads[NUM_QUEUES];
    struct thread_args args[NUM_QUEUES];

    int success_queues = 0;
    for (int i = 0; i < NUM_QUEUES; i++) {
        args[i].queue_id = i;
        if (pthread_create(&threads[i], NULL, process_queue, (void*)&args[i]) == 0) {
            success_queues++;
        } else {
            LOG_ERR("Failed to create thread for queue %d", i);
        }
    }

    if (success_queues == 0) {
        LOG_ERR("No queues successfully started, exiting.");
        free(port_list);
        return 1;
    }

    // 等待所有队列都成功创建（否则退出进程）
    //   - 每个队列线程在成功执行 nfq_open/nfq_bind_pf/nfq_create_queue/nfq_set_mode 后，
    //     将 g_queue_ready[queue_id] 置为 1，并 pthread_cond_broadcast(&g_ready_cond) 唤醒主线程。
    //   - 主线程在创建完 0..NUM_QUEUES-1 的线程后，使用 pthread_cond_timedwait() 等待，
    //     直到 g_queue_ready[] 全部为 1（或超时）。
    // 不成功场景分析：
    //   现场 iptables 一般用 --queue-balance 0:3，内核会把不同 flow hash 到 0..3 的不同队列。
    //   如果某个队列没有被成功消费，则 hash 到该队列的包会：
    //     1) 没有 --queue-bypass：卡在队列里，队列满后被内核丢弃（表现为部分用户包不转发/丢包）；
    //     2) 有 --queue-bypass：绕过 NFQUEUE 放行原包（表现为部分用户包不修改）。
    //   超时未全部 ready -> 记录缺失队列并退出进程，避免长时间部分用户稳定异常。
    {
        struct timespec ts;
        clock_gettime(CLOCK_REALTIME, &ts);
        ts.tv_sec += 30;

        pthread_mutex_lock(&g_ready_mutex);
        while (1) {
            int all_ready = 1;
            for (int i = 0; i < NUM_QUEUES; i++) {
                if (!g_queue_ready[i]) { all_ready = 0; break; }
            }
            if (all_ready) {
                pthread_mutex_unlock(&g_ready_mutex);
                LOG_INFO("All %d queues subscribed successfully", NUM_QUEUES);
                break;
            }

            int rc = pthread_cond_timedwait(&g_ready_cond, &g_ready_mutex, &ts);
            if (rc == ETIMEDOUT) {
                pthread_mutex_unlock(&g_ready_mutex);
                {
                    char miss[64] = {0};
                    int off = 0;
                    for (int i = 0; i < NUM_QUEUES; i++) {
                        if (!g_queue_ready[i]) {
                            off += snprintf(miss + off, sizeof(miss) - off, "%s%d", (off ? "," : ""), i);
                        }
                    }
                    LOG_ERR("Timeout waiting for queues. Missing queues: [%s]. Check /proc/net/netfilter/nfnetlink_queue",
                            miss[0] ? miss : "none");
                }
                free(port_list);
                cleanup_single_instance();
                log_close();
                return 1;
            }
        }
    }

    for (int i = 0; i < NUM_QUEUES; i++) {
        pthread_join(threads[i], NULL);
    }

    free(port_list);
    cleanup_single_instance();
    log_close();
    return 0;
}