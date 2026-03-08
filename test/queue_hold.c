#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <stdint.h> 
#include <libnetfilter_queue/libnetfilter_queue.h>
#include <linux/netfilter.h>

/*  异常场景测试阻塞某个队列
gcc queue_hold.c -o queue_hold -lnetfilter_queue
sudo ./queue_hold 2
cat /proc/net/netfilter/nfnetlink_queue

*/

static struct nfq_handle *h = NULL;
static struct nfq_q_handle *qh = NULL;

static void cleanup(int sig) {
    (void)sig;
    if (qh) nfq_destroy_queue(qh);
    if (h) nfq_close(h);
    fprintf(stderr, "queue_hold: cleaned up\n");
    exit(0);
}

static int cb(struct nfq_q_handle *qh_, struct nfgenmsg *nfmsg, struct nfq_data *nfa, void *data) {
    (void)qh_; (void)nfmsg; (void)nfa; (void)data;
    // 仅占用队列，不消费包
    return 0;
}

int main(int argc, char **argv) {
    int qid = 2;
    if (argc > 1) qid = atoi(argv[1]);

    signal(SIGINT, cleanup);
    signal(SIGTERM, cleanup);

    h = nfq_open();
    if (!h) {
        fprintf(stderr, "nfq_open failed\n");
        return 1;
    }

    nfq_unbind_pf(h, AF_INET);
    if (nfq_bind_pf(h, AF_INET) < 0) {
        fprintf(stderr, "nfq_bind_pf(AF_INET) failed: %s\n", strerror(errno));
        nfq_close(h);
        return 1;
    }

    qh = nfq_create_queue(h, (uint16_t)qid, &cb, NULL);
    if (!qh) {
        fprintf(stderr, "nfq_create_queue(%d) failed: %s\n", qid, strerror(errno));
        nfq_close(h);
        return 1;
    }

    if (nfq_set_mode(qh, NFQNL_COPY_PACKET, 0xffff) < 0) {
        fprintf(stderr, "nfq_set_mode failed: %s\n", strerror(errno));
        cleanup(0);
    }

    fprintf(stderr, "queue_hold: holding queue %d. PID=%d\n", qid, getpid());
    while (1) pause();
    return 0;
}

