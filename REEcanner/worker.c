/*
 * REEcanner - C packet worker
 * compila: gcc -O3 -march=native -flto -fPIC -shared -o worker.so worker.c
 * TODO: implement packet worker no C :p
 */
#define _GNU_SOURCE
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <sched.h>
#include <signal.h>
#include <errno.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <linux/if_packet.h>
#include <net/if.h>
#include <net/ethernet.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#define likely(x)   __builtin_expect(!!(x), 1)
#define unlikely(x) __builtin_expect(!!(x), 0)

// feistel cifra 

static inline __attribute__((always_inline))
uint32_t fround(uint32_t r, uint32_t k, uint32_t mask) {
    uint32_t v = (r ^ k) & mask;
    v = v * 0x41C64E6DU + 0x3039U;
    return (v ^ (v >> 8)) & mask;
}

static inline __attribute__((always_inline))
uint32_t fencrypt(uint32_t idx, const uint32_t k[4], int half_bits, uint32_t mask) {
    uint32_t l = (idx >> half_bits) & mask, r = idx & mask, t;
    t=r; r=l^fround(r,k[0],mask); l=t;
    t=r; r=l^fround(r,k[1],mask); l=t;
    t=r; r=l^fround(r,k[2],mask); l=t;
    t=r; r=l^fround(r,k[3],mask); l=t;
    return (r << half_bits) | l;
}

static inline __attribute__((always_inline))
uint32_t fget(uint32_t idx, const uint32_t k[4], uint64_t max_val, int half_bits, uint32_t mask) {
    uint32_t x = fencrypt(idx, k, half_bits, mask);
    while (unlikely(x >= max_val)) x = fencrypt(x, k, half_bits, mask);
    return x;
}

// binary blacklist

static inline __attribute__((always_inline))
int is_public(uint32_t ip, const uint32_t *bl, int bl_len) {
    int lo = 0, hi = bl_len;
    while (lo < hi) {
        int mid = (lo + hi) >> 1;
        if (bl[mid] <= ip) lo = mid + 1; else hi = mid;
    }
    if (lo & 1) return 0;
    if (lo < bl_len && bl[lo] == ip) return 0;
    return 1;
}

// lookup  da network

static inline __attribute__((always_inline))
uint32_t get_ip(uint32_t shuf_idx, const uint32_t *bases, const uint32_t *starts,
                int nets_len, int single) {
    if (likely(single)) return bases[0] + shuf_idx;
    int lo = 0, hi = nets_len;
    while (lo < hi) {
        int mid = (lo + hi) >> 1;
        if (starts[mid] <= shuf_idx) lo = mid + 1; else hi = mid;
    }
    int i = lo - 1;
    return bases[i] + (shuf_idx - starts[i]);
}

// clock monotonic 

static inline uint64_t now_ns(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000000000ULL + (uint64_t)ts.tv_nsec;
}

// main worker entry point 

void run_worker(
    int worker_id,
    const uint8_t *src_ip,          /* 4 bytes network order */
    const uint16_t *ports, int ports_len,
    uint16_t src_port,
    int rate_limit,                 /* per-worker pps */
    const uint32_t *bl, int bl_len,
    const uint32_t *fkeys,          /* 4 feistel keys */
    uint64_t total_ips,
    const uint32_t *net_bases,
    const uint32_t *net_starts,
    int nets_len, int single_net,
    volatile int *run_flag,         /* shared: 1=run 0=stop */
    volatile uint64_t *pps_ptr,     /* &pps_array[worker_id] */
    volatile uint64_t *sent_ptr,    /* &sent_array[worker_id] */
    const char *iface,              /* null = use SOCK_RAW */
    const uint8_t *lmac,            /* 6 bytes (null if !iface) */
    const uint8_t *gmac,            /* 6 bytes (null if !iface) */
    int total_workers,
    int64_t start_index,
    int shards, int shard_id,
    int batch_size,
    int half_bits,
    uint32_t feistel_mask,
    int retries,
    int is_udp
) {
    signal(SIGINT, SIG_IGN);

    // cpu afinity

    int ncpu = sysconf(_SC_NPROCESSORS_ONLN);
    if (ncpu > 0) {
        cpu_set_t cpuset;
        CPU_ZERO(&cpuset);
        CPU_SET(worker_id % ncpu, &cpuset);
        sched_setaffinity(0, sizeof(cpuset), &cpuset);
    }

    //socket de verdade
    int sockfd, use_afp = (iface != NULL);
    int off = use_afp ? 14 : 0;
    /* TCP = 20 IP + 20 TCP = 40,  UDP = 20 IP + 8 UDP = 28 */
    int payload_len = is_udp ? 28 : 40;
    int pkt_len = off + payload_len;

    if (use_afp) {
        sockfd = socket(AF_PACKET, SOCK_RAW, 0);
        if (sockfd < 0) return;
        int sndbuf = 32 << 20;
        setsockopt(sockfd, SOL_SOCKET, SO_SNDBUF, &sndbuf, sizeof(sndbuf));
        int bp = 50;
        setsockopt(sockfd, SOL_SOCKET, 46, &bp, sizeof(bp)); // SO_BUSY_POLL
        struct sockaddr_ll sll = {0};
        sll.sll_family = AF_PACKET;
        sll.sll_ifindex = if_nametoindex(iface);
        if (bind(sockfd, (struct sockaddr *)&sll, sizeof(sll)) < 0) { close(sockfd); return; }
    } else {
        sockfd = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
        if (sockfd < 0) return;
        int sndbuf = 32 << 20;
        setsockopt(sockfd, SOL_SOCKET, SO_SNDBUF, &sndbuf, sizeof(sndbuf));
    }

    // pre-compute static checksum parts
    uint16_t sw0 = ((uint16_t)src_ip[0] << 8) | src_ip[1];
    uint16_t sw1 = ((uint16_t)src_ip[2] << 8) | src_ip[3];
    /* IP static sum: ver+ihl+tos + total_len + id + flags_frag + ttl_proto + src_ip */
    uint8_t ip_proto = is_udp ? 17 : 6;
    uint32_t ip_static = 0x4500u + (uint32_t)payload_len + 54321u + 0u + (64u << 8 | ip_proto) + sw0 + sw1;

    // allocate contiguous batch buffer
    uint8_t *batch_buf = (uint8_t *)calloc((size_t)batch_size, pkt_len);
    struct mmsghdr *msgs = (struct mmsghdr *)calloc(batch_size, sizeof(struct mmsghdr));
    struct iovec *iovs = (struct iovec *)malloc((size_t)batch_size * sizeof(struct iovec));
    struct sockaddr_in *addrs = NULL;
    if (!use_afp)
        addrs = (struct sockaddr_in *)calloc(batch_size, sizeof(struct sockaddr_in));

    if (!batch_buf || !msgs || !iovs || (!use_afp && !addrs)) goto cleanup;

    // init packet templates + msg structs
    for (int i = 0; i < batch_size; i++) {
        uint8_t *pkt = batch_buf + (size_t)i * pkt_len;

        if (use_afp) {
            memcpy(pkt, gmac, 6);          /* dst mac */
            memcpy(pkt + 6, lmac, 6);      /* src mac */
            pkt[12] = 0x08; pkt[13] = 0x00; /* ethertype IPv4 */
        }
        // ip header
        pkt[off]    = 0x45;
        pkt[off+1]  = 0;
        pkt[off+2]  = (payload_len >> 8) & 0xFF;
        pkt[off+3]  = payload_len & 0xFF;
        pkt[off+4]  = 0xD4; pkt[off+5] = 0x31;  /* id=54321 */
        pkt[off+6]  = 0; pkt[off+7] = 0;
        pkt[off+8]  = 64;                        /* ttl */
        pkt[off+9]  = ip_proto;                   /* proto: TCP=6 UDP=17 */
        memcpy(pkt + off + 12, src_ip, 4);        /* src ip */

        if (is_udp) {
            // udp header: src_port, dst_port(set per-pkt), length=8, checksum=0
            pkt[off+20] = src_port >> 8;
            pkt[off+21] = src_port & 0xFF;
            // dst port set per-packet at off+22,23
            pkt[off+24] = 0; pkt[off+25] = 8;    /* udp length = 8 */
            pkt[off+26] = 0; pkt[off+27] = 0;    /* checksum = 0 (optional in IPv4) */
        } else {
            // tcp header
            pkt[off+20] = src_port >> 8;
            pkt[off+21] = src_port & 0xFF;
            // seq=0, ack=0 ja zerados
            pkt[off+32] = 0x50;                       /* data offset */
            pkt[off+33] = 0x02;                       /* SYN */
            pkt[off+34] = 0x16; pkt[off+35] = 0xD0;  /* window=5840 */
        }

        iovs[i].iov_base = pkt;
        iovs[i].iov_len = pkt_len;
        msgs[i].msg_hdr.msg_iov = &iovs[i];
        msgs[i].msg_hdr.msg_iovlen = 1;

        if (!use_afp) {
            addrs[i].sin_family = AF_INET;
            msgs[i].msg_hdr.msg_name = &addrs[i];
            msgs[i].msg_hdr.msg_namelen = sizeof(struct sockaddr_in);
        }
    }

    //rate limit 
    int eff_batch = batch_size;
    if (rate_limit > 0) {
        int max_for_rate = (rate_limit + 9) / 10;  // ~100ms worth of packets
        if (max_for_rate < 1) max_for_rate = 1;
        if (eff_batch > max_for_rate) eff_batch = max_for_rate;
    }

    uint64_t interval_ns = rate_limit > 0
        ? (uint64_t)((double)eff_batch / rate_limit * 1e9)
        : 0;
    uint64_t next_t = now_ns();

    int64_t cur_idx = start_index + worker_id;
    uint64_t rng = ((uint64_t)(worker_id + 1) * 0x9E3779B97F4A7C15ULL);
    uint64_t total_work = total_ips * (uint64_t)retries;

    // HOT LOOP
    while (likely(*run_flag)) {
        // rate limit
        if (interval_ns > 0) {
            uint64_t c = now_ns();
            if (c < next_t) {
                uint64_t w = next_t - c;
                if (w > 1000000) {
                    struct timespec sl = {
                        (time_t)(w / 1000000000ULL),
                        (long)(w % 1000000000ULL)
                    };
                    nanosleep(&sl, NULL);
                } else {
                    while (now_ns() < next_t);
                }
            }
            next_t += interval_ns;
        }

        // fill batch
        int batch_count = 0;
        for (int i = 0; i < eff_batch; i++) {
            uint32_t ip_int;
            int attempts = 0;

            for (;;) {
                if (unlikely((uint64_t)cur_idx >= total_work)) goto flush;
                if (unlikely(shards > 1 && (cur_idx % shards) != shard_id)) {
                    cur_idx += total_workers;
                    continue;
                }
                uint32_t shuf = fget((uint32_t)((uint64_t)cur_idx % total_ips), fkeys, total_ips, half_bits, feistel_mask);
                ip_int = get_ip(shuf, net_bases, net_starts, nets_len, single_net);
                cur_idx += total_workers;
                if (likely(is_public(ip_int, bl, bl_len))) break;
                if (unlikely(++attempts > 2000)) { *run_flag = 0; goto done; }
                if (unlikely(!*run_flag)) goto done;
            }

            uint32_t port_idx = (uint32_t)((uint64_t)cur_idx / total_ips) % ports_len;
            uint16_t port = ports[port_idx];

            // packet pointer
            uint8_t *p = batch_buf + (size_t)i * pkt_len;

            //checksum do ip
            uint32_t iph = ip_int >> 16, ipl = ip_int & 0xFFFF;
            uint32_t s = ip_static + iph + ipl;
            s = (s >> 16) + (s & 0xFFFF);
            s = (s >> 16) + (s & 0xFFFF);
            uint16_t cs_ip = ~s & 0xFFFF;

            p[off+10] = cs_ip >> 8;
            p[off+11] = cs_ip & 0xFF;

            // dst ip
            p[off+16] = (ip_int >> 24);
            p[off+17] = (ip_int >> 16) & 0xFF;
            p[off+18] = (ip_int >> 8) & 0xFF;
            p[off+19] = ip_int & 0xFF;

            // dst port 
            p[off+22] = port >> 8;
            p[off+23] = port & 0xFF;

            if (!is_udp) {
                //checksum tcp header 
                uint32_t st = (uint32_t)sw0 + sw1 + iph + ipl + 26u + src_port + port + 0x5002u + 5840u;
                st = (st >> 16) + (st & 0xFFFF);
                st = (st >> 16) + (st & 0xFFFF);
                uint16_t cs_tcp = ~st & 0xFFFF;
                p[off+36] = cs_tcp >> 8;
                p[off+37] = cs_tcp & 0xFF;
            }
            /* UDP checksum stays 0 (optional in IPv4) */

            //sock raw PRECISA do endereço
            if (unlikely(!use_afp)) {
                addrs[i].sin_addr.s_addr = htonl(ip_int);
            }
            batch_count++;
        }

        /* send batch */
        {
            int sent = 0;
            while (sent < batch_count) {
                int ret = sendmmsg(sockfd, msgs + sent, batch_count - sent, 0);
                if (likely(ret > 0)) {
                    __atomic_fetch_add(pps_ptr, (uint64_t)ret, __ATOMIC_RELAXED);
                    __atomic_fetch_add(sent_ptr, (uint64_t)ret, __ATOMIC_RELAXED);
                    sent += ret;
                } else break;
            }
        }
        continue;

flush:
        /* parcial send do batch e sair */
        {
            int sent = 0;
            while (sent < batch_count) {
                int ret = sendmmsg(sockfd, msgs + sent, batch_count - sent, 0);
                if (likely(ret > 0)) {
                    __atomic_fetch_add(pps_ptr, (uint64_t)ret, __ATOMIC_RELAXED);
                    __atomic_fetch_add(sent_ptr, (uint64_t)ret, __ATOMIC_RELAXED);
                    sent += ret;
                } else break;
            }
        }
        goto done;
    }

done:

cleanup:
    close(sockfd);
    free(batch_buf);
    free(msgs);
    free(iovs);
    free(addrs);
}
