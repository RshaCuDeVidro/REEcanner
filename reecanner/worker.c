/*
 * REEcanner - C packet worker
 * build: make (gcc -O2 -mtune=generic -flto -fPIC -shared -o worker.so worker.c)
 *        or REECANNER_NATIVE=1 make for -march=native
 */
#define _GNU_SOURCE
#include <stdint.h>
#include <stdio.h>
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

// feistel cipher

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

/* exported wrapper so tests can validate C/Python parity via ctypes */
uint32_t reecanner_fget(uint32_t idx, const uint32_t k[4], uint64_t max_val, int half_bits, uint32_t mask) {
    return fget(idx, k, max_val, half_bits, mask);
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
    if (lo > 0 && bl[lo-1] == ip) return 0;
    return 1;
}

// network lookup

static inline __attribute__((always_inline))
uint32_t get_ip(uint32_t shuf_idx, const uint32_t *bases, const uint32_t *starts,
                int nets_len, int single) {
    if (likely(single)) return bases[0] + shuf_idx;
    int lo = 0, hi = nets_len;
    while (lo < hi) {
        int mid = (lo + hi) >> 1;
        if (starts[mid] <= shuf_idx) lo = mid + 1; else hi = mid;
    }
    if (unlikely(lo == 0)) return bases[0] + shuf_idx; /* starts[0] is 0 today; stay safe */
    int i = lo - 1;
    return bases[i] + (shuf_idx - starts[i]);
}

// monotonic clock

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
    volatile int *rate_limit_ptr,   /* per-worker pps pointer */
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
    int is_udp,
    int adaptive,
    volatile uint64_t *fail_ptr,    /* &fail_array[worker_id] */
    const uint8_t *payloads,        /* concatenated UDP probe payloads */
    const int *payload_lens,        /* num_payloads entries */
    int num_payloads,
    int is_icmp
) {
    signal(SIGINT, SIG_IGN);
    (void)adaptive;  // part of the entry-point ABI; the parent handles adaptive rate

    // cpu affinity

    int ncpu = sysconf(_SC_NPROCESSORS_ONLN);
    if (ncpu > 0) {
        cpu_set_t cpuset;
        CPU_ZERO(&cpuset);
        CPU_SET(worker_id % ncpu, &cpuset);
        if (sched_setaffinity(0, sizeof(cpuset), &cpuset) != 0)
            fprintf(stderr, "worker %d: sched_setaffinity failed: %s\n",
                    worker_id, strerror(errno));
    }

    // send socket
    int sockfd, use_afp = (iface != NULL);
    int off = use_afp ? 14 : 0;

    static const uint8_t default_dns_payload[] = {
        0x13, 0x37, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x06, 'g', 'o', 'o',
        'g', 'l', 'e', 0x03, 'c', 'o', 'm', 0x00,
        0x00, 0x01, 0x00, 0x01
    };

#define ICMP_PAYLOAD_LEN 16

    /* payload offsets into the concatenated buffer + per-payload ip lengths */
    int payload_offs[16];
    int ip_tot_lens[16];
    if (is_udp) {
        if (num_payloads <= 0 || !payloads || !payload_lens) {
            payloads = default_dns_payload;
            static const int dns_len_arr[1] = { (int)sizeof(default_dns_payload) };
            payload_lens = dns_len_arr;
            num_payloads = 1;
        }
        if (num_payloads > 16) num_payloads = 16;
        int acc = 0;
        for (int k = 0; k < num_payloads; k++) {
            payload_offs[k] = acc;
            ip_tot_lens[k] = 28 + payload_lens[k];
            acc += payload_lens[k];
        }
    } else {
        num_payloads = 1;
        payload_offs[0] = 0;
        ip_tot_lens[0] = is_icmp ? (20 + 8 + ICMP_PAYLOAD_LEN) : 40;
    }

    /* TCP = 20 IP + 20 TCP = 40,  UDP = 20 IP + 8 UDP + payload,
       ICMP = 20 IP + 8 ICMP + payload. All slots use the largest layout
       so the batch buffer has a uniform stride. */
    int max_payload_len = 40;
    if (is_udp) {
        max_payload_len = 0;
        for (int k = 0; k < num_payloads; k++)
            if (ip_tot_lens[k] > max_payload_len) max_payload_len = ip_tot_lens[k];
    } else if (is_icmp) {
        max_payload_len = 20 + 8 + ICMP_PAYLOAD_LEN;
    }
    int pkt_stride = off + max_payload_len;

    if (use_afp) {
        sockfd = socket(AF_PACKET, SOCK_RAW, 0);
        if (sockfd < 0) {
            fprintf(stderr, "worker %d: socket(AF_PACKET) failed: %s\n",
                    worker_id, strerror(errno));
            return;
        }
        int sndbuf = 32 << 20;
        setsockopt(sockfd, SOL_SOCKET, SO_SNDBUF, &sndbuf, sizeof(sndbuf));
        /* SOL_PACKET(263) / PACKET_QDISC_BYPASS(21): skip the qdisc so a full
           TX path fails fast instead of silently queueing — send errors are
           the congestion signal for adaptive mode */
        int one = 1;
        setsockopt(sockfd, 263, 21, &one, sizeof(one));
        struct sockaddr_ll sll = {0};
        sll.sll_family = AF_PACKET;
        sll.sll_ifindex = if_nametoindex(iface);
        if (bind(sockfd, (struct sockaddr *)&sll, sizeof(sll)) < 0) {
            fprintf(stderr, "worker %d: bind(%s) failed: %s\n",
                    worker_id, iface, strerror(errno));
            close(sockfd);
            return;
        }
    } else {
        sockfd = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
        if (sockfd < 0) {
            fprintf(stderr, "worker %d: socket(SOCK_RAW) failed: %s\n",
                    worker_id, strerror(errno));
            return;
        }
        int sndbuf = 32 << 20;
        setsockopt(sockfd, SOL_SOCKET, SO_SNDBUF, &sndbuf, sizeof(sndbuf));
    }

    // pre-compute static checksum parts
    uint16_t sw0 = ((uint16_t)src_ip[0] << 8) | src_ip[1];
    uint16_t sw1 = ((uint16_t)src_ip[2] << 8) | src_ip[3];
    /* IP static sum: ver+ihl+tos + total_len + id + flags_frag + ttl_proto + src_ip */
    uint8_t ip_proto = is_udp ? 17 : (is_icmp ? 1 : 6);
    uint32_t ip_static_arr[16];
    for (int k = 0; k < num_payloads; k++)
        ip_static_arr[k] = 0x4500u + (uint32_t)ip_tot_lens[k] + 54321u + 0u
                         + ((uint32_t)64u << 8 | ip_proto) + sw0 + sw1;

    // allocate contiguous batch buffer
    uint8_t *batch_buf = (uint8_t *)calloc((size_t)batch_size, pkt_stride);
    struct mmsghdr *msgs = (struct mmsghdr *)calloc(batch_size, sizeof(struct mmsghdr));
    struct iovec *iovs = (struct iovec *)malloc((size_t)batch_size * sizeof(struct iovec));
    struct sockaddr_in *addrs = NULL;
    if (!use_afp)
        addrs = (struct sockaddr_in *)calloc(batch_size, sizeof(struct sockaddr_in));

    if (!batch_buf || !msgs || !iovs || (!use_afp && !addrs)) goto cleanup;

    // init packet templates + msg structs
    for (int i = 0; i < batch_size; i++) {
        uint8_t *pkt = batch_buf + (size_t)i * pkt_stride;

        if (use_afp) {
            memcpy(pkt, gmac, 6);          /* dst mac */
            memcpy(pkt + 6, lmac, 6);      /* src mac */
            pkt[12] = 0x08; pkt[13] = 0x00; /* ethertype IPv4 */
        }
        // ip header (total_len, dst ip and checksum patched per-packet)
        pkt[off]    = 0x45;
        pkt[off+1]  = 0;
        pkt[off+2]  = (ip_tot_lens[0] >> 8) & 0xFF;
        pkt[off+3]  = ip_tot_lens[0] & 0xFF;
        pkt[off+4]  = 0xD4; pkt[off+5] = 0x31;  /* id=54321 */
        pkt[off+6]  = 0; pkt[off+7] = 0;
        pkt[off+8]  = 64;                        /* ttl */
        pkt[off+9]  = ip_proto;                   /* proto: TCP=6 UDP=17 ICMP=1 */
        memcpy(pkt + off + 12, src_ip, 4);        /* src ip */

        if (is_udp) {
            // udp header: src_port, dst_port(set per-pkt), length, checksum=0
            pkt[off+20] = src_port >> 8;
            pkt[off+21] = src_port & 0xFF;
            // dst port, length and payload set per-packet
        } else if (is_icmp) {
            // icmp echo request: type 8, code 0, id, seq, padding payload
            pkt[off+20] = 8; pkt[off+21] = 0;
            pkt[off+22] = 0; pkt[off+23] = 0;    /* checksum, filled below */
            pkt[off+24] = 0x13; pkt[off+25] = 0x37;  /* id */
            pkt[off+26] = 0; pkt[off+27] = 1;        /* seq */
            for (int b = 0; b < ICMP_PAYLOAD_LEN; b++)
                pkt[off+28+b] = (uint8_t)(0x61 + (b % 26));
            uint32_t cs = 0;
            for (int b = off + 20; b < off + 28 + ICMP_PAYLOAD_LEN; b += 2)
                cs += ((uint32_t)pkt[b] << 8) | pkt[b+1];
            cs = (cs >> 16) + (cs & 0xFFFF);
            cs = (cs >> 16) + (cs & 0xFFFF);
            uint16_t cs_icmp = ~cs & 0xFFFF;
            pkt[off+22] = cs_icmp >> 8;
            pkt[off+23] = cs_icmp & 0xFF;
        } else {
            // tcp header
            pkt[off+20] = src_port >> 8;
            pkt[off+21] = src_port & 0xFF;
            // seq=0, ack=0 already zeroed by calloc
            pkt[off+32] = 0x50;                       /* data offset */
            pkt[off+33] = 0x02;                       /* SYN */
            pkt[off+34] = 0x16; pkt[off+35] = 0xD0;  /* window=5840 */
        }

        iovs[i].iov_base = pkt;
        iovs[i].iov_len = off + ip_tot_lens[0];
        msgs[i].msg_hdr.msg_iov = &iovs[i];
        msgs[i].msg_hdr.msg_iovlen = 1;

        if (!use_afp) {
            addrs[i].sin_family = AF_INET;
            msgs[i].msg_hdr.msg_name = &addrs[i];
            msgs[i].msg_hdr.msg_namelen = sizeof(struct sockaddr_in);
        }
    }

    // rate limit
    int eff_batch = batch_size;
    uint64_t interval_ns = 0;
    int last_rate_limit = -1;

    /* Shard distribution: step over the shard's own index sub-space so work is
       spread across ALL workers. Stepping by total_workers with a plain
       cur_idx%shards==shard_id skip leaves whole workers idle whenever shards
       divides total_workers (each worker's residue mod shards is then fixed).
       Worker w walks shard_id + (w + k*W)*shards, which together cover exactly
       this shard's indices with no gaps or overlap. */
    int64_t step = total_workers;
    int64_t cur_idx = start_index + worker_id;
    if (shards > 1) {
        step = (int64_t)total_workers * shards;
        int64_t r = (((int64_t)shard_id - start_index) % shards + shards) % shards;
        cur_idx = start_index + r + (int64_t)worker_id * shards;
    }
    uint64_t total_work = total_ips * (uint64_t)ports_len * (uint64_t)retries;

    int64_t last_shuf_idx = -1;
    uint32_t cached_ip = 0;
    int cached_public = 0;

    // HOT LOOP
    while (likely(*run_flag)) {
        uint64_t start_time = now_ns();

        // rate limit check/update
        int rate_limit = *rate_limit_ptr;
        if (unlikely(rate_limit != last_rate_limit)) {
            last_rate_limit = rate_limit;
            eff_batch = batch_size;
            if (rate_limit > 0) {
                int max_for_rate = (rate_limit + 9) / 10;  // ~100ms worth of packets
                if (max_for_rate < 1) max_for_rate = 1;
                if (eff_batch > max_for_rate) eff_batch = max_for_rate;
                interval_ns = (uint64_t)((double)eff_batch / rate_limit * 1e9);
            } else {
                interval_ns = 0;
            }
        }

        // fill batch
        int batch_count = 0;
        for (int i = 0; i < eff_batch; i++) {
            uint32_t ip_int;
            int attempts = 0;
            int64_t shuf_idx = 0;

            for (;;) {
                if (unlikely((uint64_t)cur_idx >= total_work)) goto flush;

                shuf_idx = (int64_t)(((uint64_t)cur_idx / ports_len) % total_ips);
                if (shuf_idx != last_shuf_idx) {
                    uint32_t shuf = fget((uint32_t)shuf_idx, fkeys, total_ips, half_bits, feistel_mask);
                    cached_ip = get_ip(shuf, net_bases, net_starts, nets_len, single_net);
                    cached_public = is_public(cached_ip, bl, bl_len);
                    last_shuf_idx = shuf_idx;
                }

                ip_int = cached_ip;
                cur_idx += step;
                if (likely(cached_public)) break;

                if (unlikely(++attempts > 10000)) { *run_flag = 0; goto done; }
                if (unlikely(!*run_flag)) goto done;
            }

            uint32_t port_idx = (uint32_t)((uint64_t)(cur_idx - step) % ports_len);
            uint16_t port = ports[port_idx];

            /* probe payload: round-robin across target IPs (UDP only) */
            int pidx = is_udp ? (int)((uint64_t)shuf_idx % (uint64_t)num_payloads) : 0;
            int plen = ip_tot_lens[pidx];

            // packet pointer
            uint8_t *p = batch_buf + (size_t)i * pkt_stride;

            // per-packet ip total length
            p[off+2] = (plen >> 8) & 0xFF;
            p[off+3] = plen & 0xFF;

            // ip checksum
            uint32_t iph = ip_int >> 16, ipl = ip_int & 0xFFFF;
            uint32_t s = ip_static_arr[pidx] + iph + ipl;
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

            if (is_udp) {
                // dst port, udp length and payload
                p[off+22] = port >> 8;
                p[off+23] = port & 0xFF;
                uint16_t ulen = (uint16_t)(8 + payload_lens[pidx]);
                p[off+24] = ulen >> 8;
                p[off+25] = ulen & 0xFF;
                p[off+26] = 0; p[off+27] = 0;    /* checksum = 0 (optional in IPv4) */
                memcpy(p + off + 28, payloads + payload_offs[pidx], payload_lens[pidx]);
            } else if (!is_icmp) {
                // dst port
                p[off+22] = port >> 8;
                p[off+23] = port & 0xFF;
                // tcp header checksum
                uint32_t st = (uint32_t)sw0 + sw1 + iph + ipl + 26u + src_port + port + 0x5002u + 5840u;
                st = (st >> 16) + (st & 0xFFFF);
                st = (st >> 16) + (st & 0xFFFF);
                uint16_t cs_tcp = ~st & 0xFFFF;
                p[off+36] = cs_tcp >> 8;
                p[off+37] = cs_tcp & 0xFF;
            }
            /* ICMP: header and checksum are fully static in the template */

            iovs[i].iov_len = off + plen;

            // SOCK_RAW requires the destination address per message
            if (unlikely(!use_afp)) {
                addrs[i].sin_addr.s_addr = htonl(ip_int);
            }
            batch_count++;
        }

        /* send batch — MSG_DONTWAIT: a full TX queue must fail (EAGAIN),
           not block, so adaptive mode sees the congestion */
        {
            int sent = 0;
            while (sent < batch_count) {
                int ret = sendmmsg(sockfd, msgs + sent, batch_count - sent, MSG_DONTWAIT);
                if (likely(ret > 0)) {
                    __atomic_fetch_add(pps_ptr, (uint64_t)ret, __ATOMIC_RELAXED);
                    __atomic_fetch_add(sent_ptr, (uint64_t)ret, __ATOMIC_RELAXED);
                    sent += ret;
                } else {
                    /* send failure: primary congestion signal for adaptive mode */
                    if (fail_ptr)
                        __atomic_fetch_add(fail_ptr, 1, __ATOMIC_RELAXED);
                    break;
                }
            }
        }

        // rate limit sleep with transmission compensation
        if (interval_ns > 0) {
            uint64_t duration = now_ns() - start_time;
            if (duration < interval_ns) {
                uint64_t w = interval_ns - duration;
                if (w > 1000000) {
                    struct timespec sl = {
                        (time_t)(w / 1000000000ULL),
                        (long)(w % 1000000000ULL)
                    };
                    nanosleep(&sl, NULL);
                } else {
                    uint64_t end_t = now_ns() + w;
                    while (now_ns() < end_t);
                }
            }
        }

        continue;

flush:
        /* send the partial batch and exit */
        {
            int sent = 0;
            while (sent < batch_count) {
                int ret = sendmmsg(sockfd, msgs + sent, batch_count - sent, MSG_DONTWAIT);
                if (likely(ret > 0)) {
                    __atomic_fetch_add(pps_ptr, (uint64_t)ret, __ATOMIC_RELAXED);
                    __atomic_fetch_add(sent_ptr, (uint64_t)ret, __ATOMIC_RELAXED);
                    sent += ret;
                } else {
                    /* send failure: primary congestion signal for adaptive mode */
                    if (fail_ptr)
                        __atomic_fetch_add(fail_ptr, 1, __ATOMIC_RELAXED);
                    break;
                }
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
