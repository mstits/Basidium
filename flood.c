/*
 * flood.c — packet builders, worker threads, sniffer, RNG, selftest
 *
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2026 Matthew Stits
 */
#define _GNU_SOURCE
#include "flood.h"
#include "nccl.h"
#include "tco.h"

#include <arpa/inet.h>
#include <err.h>
#include <netinet/ip.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/time.h>
#include <time.h>
#include <unistd.h>

/* ---- Mode helpers ---- */

const char *mode_to_string(flood_mode_t mode) {
    switch (mode) {
    case MODE_ARP:  return "arp";
    case MODE_DHCP: return "dhcp";
    case MODE_PFC:  return "pfc";
    case MODE_ND:   return "nd";
    case MODE_LLDP: return "lldp";
    case MODE_STP:  return "stp";
    case MODE_IGMP: return "igmp";
    default:        return "mac";
    }
}

flood_mode_t mode_from_string(const char *str) {
    if (strcmp(str, "mac")  == 0) return MODE_MAC;
    if (strcmp(str, "arp")  == 0) return MODE_ARP;
    if (strcmp(str, "dhcp") == 0) return MODE_DHCP;
    if (strcmp(str, "pfc")  == 0) return MODE_PFC;
    if (strcmp(str, "nd")   == 0) return MODE_ND;
    if (strcmp(str, "lldp") == 0) return MODE_LLDP;
    if (strcmp(str, "stp")  == 0) return MODE_STP;
    if (strcmp(str, "igmp") == 0) return MODE_IGMP;
    return MODE_INVALID;
}

/* ---- Logging ---- */

void log_event(const char *type, const char *msg) {
    if (!conf.log_file)
        return;
    pthread_mutex_lock(&log_mutex);
    FILE *fp = fopen(conf.log_file, "a");
    if (fp) {
        time_t now = time(NULL);
        char ts[64];
        strftime(ts, sizeof(ts), "%Y-%m-%dT%H:%M:%S", localtime(&now));
        fprintf(fp, "{\"timestamp\": \"%s\", \"type\": \"%s\", \"message\": \"%s\"}\n",
                ts, type, msg);
        fclose(fp);
    }
    pthread_mutex_unlock(&log_mutex);
}

/* ---- Fast RNG (Xorshift128+) — thread-safe, no global state ---- */

uint64_t xorshift128plus(uint64_t s[2]) {
    uint64_t x = s[0];
    uint64_t const y = s[1];
    s[0] = y;
    x ^= x << 23;
    s[1] = x ^ y ^ (x >> 17) ^ (y >> 26);
    return s[1] + y;
}

void rng_init(struct rng_state *rng, int seed_offset) {
    rng->s[0] = (uint64_t)time(NULL) + seed_offset;
    rng->s[1] = (uint64_t)getpid()  + seed_offset;
}

uint32_t rng_rand(struct rng_state *rng) {
    return (uint32_t)xorshift128plus(rng->s);
}

/* ---- IPv4 Header Checksum ---- */

uint16_t ip_checksum(const void *data, int len) {
    const uint16_t *p = (const uint16_t *)data;
    uint32_t sum = 0;
    for (int i = 0; i < len / 2; i++)
        sum += p[i];
    if (len & 1)
        sum += ((const uint8_t *)data)[len - 1];
    while (sum >> 16)
        sum = (sum & 0xFFFF) + (sum >> 16);
    return (uint16_t)~sum;
}

/* ---- Helpers ---- */

void randomize_mac(uint8_t *mac, struct rng_state *rng) {
    if (conf.stealth) {
        memcpy(mac, conf.stealth_oui, 3);
        uint32_t r = rng_rand(rng);
        mac[3] = r & 0xFF;
        mac[4] = (r >> 8) & 0xFF;
        mac[5] = (r >> 16) & 0xFF;
    } else {
        uint32_t r1 = rng_rand(rng);
        uint32_t r2 = rng_rand(rng);
        mac[0] = r1 & 0xFF;
        mac[1] = (r1 >> 8) & 0xFF;
        mac[2] = (r1 >> 16) & 0xFF;
        mac[3] = r2 & 0xFF;
        mac[4] = (r2 >> 8) & 0xFF;
        mac[5] = (r2 >> 16) & 0xFF;
    }
    if (!conf.allow_multicast)
        mac[0] &= 0xfe; /* enforce unicast */
}

int is_learned_mac(uint8_t *mac) {
    pthread_mutex_lock(&learn_mutex);
    for (int i = 0; i < learned_count; i++) {
        if (memcmp(learned_macs[i], mac, 6) == 0) {
            pthread_mutex_unlock(&learn_mutex);
            return 1;
        }
    }
    pthread_mutex_unlock(&learn_mutex);
    return 0;
}

uint32_t get_target_ip(struct rng_state *rng) {
    if (conf.target_count == 0)
        return rng_rand(rng);
    struct target t = conf.targets[rng_rand(rng) % conf.target_count];
    uint32_t rand_suffix = rng_rand(rng) & ~t.mask;
    return htonl(ntohl(t.ip) | rand_suffix);
}

/* ---- Sniffer / Learning + Adaptive Thread ---- */

void *sniffer_thread_func(void *arg) {
    (void)arg;
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *sniffer = pcap_open_live(conf.interface, 65535, 1, 100, errbuf);
    if (!sniffer) {
        warnx("Sniffer failed: %s", errbuf);
        return NULL;
    }

    /* BPF filter: exclude our own injected traffic by filtering out frames
     * with our probe signature in the IP ID field.  This reduces false
     * positives in adaptive mode and makes learning more accurate. */
    struct bpf_program bpf;
    char filter[128];
    snprintf(filter, sizeof(filter),
             "not (ip and ip[4:2] = 0x%04x)", probe_signature);
    if (pcap_compile(sniffer, &bpf, filter, 1, PCAP_NETMASK_UNKNOWN) == 0) {
        pcap_setfilter(sniffer, &bpf);
        pcap_freecode(&bpf);
    }
    /* if compile fails, continue without filter — still functional */

    struct pcap_pkthdr hdr;
    const u_char *pkt;
    static const uint8_t bcast[6] = {0xff,0xff,0xff,0xff,0xff,0xff};

    while (is_running) {
        pkt = pcap_next(sniffer, &hdr);
        if (!pkt)
            continue;

        struct ether_header_custom *eth = (struct ether_header_custom *)pkt;

        /* Learning mode: record real MACs to avoid spoofing them */
        if (conf.learning && !is_learned_mac(eth->source)) {
            pthread_mutex_lock(&learn_mutex);
            if (learned_count < MAX_LEARNED_MACS)
                memcpy(learned_macs[learned_count++], eth->source, 6);
            pthread_mutex_unlock(&learn_mutex);
        }

        /* Fail-open detection: MAC-flood frames embed probe_signature in ip_id.
         * If we receive an IP frame with our own probe_signature, the switch
         * is broadcasting our injected traffic — it has failed open to hub mode.
         * Note: with the BPF filter active, this branch only fires if the filter
         * could not be installed (pcap_compile failure). */
        if (conf.detect_failopen && !fail_open_detected &&
                ntohs(eth->type) == ETHERTYPE_IP && hdr.caplen >= 34) {
            struct ip *iph = (struct ip *)(pkt + sizeof(struct ether_header_custom));
            if (ntohs(iph->ip_id) == probe_signature) {
                atomic_store(&fail_open_detected, 1);
                log_event("FAIL_OPEN",
                          "Switch fail-open detected — injected frames echoed back");
            }
        }

        /* Adaptive mode: count broadcast frames as a fail-open indicator. */
        if (conf.adaptive && memcmp(eth->dest, bcast, 6) == 0)
            atomic_fetch_add(&bcast_rx, 1);
    }

    pcap_close(sniffer);
    return NULL;
}

/* ---- 802.1Q VLAN tag insertion ---- */

void vlan_tag_frame(uint8_t *buffer, int *len, struct rng_state *rng) {
    if (!conf.vlan_id) return;

    memmove(buffer + 16, buffer + 12, *len - 12);

    uint16_t tpid = htons(ETHERTYPE_VLAN);
    memcpy(buffer + 12, &tpid, 2);

    int vid = conf.vlan_id;
    if (conf.vlan_range_end > conf.vlan_id)
        vid = conf.vlan_id +
              (rng_rand(rng) % (conf.vlan_range_end - conf.vlan_id + 1));

    uint16_t tci = htons(((conf.vlan_pcp & 0x7) << 13) | (vid & 0x0FFF));
    memcpy(buffer + 14, &tci, 2);

    *len += 4;
}

void qinq_tag_frame(uint8_t *buffer, int *len) {
    if (!conf.qinq_outer_vid) return;

    memmove(buffer + 16, buffer + 12, *len - 12);

    uint16_t tpid = htons(ETHERTYPE_8021AD);
    memcpy(buffer + 12, &tpid, 2);

    uint16_t tci = htons(conf.qinq_outer_vid & 0x0FFF);
    memcpy(buffer + 14, &tci, 2);

    *len += 4;
}

/* ---- Payload Pattern Fill ---- */

static void apply_payload_pattern(uint8_t *buf, int hdr_end, int frame_len) {
    if (frame_len <= hdr_end) return;

    switch (conf.payload_pattern) {
    case 1:
        memset(buf + hdr_end, 0xFF, frame_len - hdr_end);
        break;
    case 2:
        for (int i = hdr_end; i < frame_len; i++)
            buf[i] = (uint8_t[]){0xDE, 0xAD, 0xBE, 0xEF}[(i - hdr_end) & 3];
        break;
    case 3:
        for (int i = hdr_end; i < frame_len; i++)
            buf[i] = (uint8_t)(i - hdr_end);
        break;
    default:
        break;
    }
}

/* ---- Frame Builders ---- */

int build_packet_mac(uint8_t *buffer, struct rng_state *rng) {
    struct ether_header_custom *eth = (struct ether_header_custom *)buffer;
    uint8_t src[6];

    do { randomize_mac(src, rng); }
    while (conf.learning && is_learned_mac(src));

    memcpy(eth->source, src, 6);
    randomize_mac(eth->dest, rng);
    eth->type = htons(ETHERTYPE_IP);

    struct ip *iph = (struct ip *)(buffer + sizeof(struct ether_header_custom));
    int frame_len = (conf.packet_size > 60) ? conf.packet_size : 60;
    if (frame_len > MAX_PACKET_SIZE)
        frame_len = MAX_PACKET_SIZE;

    iph->ip_hl  = 5;
    iph->ip_v   = 4;
    iph->ip_len = htons(frame_len - sizeof(struct ether_header_custom));
    iph->ip_src.s_addr = get_target_ip(rng);
    iph->ip_dst.s_addr = get_target_ip(rng);
    iph->ip_id  = htons(probe_signature);
    iph->ip_ttl = 64;
    iph->ip_sum = 0;
    iph->ip_sum = ip_checksum(iph, sizeof(struct ip));

    int hdr_end = (int)(sizeof(struct ether_header_custom) + sizeof(struct ip));
    apply_payload_pattern(buffer, hdr_end, frame_len);

    vlan_tag_frame(buffer, &frame_len, rng);
    qinq_tag_frame(buffer, &frame_len);
    return frame_len;
}

int build_packet_arp(uint8_t *buffer, struct rng_state *rng) {
    struct ether_header_custom *eth = (struct ether_header_custom *)buffer;
    struct arp_header *arp =
        (struct arp_header *)(buffer + sizeof(struct ether_header_custom));

    uint8_t mac[6];
    randomize_mac(mac, rng);

    memcpy(eth->source, mac, 6);
    memset(eth->dest, 0xff, 6);
    eth->type = htons(ETHERTYPE_ARP);

    arp->htype = htons(1);
    arp->ptype = htons(ETHERTYPE_IP);
    arp->hlen  = 6;
    arp->plen  = 4;
    arp->oper  = htons(1);
    memcpy(arp->sha, mac, 6);
    arp->spa = get_target_ip(rng);
    memset(arp->tha, 0, 6);
    arp->tpa = get_target_ip(rng);

    int len = (int)(sizeof(struct ether_header_custom) + sizeof(struct arp_header));
    vlan_tag_frame(buffer, &len, rng);
    qinq_tag_frame(buffer, &len);
    return len;
}

int build_packet_dhcp(uint8_t *buffer, struct rng_state *rng) {
    struct ether_header_custom *eth = (struct ether_header_custom *)buffer;
    struct ip *iph =
        (struct ip *)(buffer + sizeof(*eth));
    struct udp_header *udph =
        (struct udp_header *)(buffer + sizeof(*eth) + sizeof(struct ip));
    struct dhcp_packet *dhcp =
        (struct dhcp_packet *)(buffer + sizeof(*eth) + sizeof(struct ip) +
                               sizeof(struct udp_header));

    uint8_t mac[6];
    randomize_mac(mac, rng);

    memcpy(eth->source, mac, 6);
    memset(eth->dest, 0xff, 6);
    eth->type = htons(ETHERTYPE_IP);

    iph->ip_v   = 4;
    iph->ip_hl  = 5;
    iph->ip_ttl = 64;
    iph->ip_p   = IPPROTO_UDP;
    iph->ip_src.s_addr = 0;
    iph->ip_dst.s_addr = 0xffffffff;
    iph->ip_len = htons(sizeof(struct ip) + sizeof(struct udp_header) +
                        sizeof(struct dhcp_packet));
    iph->ip_sum = 0;
    iph->ip_sum = ip_checksum(iph, sizeof(struct ip));

    udph->src_port = htons(68);
    udph->dst_port = htons(67);
    udph->len  = htons(sizeof(struct udp_header) + sizeof(struct dhcp_packet));
    udph->check = 0;

    dhcp->op    = 1;
    dhcp->htype = 1;
    dhcp->hlen  = 6;
    dhcp->xid   = htonl(rng_rand(rng));

    if (conf.random_client_mac) {
        uint8_t rand_mac[6];
        uint32_t r1 = rng_rand(rng), r2 = rng_rand(rng);
        rand_mac[0] = r1; rand_mac[1] = r1 >> 8; rand_mac[2] = r1 >> 16;
        rand_mac[3] = r2; rand_mac[4] = r2 >> 8; rand_mac[5] = r2 >> 16;
        memcpy(dhcp->chaddr, rand_mac, 6);
    } else {
        memcpy(dhcp->chaddr, mac, 6);
    }

    dhcp->magic_cookie = htonl(0x63825363);
    dhcp->options[0]   = 53;
    dhcp->options[1]   = 1;
    dhcp->options[2]   = 1;
    dhcp->options[3]   = 255;

    int len = (int)(sizeof(*eth) + sizeof(struct ip) + sizeof(struct udp_header) +
                    sizeof(struct dhcp_packet));
    vlan_tag_frame(buffer, &len, rng);
    qinq_tag_frame(buffer, &len);
    return len;
}

int build_packet_nd(uint8_t *buffer, struct rng_state *rng) {
    uint8_t src_mac[6];
    randomize_mac(src_mac, rng);

    uint8_t target_ip6[16];
    uint32_t r;
    for (int i = 0; i < 16; i += 4) {
        r = rng_rand(rng);
        memcpy(target_ip6 + i, &r, (i + 4 <= 16) ? 4 : 16 - i);
    }

    struct ether_header_custom *eth = (struct ether_header_custom *)buffer;
    eth->dest[0] = 0x33; eth->dest[1] = 0x33; eth->dest[2] = 0xff;
    eth->dest[3] = target_ip6[13];
    eth->dest[4] = target_ip6[14];
    eth->dest[5] = target_ip6[15];
    memcpy(eth->source, src_mac, 6);
    eth->type = htons(0x86DD);

    struct ipv6_header *ip6 =
        (struct ipv6_header *)(buffer + sizeof(struct ether_header_custom));
    ip6->vcf         = htonl(0x60000000);
    ip6->payload_len = htons(sizeof(struct icmpv6_ns_pkt));
    ip6->next_header = 58;
    ip6->hop_limit   = 255;

    memset(ip6->src, 0, 16);
    ip6->src[0] = 0xfe; ip6->src[1] = 0x80;
    ip6->src[8]  = src_mac[0] ^ 0x02;
    ip6->src[9]  = src_mac[1];
    ip6->src[10] = src_mac[2];
    ip6->src[11] = 0xff;
    ip6->src[12] = 0xfe;
    ip6->src[13] = src_mac[3];
    ip6->src[14] = src_mac[4];
    ip6->src[15] = src_mac[5];

    ip6->dst[0]  = 0xff; ip6->dst[1]  = 0x02;
    memset(ip6->dst + 2, 0, 9);
    ip6->dst[11] = 0x00; ip6->dst[12] = 0x01;
    ip6->dst[13] = 0xff;
    ip6->dst[14] = target_ip6[14];
    ip6->dst[15] = target_ip6[15];

    struct icmpv6_ns_pkt *ns =
        (struct icmpv6_ns_pkt *)(buffer + sizeof(struct ether_header_custom) +
                                  sizeof(struct ipv6_header));
    ns->type     = 135;
    ns->code     = 0;
    ns->checksum = 0;
    ns->reserved = 0;
    memcpy(ns->target, target_ip6, 16);
    ns->opt_type = 1;
    ns->opt_len  = 1;
    memcpy(ns->opt_mac, src_mac, 6);

    return (int)(sizeof(struct ether_header_custom) +
                 sizeof(struct ipv6_header) +
                 sizeof(struct icmpv6_ns_pkt));
}

int build_packet_igmp(uint8_t *buffer, struct rng_state *rng) {
    uint32_t group_h = 0xE0000000 | (rng_rand(rng) & 0x0FFFFFFF);
    uint32_t group_n = htonl(group_h);

    uint8_t src[6];
    randomize_mac(src, rng);

    struct ether_header_custom *eth = (struct ether_header_custom *)buffer;
    eth->dest[0] = 0x01; eth->dest[1] = 0x00; eth->dest[2] = 0x5E;
    eth->dest[3] = (group_h >> 16) & 0x7F;
    eth->dest[4] = (group_h >>  8) & 0xFF;
    eth->dest[5] =  group_h        & 0xFF;
    memcpy(eth->source, src, 6);
    eth->type = htons(ETHERTYPE_IP);

    struct ip *iph = (struct ip *)(buffer + sizeof(*eth));
    iph->ip_v   = 4;
    iph->ip_hl  = 5;
    iph->ip_tos = 0xC0;
    iph->ip_ttl = 1;
    iph->ip_p   = 2;
    iph->ip_src.s_addr = get_target_ip(rng);
    iph->ip_dst.s_addr = group_n;
    iph->ip_len = htons((uint16_t)(sizeof(struct ip) + sizeof(struct igmp_header)));
    iph->ip_sum = 0;
    iph->ip_sum = ip_checksum(iph, sizeof(struct ip));

    struct igmp_header *igmp =
        (struct igmp_header *)(buffer + sizeof(*eth) + sizeof(struct ip));
    igmp->type     = 0x16;
    igmp->max_resp = 0;
    igmp->checksum = 0;
    igmp->group    = group_n;

    int len = (int)(sizeof(*eth) + sizeof(struct ip) + sizeof(struct igmp_header));
    if (len < 60) { memset(buffer + len, 0, 60 - len); len = 60; }
    vlan_tag_frame(buffer, &len, rng);
    qinq_tag_frame(buffer, &len);
    return len;
}

int build_packet_lldp(uint8_t *buffer, struct rng_state *rng) {
    static const uint8_t lldp_dst[6] = {0x01, 0x80, 0xC2, 0x00, 0x00, 0x0E};

    uint8_t src[6];
    randomize_mac(src, rng);

    struct ether_header_custom *eth = (struct ether_header_custom *)buffer;
    memcpy(eth->dest,   lldp_dst, 6);
    memcpy(eth->source, src,      6);
    eth->type = htons(ETHERTYPE_LLDP);

    uint8_t *p = buffer + sizeof(struct ether_header_custom);
    int off = 0;

    uint16_t tlv_hdr = htons((1u << 9) | 7);
    memcpy(p + off, &tlv_hdr, 2); off += 2;
    p[off++] = 4;
    memcpy(p + off, src, 6);    off += 6;

    tlv_hdr = htons((2u << 9) | 6);
    memcpy(p + off, &tlv_hdr, 2); off += 2;
    p[off++] = 7;
    memcpy(p + off, "port1", 5); off += 5;

    tlv_hdr = htons((3u << 9) | 2);
    memcpy(p + off, &tlv_hdr, 2); off += 2;
    uint16_t ttl_val = htons(120);
    memcpy(p + off, &ttl_val, 2); off += 2;

    tlv_hdr = 0;
    memcpy(p + off, &tlv_hdr, 2); off += 2;

    int len = (int)sizeof(struct ether_header_custom) + off;
    if (len < 60) { memset(buffer + len, 0, 60 - len); len = 60; }
    return len;
}

int build_packet_stp(uint8_t *buffer, struct rng_state *rng) {
    static const uint8_t stp_dst[6] = {0x01, 0x80, 0xC2, 0x00, 0x00, 0x00};

    uint8_t src[6];
    randomize_mac(src, rng);
    src[0] &= 0xfe;

    struct ether_header_custom *eth = (struct ether_header_custom *)buffer;
    memcpy(eth->dest,   stp_dst, 6);
    memcpy(eth->source, src,     6);
    eth->type = htons(7);

    uint8_t *p = buffer + sizeof(struct ether_header_custom);
    p[0] = 0x42; p[1] = 0x42; p[2] = 0x03;
    p[3] = 0x00; p[4] = 0x00; p[5] = 0x00; p[6] = 0x80;

    int len = (int)sizeof(struct ether_header_custom) + 7;
    memset(buffer + len, 0, 60 - len);
    return 60;
}

int build_packet_pfc(uint8_t *buffer, struct rng_state *rng) {
    static const uint8_t pfc_dst[6] = {0x01, 0x80, 0xC2, 0x00, 0x00, 0x01};

    struct ether_header_custom *eth = (struct ether_header_custom *)buffer;

    uint8_t src[6];
    randomize_mac(src, rng);
    memcpy(eth->source, src, 6);
    memcpy(eth->dest, pfc_dst, 6);
    eth->type = htons(ETHERTYPE_PAUSE);

    uint8_t *p = buffer + sizeof(struct ether_header_custom);
    p[0] = 0x01; p[1] = 0x01;

    uint16_t pev = htons((uint16_t)(1u << (conf.pfc_priority & 0x7)));
    memcpy(p + 2, &pev, 2);

    memset(p + 4, 0, 16);
    uint16_t q = htons((uint16_t)conf.pfc_quanta);
    memcpy(p + 4 + (conf.pfc_priority & 0x7) * 2, &q, 2);

    int total = (int)sizeof(struct ether_header_custom) + 2 + 2 + 16;
    memset(buffer + total, 0, 60 - total);
    return 60;
}

/* ---- Worker Thread ---- */

void *worker_func(void *arg) {
    int thread_id = *(int *)arg;
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *inj = NULL;

    if (!global_pd) {
        inj = pcap_open_live(conf.interface, MAX_PACKET_SIZE, 1, 1000, errbuf);
        if (!inj) {
            warnx("Worker %d open failed: %s", thread_id, errbuf);
            return NULL;
        }
    }

    uint8_t buffer[MAX_PACKET_SIZE];
    memset(buffer, 0, MAX_PACKET_SIZE);
    int len = 0;
    struct rng_state rng;
    rng_init(&rng, thread_id);

    /* Build initial template */
    switch (conf.mode) {
    case MODE_ARP:  len = build_packet_arp(buffer, &rng);  break;
    case MODE_DHCP: len = build_packet_dhcp(buffer, &rng); break;
    case MODE_PFC:  len = build_packet_pfc(buffer, &rng);  break;
    case MODE_ND:   len = build_packet_nd(buffer, &rng);   break;
    case MODE_LLDP: len = build_packet_lldp(buffer, &rng); break;
    case MODE_STP:  len = build_packet_stp(buffer, &rng);  break;
    case MODE_IGMP: len = build_packet_igmp(buffer, &rng); break;
    default:        len = build_packet_mac(buffer, &rng);  break;
    }

    struct ether_header_custom *eth = (struct ether_header_custom *)buffer;
    uint64_t local_sent       = 0;
    int      inject_failures  = 0;
    /* fast path eligible: mode 0, no stealth/learning/targeting/VLAN-range.
     * Also disabled when a TCO scenario is active: mode switches corrupt the
     * template buffer (ether_type, payload), and the fast path only overwrites
     * the 12 MAC bytes.  Switching MAC→PFC→MAC would leave stale PFC data.
     * We also re-check conf.mode at runtime as a safety net. */
    int fast_mac_eligible = (!conf.scenario_file &&
                             !conf.learning && !conf.stealth &&
                             conf.target_count == 0 &&
                             !(conf.vlan_range_end > conf.vlan_id));

    unsigned long long last_bcast_rx = 0;

    /* Standby: wait for TUI user to press start before injecting */
    while (!is_started && is_running)
        usleep(50000);

    uint64_t burst_local = 0;

    while (is_running) {
        if (conf.count > 0 && (unsigned long long)total_sent >= (unsigned long long)conf.count)
            break;

        while (is_paused && is_running)
            usleep(50000);

        /* ---- Fast Path ---- */
        if (fast_mac_eligible && conf.mode == MODE_MAC) {
            uint64_t r1 = xorshift128plus(rng.s);
            uint64_t r2 = xorshift128plus(rng.s);

            uint8_t *src_ptr = eth->source;
            uint8_t *dst_ptr = eth->dest;

            *(uint32_t *)src_ptr        = (uint32_t)r1;
            *(uint16_t *)(src_ptr + 4)  = (uint16_t)(r1 >> 32);
            if (!conf.allow_multicast)
                src_ptr[0] &= 0xfe;

            *(uint32_t *)dst_ptr        = (uint32_t)r2;
            *(uint16_t *)(dst_ptr + 4)  = (uint16_t)(r2 >> 32);
        }
        /* ---- Slow Path ---- */
        else {
            switch (conf.mode) {
            case MODE_ARP:  len = build_packet_arp(buffer, &rng);  break;
            case MODE_DHCP: len = build_packet_dhcp(buffer, &rng); break;
            case MODE_PFC:  len = build_packet_pfc(buffer, &rng);  break;
            case MODE_ND:   len = build_packet_nd(buffer, &rng);   break;
            case MODE_LLDP: len = build_packet_lldp(buffer, &rng); break;
            case MODE_STP:  len = build_packet_stp(buffer, &rng);  break;
            case MODE_IGMP: len = build_packet_igmp(buffer, &rng); break;
            default:        len = build_packet_mac(buffer, &rng);  break;
            }
        }

        /* Send */
        if (global_pd) {
            struct pcap_pkthdr pkthdr;
            gettimeofday(&pkthdr.ts, NULL);
            pkthdr.caplen = pkthdr.len = len;
            pcap_dump((u_char *)global_pd, &pkthdr, buffer);
            local_sent++;
            inject_failures = 0;
        } else if (pcap_inject(inj, buffer, len) > 0) {
            local_sent++;
            inject_failures = 0;
        } else {
            inject_failures++;
            if (inject_failures == 1) {
                warnx("Worker %d: injection failed: %s — try running with sudo",
                      thread_id, pcap_geterr(inj));
                log_event("error", "injection failed — try running with sudo");
            }
            if (inject_failures >= MAX_INJECT_FAILURES) {
                warnx("Worker %d: %d consecutive inject failures, exiting",
                      thread_id, inject_failures);
                break;
            }
        }

        /* Burst mode */
        if (conf.burst_count > 0) {
            burst_local++;
            if (burst_local >= (uint64_t)conf.burst_count) {
                usleep((unsigned)conf.burst_gap_ms * 1000);
                burst_local = 0;
            }
        }

        /* Batch-update globals every 1024 packets */
        if ((local_sent & 1023) == 0) {
            atomic_fetch_add(&total_sent, 1024);
            atomic_fetch_add(&thread_sent[thread_id], 1024);

            if (conf.pps > 0 && conf.burst_count == 0)
                usleep((1024 * 1000000ULL / conf.pps) * conf.threads);

            if (conf.adaptive) {
                unsigned long long cur_bcast = (unsigned long long)bcast_rx;
                if (cur_bcast - last_bcast_rx > 2048)
                    usleep(5000);
                last_bcast_rx = cur_bcast;
            }
        }
    }

    /* Flush residual to BOTH counters */
    uint64_t residual = local_sent % 1024;
    atomic_fetch_add(&total_sent, residual);
    atomic_fetch_add(&thread_sent[thread_id], residual);

    if (inj)
        pcap_close(inj);
    return NULL;
}

/* ---- PCAP Replay Thread ---- */

void *pcap_replay_func(void *arg) {
    (void)arg;
    char errbuf[PCAP_ERRBUF_SIZE];

    pcap_t *replay = pcap_open_offline(conf.pcap_replay_file, errbuf);
    if (!replay) {
        warnx("pcap replay open failed: %s", errbuf);
        return NULL;
    }

    pcap_t *inj = pcap_open_live(conf.interface, MAX_PACKET_SIZE, 1, 1000, errbuf);
    if (!inj) {
        warnx("pcap replay inject open failed: %s", errbuf);
        pcap_close(replay);
        return NULL;
    }

    struct pcap_pkthdr *hdr;
    const u_char *data;
    int rc;

    while (is_running && (rc = pcap_next_ex(replay, &hdr, &data)) >= 0) {
        if (rc == 0) continue;
        pcap_inject(inj, data, hdr->caplen);
        atomic_fetch_add(&total_sent, 1);
        if (conf.pps > 0)
            usleep(1000000 / conf.pps);
    }

    pcap_close(inj);
    pcap_close(replay);
    return NULL;
}

/* ---- Rate Sweep Thread ---- */

void *sweep_thread_func(void *arg) {
    (void)arg;

    while (!is_started && is_running)
        sleep(1);

    int total = (conf.sweep_end - conf.sweep_start) / conf.sweep_step + 1;
    if (total < 1) total = 1;
    if (total > MAX_SWEEP_STEPS) total = MAX_SWEEP_STEPS;
    atomic_store(&sweep_total_steps, total);

    /* If NCCL correlation is active, record baseline before first step ramp.
     * We use the existing baseline if one was set (--nccl + 'b' key in TUI),
     * otherwise the first step's result becomes the implicit reference. */
    int nccl_correlate = conf.nccl;

    int step = 0;
    for (int pps = conf.sweep_start;
         pps <= conf.sweep_end && is_running && step < MAX_SWEEP_STEPS;
         pps += conf.sweep_step, step++) {

        conf.pps = pps;
        atomic_store(&sweep_step_num, step + 1);

        /* Launch NCCL test at the start of this step's hold period.
         * The test runs concurrently with injection at the current PPS. */
        int nccl_launched = 0;
        if (nccl_correlate) {
            if (nccl_launch() == 0) {
                nccl_launched = 1;
                log_event("SWEEP_NCCL", "NCCL test launched for sweep step");
            } else {
                log_event("SWEEP_NCCL", "NCCL launch failed (busy or error)");
            }
        }

        /* Snapshot NIC stats at step start */
        struct nic_stats nic_before;
        int have_nic = (nic_stats_read(conf.interface, &nic_before) == 0);

        /* Hold at this PPS level — this is the measurement window */
        unsigned long long sent_start = (unsigned long long)total_sent;

        for (int t = conf.sweep_hold; t > 0 && is_running; t--) {
            atomic_store(&sweep_hold_rem, t);
            sleep(1);
        }

        unsigned long long sent_end = (unsigned long long)total_sent;
        sweep_step_pps[step] = (conf.sweep_hold > 0)
            ? (sent_end - sent_start) / conf.sweep_hold
            : 0;

        /* Compute NIC stats delta for this step */
        if (have_nic) {
            struct nic_stats nic_after;
            if (nic_stats_read(conf.interface, &nic_after) == 0) {
                sweep_step_nic_delta[step].tx_packets = nic_after.tx_packets - nic_before.tx_packets;
                sweep_step_nic_delta[step].tx_bytes   = nic_after.tx_bytes   - nic_before.tx_bytes;
                sweep_step_nic_delta[step].tx_dropped = nic_after.tx_dropped - nic_before.tx_dropped;
                sweep_step_nic_delta[step].tx_errors  = nic_after.tx_errors  - nic_before.tx_errors;
                sweep_step_nic_delta[step].rx_packets = nic_after.rx_packets - nic_before.rx_packets;
                sweep_step_nic_delta[step].rx_bytes   = nic_after.rx_bytes   - nic_before.rx_bytes;
                sweep_step_nic_valid[step] = 1;
            }
        }

        /* Wait for NCCL to finish if it was launched.
         * We keep the current PPS level active until NCCL completes so the
         * measurement reflects the actual congestion conditions. */
        if (nccl_launched) {
            int nccl_wait = 300; /* max 5 minutes for NCCL to finish */
            while (nccl.status == NCCL_RUNNING && is_running && nccl_wait-- > 0) {
                atomic_store(&sweep_hold_rem, 0);
                sleep(1);
            }
            if (nccl.status == NCCL_DONE && nccl.result_count > 0) {
                /* Use the last (largest message) result as representative */
                sweep_step_nccl_busbw[step] =
                    nccl.results[nccl.result_count - 1].bus_bw;
                sweep_step_nccl_valid[step] = 1;

                /* Set baseline from first successful measurement */
                if (nccl.baseline_bus_bw <= 0.0)
                    nccl_set_baseline();
            }
        }

        char msg[128];
        if (sweep_step_nccl_valid[step]) {
            double delta = (nccl.baseline_bus_bw > 0.0)
                ? ((sweep_step_nccl_busbw[step] - nccl.baseline_bus_bw)
                   / nccl.baseline_bus_bw) * 100.0
                : 0.0;
            snprintf(msg, sizeof(msg),
                     "step %d/%d pps=%d achieved=%llu nccl=%.1f GB/s (%+.1f%%)",
                     step + 1, total, pps, sweep_step_pps[step],
                     sweep_step_nccl_busbw[step], delta);
        } else {
            snprintf(msg, sizeof(msg), "step %d/%d pps=%d achieved=%llu",
                     step + 1, total, pps, sweep_step_pps[step]);
        }
        log_event("SWEEP_STEP", msg);
    }

    log_event("SWEEP_DONE", "Rate sweep completed");
    atomic_store(&is_running, 0);
    return NULL;
}

/* ---- Self Test ---- */

int run_selftest(void) {
    printf("Running Self-Test Suite...\n");
    uint8_t buf[MAX_PACKET_SIZE];
    int len;
    struct rng_state rng;
    rng_init(&rng, 42);

    /* Test 1: MAC */
    memset(buf, 0, sizeof(buf));
    len = build_packet_mac(buf, &rng);
    if (len < 60) errx(1, "FAIL: MAC packet too small (%d)", len);
    struct ether_header_custom *eth = (struct ether_header_custom *)buf;
    if (ntohs(eth->type) != ETHERTYPE_IP) errx(1, "FAIL: MAC ethertype incorrect");
    /* verify IP checksum */
    struct ip *test_iph = (struct ip *)(buf + sizeof(*eth));
    if (ip_checksum(test_iph, sizeof(struct ip)) != 0)
        errx(1, "FAIL: MAC IP checksum verification failed");
    printf("[PASS] MAC Builder (with IP checksum)\n");

    /* Test 2: ARP */
    memset(buf, 0, sizeof(buf));
    build_packet_arp(buf, &rng);
    eth = (struct ether_header_custom *)buf;
    if (ntohs(eth->type) != ETHERTYPE_ARP) errx(1, "FAIL: ARP ethertype incorrect");
    struct arp_header *arp = (struct arp_header *)(buf + sizeof(*eth));
    if (ntohs(arp->oper) != 1) errx(1, "FAIL: ARP opcode not Request");
    printf("[PASS] ARP Builder\n");

    /* Test 3: DHCP */
    memset(buf, 0, sizeof(buf));
    build_packet_dhcp(buf, &rng);
    eth = (struct ether_header_custom *)buf;
    struct ip *iph = (struct ip *)(buf + sizeof(*eth));
    if (iph->ip_p != IPPROTO_UDP) errx(1, "FAIL: DHCP not UDP");
    struct dhcp_packet *dhcp =
        (struct dhcp_packet *)(buf + sizeof(*eth) + sizeof(*iph) +
                               sizeof(struct udp_header));
    if (dhcp->op != 1) errx(1, "FAIL: DHCP op not BootRequest");
    if (dhcp->magic_cookie != htonl(0x63825363)) errx(1, "FAIL: DHCP cookie invalid");
    printf("[PASS] DHCP Builder\n");

    /* Test 4: 802.1Q VLAN tagging */
    memset(buf, 0, sizeof(buf));
    conf.vlan_id  = 100;
    conf.vlan_pcp = 5;
    int base_len = build_packet_mac(buf, &rng);
    eth = (struct ether_header_custom *)buf;
    uint16_t tpid, tci, inner;
    memcpy(&tpid,  buf + 12, 2);
    memcpy(&tci,   buf + 14, 2);
    memcpy(&inner, buf + 16, 2);
    if (ntohs(tpid)  != ETHERTYPE_VLAN)
        errx(1, "FAIL: VLAN TPID incorrect (got 0x%04x)", ntohs(tpid));
    if (ntohs(tci) != (uint16_t)(((5 & 0x7) << 13) | (100 & 0x0FFF)))
        errx(1, "FAIL: VLAN TCI incorrect (got 0x%04x)", ntohs(tci));
    if (ntohs(inner) != ETHERTYPE_IP)
        errx(1, "FAIL: VLAN inner EtherType not IP (got 0x%04x)", ntohs(inner));
    if (base_len < 64)
        errx(1, "FAIL: VLAN-tagged frame too short (%d)", base_len);
    conf.vlan_id = 0;
    conf.vlan_pcp = 0;
    printf("[PASS] VLAN Tagging\n");

    /* Test 5: PFC PAUSE frame */
    memset(buf, 0, sizeof(buf));
    conf.pfc_priority = 3;
    conf.pfc_quanta   = 0xFFFF;
    int pfc_len = build_packet_pfc(buf, &rng);
    static const uint8_t expected_dst[6] = {0x01,0x80,0xC2,0x00,0x00,0x01};
    if (memcmp(buf, expected_dst, 6) != 0)
        errx(1, "FAIL: PFC destination MAC incorrect");
    uint16_t ptype;
    memcpy(&ptype, buf + 12, 2);
    if (ntohs(ptype) != ETHERTYPE_PAUSE)
        errx(1, "FAIL: PFC EtherType incorrect (got 0x%04x)", ntohs(ptype));
    if (buf[14] != 0x01 || buf[15] != 0x01)
        errx(1, "FAIL: PFC opcode incorrect");
    uint16_t pev;
    memcpy(&pev, buf + 16, 2);
    if (ntohs(pev) != (1u << 3))
        errx(1, "FAIL: PFC priority enable vector incorrect");
    uint16_t quanta;
    memcpy(&quanta, buf + 18 + 3 * 2, 2);
    if (ntohs(quanta) != 0xFFFF)
        errx(1, "FAIL: PFC quanta for priority 3 incorrect");
    for (int i = 0; i < 8; i++) {
        if (i == 3) continue;
        uint16_t q;
        memcpy(&q, buf + 18 + i * 2, 2);
        if (q != 0) errx(1, "FAIL: PFC quanta for priority %d should be 0", i);
    }
    if (pfc_len != 60)
        errx(1, "FAIL: PFC frame length %d (expected 60)", pfc_len);
    printf("[PASS] PFC Builder\n");

    /* Test 6: IPv6 ND */
    memset(buf, 0, sizeof(buf));
    int nd_len = build_packet_nd(buf, &rng);
    eth = (struct ether_header_custom *)buf;
    if (ntohs(eth->type) != 0x86DD)
        errx(1, "FAIL: ND EtherType not IPv6 (got 0x%04x)", ntohs(eth->type));
    if (eth->dest[0] != 0x33 || eth->dest[1] != 0x33 || eth->dest[2] != 0xff)
        errx(1, "FAIL: ND dst MAC not solicited-node multicast");
    struct ipv6_header *ip6nd = (struct ipv6_header *)(buf + sizeof(*eth));
    if ((ntohl(ip6nd->vcf) >> 28) != 6)
        errx(1, "FAIL: ND IPv6 version not 6");
    if (ip6nd->next_header != 58)
        errx(1, "FAIL: ND next_header not ICMPv6 (58)");
    struct icmpv6_ns_pkt *ns_test =
        (struct icmpv6_ns_pkt *)(buf + sizeof(*eth) + sizeof(struct ipv6_header));
    if (ns_test->type != 135)
        errx(1, "FAIL: ND ICMPv6 type not 135");
    if (nd_len != 86)
        errx(1, "FAIL: ND frame length %d (expected 86)", nd_len);
    printf("[PASS] ND Builder\n");

    /* Test 7: LLDP */
    memset(buf, 0, sizeof(buf));
    int lldp_len = build_packet_lldp(buf, &rng);
    eth = (struct ether_header_custom *)buf;
    static const uint8_t lldp_dst_exp[6] = {0x01, 0x80, 0xC2, 0x00, 0x00, 0x0E};
    if (memcmp(eth->dest, lldp_dst_exp, 6) != 0)
        errx(1, "FAIL: LLDP dst MAC incorrect");
    if (ntohs(eth->type) != ETHERTYPE_LLDP)
        errx(1, "FAIL: LLDP EtherType incorrect (got 0x%04x)", ntohs(eth->type));
    uint16_t lldp_tlv1;
    memcpy(&lldp_tlv1, buf + sizeof(struct ether_header_custom), 2);
    if ((ntohs(lldp_tlv1) >> 9) != 1)
        errx(1, "FAIL: LLDP first TLV not Chassis ID (type %d)", ntohs(lldp_tlv1) >> 9);
    if (lldp_len != 60)
        errx(1, "FAIL: LLDP frame length %d (expected 60)", lldp_len);
    printf("[PASS] LLDP Builder\n");

    /* Test 8: STP TCN BPDU */
    memset(buf, 0, sizeof(buf));
    int stp_len = build_packet_stp(buf, &rng);
    eth = (struct ether_header_custom *)buf;
    static const uint8_t stp_dst_exp[6] = {0x01, 0x80, 0xC2, 0x00, 0x00, 0x00};
    if (memcmp(eth->dest, stp_dst_exp, 6) != 0)
        errx(1, "FAIL: STP dst MAC incorrect");
    if (ntohs(eth->type) != 7)
        errx(1, "FAIL: STP 802.3 length field incorrect (got %d)", ntohs(eth->type));
    uint8_t *stp_llc = buf + sizeof(struct ether_header_custom);
    if (stp_llc[0] != 0x42 || stp_llc[1] != 0x42 || stp_llc[2] != 0x03)
        errx(1, "FAIL: STP LLC header incorrect");
    if (stp_llc[6] != 0x80)
        errx(1, "FAIL: STP BPDU type not TCN (0x80)");
    if (stp_len != 60)
        errx(1, "FAIL: STP frame length %d (expected 60)", stp_len);
    printf("[PASS] STP TCN Builder\n");

    /* Test 9: QinQ double-tagging */
    memset(buf, 0, sizeof(buf));
    conf.vlan_id       = 100;
    conf.qinq_outer_vid = 200;
    int qq_len = build_packet_mac(buf, &rng);
    uint16_t outer_tpid, outer_tci, inner_tpid, inner_tci;
    memcpy(&outer_tpid, buf + 12, 2);
    memcpy(&outer_tci,  buf + 14, 2);
    memcpy(&inner_tpid, buf + 16, 2);
    memcpy(&inner_tci,  buf + 18, 2);
    if (ntohs(outer_tpid) != ETHERTYPE_8021AD)
        errx(1, "FAIL: QinQ outer TPID incorrect (got 0x%04x)", ntohs(outer_tpid));
    if ((ntohs(outer_tci) & 0x0FFF) != 200)
        errx(1, "FAIL: QinQ outer VID incorrect (got %d)", ntohs(outer_tci) & 0x0FFF);
    if (ntohs(inner_tpid) != ETHERTYPE_VLAN)
        errx(1, "FAIL: QinQ inner TPID not 0x8100 (got 0x%04x)", ntohs(inner_tpid));
    if ((ntohs(inner_tci) & 0x0FFF) != 100)
        errx(1, "FAIL: QinQ inner VID incorrect (got %d)", ntohs(inner_tci) & 0x0FFF);
    if (qq_len < 68)
        errx(1, "FAIL: QinQ frame too short (%d)", qq_len);
    conf.vlan_id = 0; conf.qinq_outer_vid = 0;
    printf("[PASS] QinQ Double-Tag\n");

    /* Test 10: IGMP Membership Report */
    memset(buf, 0, sizeof(buf));
    int igmp_len = build_packet_igmp(buf, &rng);
    eth = (struct ether_header_custom *)buf;
    if (eth->dest[0] != 0x01 || eth->dest[1] != 0x00 || eth->dest[2] != 0x5E)
        errx(1, "FAIL: IGMP dst MAC not 01:00:5E multicast prefix");
    if (ntohs(eth->type) != ETHERTYPE_IP)
        errx(1, "FAIL: IGMP EtherType not IP");
    iph = (struct ip *)(buf + sizeof(*eth));
    if (iph->ip_p != 2)
        errx(1, "FAIL: IGMP IP protocol not 2");
    if (iph->ip_ttl != 1)
        errx(1, "FAIL: IGMP IP TTL not 1");
    uint8_t *igmp_bytes = buf + sizeof(*eth) + sizeof(struct ip);
    if (igmp_bytes[0] != 0x16)
        errx(1, "FAIL: IGMP type not 0x16 (Membership Report v2)");
    if (igmp_len != 60)
        errx(1, "FAIL: IGMP frame length %d (expected 60)", igmp_len);
    printf("[PASS] IGMP Builder\n");

    /* Test 11: payload pattern */
    memset(buf, 0, sizeof(buf));
    conf.packet_size   = 128;
    conf.payload_pattern = 2;
    int pl_len = build_packet_mac(buf, &rng);
    if (buf[34] != 0xDE || buf[35] != 0xAD || buf[36] != 0xBE || buf[37] != 0xEF)
        errx(1, "FAIL: payload pattern 0xDEADBEEF not present at offset 34");
    if (pl_len != 128)
        errx(1, "FAIL: payload pattern frame length %d (expected 128)", pl_len);
    conf.packet_size = 0; conf.payload_pattern = 0;
    printf("[PASS] Payload Pattern\n");

    /* Test 12: IP checksum correctness */
    {
        uint8_t hdr[20] = {0x45,0x00,0x00,0x3c,0x1c,0x46,0x40,0x00,
                           0x40,0x06,0x00,0x00,0xac,0x10,0x0a,0x63,
                           0xac,0x10,0x0a,0x0c};
        uint16_t ck = ip_checksum(hdr, 20);
        /* known correct checksum for this header: 0xb1e6 */
        hdr[10] = ck & 0xFF; hdr[11] = (ck >> 8) & 0xFF;
        if (ip_checksum(hdr, 20) != 0)
            errx(1, "FAIL: IP checksum verification failed on known header");
        printf("[PASS] IP Checksum\n");
    }

    /* Test 13: TCO scenario parser */
    {
        char path[] = "/tmp/basidium-tco-selftest.XXXXXX";
        int fd = mkstemp(path);
        if (fd < 0) errx(1, "FAIL: TCO could not create temp file");
        FILE *fp = fdopen(fd, "w");
        if (!fp) { close(fd); unlink(path); errx(1, "FAIL: TCO fdopen failed"); }
        fputs("# header comment\n"
              "\n"
              "mac  1000  30\n"
              "pfc  5000  60  nccl\n"
              "arp   200  15\n", fp);
        fclose(fp);

        int rc = tco_load(path);
        unlink(path);
        if (rc != 0) errx(1, "FAIL: TCO parser rejected valid scenario");
        if (tco_scenario.step_count != 3)
            errx(1, "FAIL: TCO step_count=%d (expected 3)", tco_scenario.step_count);
        if (tco_scenario.steps[0].mode != MODE_MAC
            || tco_scenario.steps[0].pps != 1000
            || tco_scenario.steps[0].duration_s != 30
            || tco_scenario.steps[0].run_nccl != 0)
            errx(1, "FAIL: TCO step 0 fields incorrect");
        if (tco_scenario.steps[1].mode != MODE_PFC
            || tco_scenario.steps[1].pps != 5000
            || tco_scenario.steps[1].duration_s != 60
            || tco_scenario.steps[1].run_nccl != 1)
            errx(1, "FAIL: TCO step 1 fields incorrect");
        if (tco_scenario.steps[2].mode != MODE_ARP
            || tco_scenario.steps[2].pps != 200
            || tco_scenario.steps[2].duration_s != 15)
            errx(1, "FAIL: TCO step 2 fields incorrect");

        /* Negative: unknown mode must be rejected. Suppress expected stderr. */
        char bad_path[] = "/tmp/basidium-tco-bad.XXXXXX";
        int bfd = mkstemp(bad_path);
        if (bfd < 0) errx(1, "FAIL: TCO could not create temp file");
        FILE *bfp = fdopen(bfd, "w");
        if (!bfp) { close(bfd); unlink(bad_path); errx(1, "FAIL: TCO fdopen failed"); }
        fputs("bogus 1000 10\n", bfp);
        fclose(bfp);

        fflush(stderr);
        int saved_stderr = dup(STDERR_FILENO);
        if (!freopen("/dev/null", "w", stderr)) { /* non-fatal */ }
        int bad_rc = tco_load(bad_path);
        fflush(stderr);
        if (saved_stderr >= 0) {
            dup2(saved_stderr, STDERR_FILENO);
            close(saved_stderr);
        }
        unlink(bad_path);
        if (bad_rc == 0) errx(1, "FAIL: TCO accepted unknown mode");

        memset(&tco_scenario, 0, sizeof(tco_scenario));
        printf("[PASS] TCO Scenario Parser\n");
    }

    /* Test 14: NCCL output parser */
    {
        struct nccl_result r;
        const char *data =
            "  33554432  8388608  float  sum  820.5  40.89  76.67  N/A  0\n";
        if (!nccl_parse_line(data, &r))
            errx(1, "FAIL: NCCL parser rejected valid data line");
        if (r.msg_size != 33554432)
            errx(1, "FAIL: NCCL msg_size=%zu (expected 33554432)", r.msg_size);
        if (r.alg_bw < 40.88 || r.alg_bw > 40.90)
            errx(1, "FAIL: NCCL alg_bw=%.3f (expected ~40.89)", r.alg_bw);
        if (r.bus_bw < 76.66 || r.bus_bw > 76.68)
            errx(1, "FAIL: NCCL bus_bw=%.3f (expected ~76.67)", r.bus_bw);

        if (nccl_parse_line("# size  count  type  redop  time  algbw  busbw\n", &r))
            errx(1, "FAIL: NCCL parser accepted header/comment line");
        if (nccl_parse_line("\n", &r))
            errx(1, "FAIL: NCCL parser accepted blank line");
        if (nccl_parse_line("   123  456\n", &r))
            errx(1, "FAIL: NCCL parser accepted truncated line");
        printf("[PASS] NCCL Output Parser\n");
    }

    printf("All 14 Tests Passed.\n");
    return 0;
}
