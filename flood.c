/*
 * flood.c — packet builders, worker threads, sniffer, RNG, selftest
 */
#define _GNU_SOURCE
#include "flood.h"

#include <arpa/inet.h>
#include <err.h>
#include <netinet/ip.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/time.h>
#include <time.h>
#include <unistd.h>

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

/* ---- Helpers ---- */

void randomize_mac(uint8_t *mac) {
    if (conf.stealth) {
        memcpy(mac, conf.stealth_oui, 3);
        mac[3] = rand() % 256;
        mac[4] = rand() % 256;
        mac[5] = rand() % 256;
    } else {
        for (int i = 0; i < 6; i++)
            mac[i] = rand() % 256;
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

uint32_t get_target_ip(void) {
    if (conf.target_count == 0)
        return (uint32_t)rand();
    struct target t = conf.targets[rand() % conf.target_count];
    uint32_t rand_suffix = rand() & ~t.mask;
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
         * is broadcasting our injected traffic — it has failed open to hub mode. */
        if (conf.detect_failopen && !fail_open_detected &&
                ntohs(eth->type) == ETHERTYPE_IP && hdr.caplen >= 34) {
            struct ip *iph = (struct ip *)(pkt + sizeof(struct ether_header_custom));
            if (ntohs(iph->ip_id) == probe_signature) {
                atomic_store(&fail_open_detected, 1);
                log_event("FAIL_OPEN",
                          "Switch fail-open detected — injected frames echoed back");
            }
        }

        /* Adaptive mode: count broadcast frames as a fail-open indicator.
         * A rising bcast_rx rate suggests the switch is now in hub mode,
         * echoing all traffic as broadcasts. Workers check this to throttle. */
        if (conf.adaptive && memcmp(eth->dest, bcast, 6) == 0)
            atomic_fetch_add(&bcast_rx, 1);
    }

    pcap_close(sniffer);
    return NULL;
}

/* ---- 802.1Q VLAN tag insertion ---- */

/*
 * Insert a 4-byte 802.1Q tag between src MAC and EtherType in an already-built
 * frame.  Uses memmove so src/dst overlap is handled correctly.
 *
 * Before: [dst:6][src:6][ethertype:2][payload...]
 * After:  [dst:6][src:6][0x8100:2][TCI:2][ethertype:2][payload...]
 *
 * Caller must ensure buffer has at least 4 bytes of headroom beyond *len.
 */
void vlan_tag_frame(uint8_t *buffer, int *len) {
    if (!conf.vlan_id) return;

    /* shift EtherType + payload right 4 bytes */
    memmove(buffer + 16, buffer + 12, *len - 12);

    /* TPID */
    uint16_t tpid = htons(ETHERTYPE_VLAN);
    memcpy(buffer + 12, &tpid, 2);

    /* VID: use range if configured */
    int vid = conf.vlan_id;
    if (conf.vlan_range_end > conf.vlan_id)
        vid = conf.vlan_id +
              (rand() % (conf.vlan_range_end - conf.vlan_id + 1));

    /* TCI: PCP(3 bits) | DEI(1 bit, always 0) | VID(12 bits) */
    uint16_t tci = htons(((conf.vlan_pcp & 0x7) << 13) | (vid & 0x0FFF));
    memcpy(buffer + 14, &tci, 2);

    *len += 4;
}

/*
 * Insert a 4-byte 802.1ad outer TPID (0x88A8) at offset 12, pushing any
 * existing 802.1Q inner tag and payload right.  Call after vlan_tag_frame
 * so the inner tag is already in place.
 *
 * Result with both -V and --qinq:
 *   [dst][src][0x88A8][outer TCI][0x8100][inner TCI][etype][payload]
 *
 * Result with --qinq only (no -V):
 *   [dst][src][0x88A8][outer TCI][etype][payload]
 */
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

/*
 * Fill the payload region of a frame (bytes hdr_end..frame_len) with the
 * configured pattern.  payload_pattern: 0=zeros, 1=0xFF, 2=0xDEADBEEF, 3=incr.
 * Applied only when a larger frame size is requested via -J.
 */
static void apply_payload_pattern(uint8_t *buf, int hdr_end, int frame_len) {
    if (frame_len <= hdr_end) return;

    switch (conf.payload_pattern) {
    case 1: /* all 0xFF */
        memset(buf + hdr_end, 0xFF, frame_len - hdr_end);
        break;
    case 2: /* 0xDEADBEEF repeating */
        for (int i = hdr_end; i < frame_len; i++)
            buf[i] = (uint8_t[]){0xDE, 0xAD, 0xBE, 0xEF}[(i - hdr_end) & 3];
        break;
    case 3: /* incrementing byte value */
        for (int i = hdr_end; i < frame_len; i++)
            buf[i] = (uint8_t)(i - hdr_end);
        break;
    default: /* 0=zeros — already zero from caller's memset */
        break;
    }
}

/* ---- Frame Builders ---- */

int build_packet_mac(uint8_t *buffer) {
    struct ether_header_custom *eth = (struct ether_header_custom *)buffer;
    uint8_t src[6];

    do { randomize_mac(src); }
    while (conf.learning && is_learned_mac(src));

    memcpy(eth->source, src, 6);
    randomize_mac(eth->dest);
    eth->type = htons(ETHERTYPE_IP);

    struct ip *iph = (struct ip *)(buffer + sizeof(struct ether_header_custom));
    int frame_len = (conf.packet_size > 60) ? conf.packet_size : 60;
    if (frame_len > MAX_PACKET_SIZE)
        frame_len = MAX_PACKET_SIZE;

    iph->ip_hl  = 5;
    iph->ip_v   = 4;
    iph->ip_len = htons(frame_len - sizeof(struct ether_header_custom));
    iph->ip_src.s_addr = get_target_ip();
    iph->ip_dst.s_addr = get_target_ip();
    iph->ip_id  = htons(probe_signature); /* embed probe for fail-open detection */

    /* fill payload region (after IP header) with configured pattern */
    int hdr_end = (int)(sizeof(struct ether_header_custom) + sizeof(struct ip));
    apply_payload_pattern(buffer, hdr_end, frame_len);

    vlan_tag_frame(buffer, &frame_len);
    qinq_tag_frame(buffer, &frame_len);
    return frame_len;
}

int build_packet_arp(uint8_t *buffer) {
    struct ether_header_custom *eth = (struct ether_header_custom *)buffer;
    struct arp_header *arp =
        (struct arp_header *)(buffer + sizeof(struct ether_header_custom));

    uint8_t mac[6];
    randomize_mac(mac);

    memcpy(eth->source, mac, 6);
    memset(eth->dest, 0xff, 6);
    eth->type = htons(ETHERTYPE_ARP);

    arp->htype = htons(1);
    arp->ptype = htons(ETHERTYPE_IP);
    arp->hlen  = 6;
    arp->plen  = 4;
    arp->oper  = htons(1); /* request */
    memcpy(arp->sha, mac, 6);
    arp->spa = get_target_ip();
    memset(arp->tha, 0, 6);
    arp->tpa = get_target_ip();

    int len = (int)(sizeof(struct ether_header_custom) + sizeof(struct arp_header));
    vlan_tag_frame(buffer, &len);
    qinq_tag_frame(buffer, &len);
    return len;
}

int build_packet_dhcp(uint8_t *buffer) {
    struct ether_header_custom *eth = (struct ether_header_custom *)buffer;
    struct ip *iph =
        (struct ip *)(buffer + sizeof(*eth));
    struct udp_header *udph =
        (struct udp_header *)(buffer + sizeof(*eth) + sizeof(struct ip));
    struct dhcp_packet *dhcp =
        (struct dhcp_packet *)(buffer + sizeof(*eth) + sizeof(struct ip) +
                               sizeof(struct udp_header));

    uint8_t mac[6];
    randomize_mac(mac);

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

    udph->src_port = htons(68);
    udph->dst_port = htons(67);
    udph->len  = htons(sizeof(struct udp_header) + sizeof(struct dhcp_packet));
    udph->check = 0;

    dhcp->op    = 1; /* BootRequest */
    dhcp->htype = 1;
    dhcp->hlen  = 6;
    dhcp->xid   = htonl(rand());

    if (conf.random_client_mac) {
        uint8_t rand_mac[6];
        for (int i = 0; i < 6; i++) rand_mac[i] = rand() % 256;
        memcpy(dhcp->chaddr, rand_mac, 6);
    } else {
        memcpy(dhcp->chaddr, mac, 6);
    }

    dhcp->magic_cookie = htonl(0x63825363);
    dhcp->options[0]   = 53; /* DHCP Message Type */
    dhcp->options[1]   = 1;
    dhcp->options[2]   = 1;  /* Discover */
    dhcp->options[3]   = 255; /* End */

    int len = (int)(sizeof(*eth) + sizeof(struct ip) + sizeof(struct udp_header) +
                    sizeof(struct dhcp_packet));
    vlan_tag_frame(buffer, &len);
    qinq_tag_frame(buffer, &len);
    return len;
}

/*
 * build_packet_nd — IPv6 Neighbor Discovery (ICMPv6 NS) flood
 *
 * Generates Neighbor Solicitation frames with random source MACs and target
 * IPv6 addresses, stressing the ND/NDP table on switches and routers.
 * Note: ICMPv6 checksum is not computed — switches forward the frame
 * regardless, achieving the ND table flooding effect.
 *
 * Wire format (86 bytes):
 *   [Eth: 14][IPv6: 40][ICMPv6 NS + SLLA option: 32]
 */
int build_packet_nd(uint8_t *buffer) {
    uint8_t src_mac[6];
    randomize_mac(src_mac);

    /* generate a random target IPv6 address (any scope is fine for flooding) */
    uint8_t target_ip6[16];
    for (int i = 0; i < 16; i++)
        target_ip6[i] = (uint8_t)rand();

    /* solicited-node multicast destination MAC: 33:33:ff + last 3 bytes of target */
    struct ether_header_custom *eth = (struct ether_header_custom *)buffer;
    eth->dest[0] = 0x33; eth->dest[1] = 0x33; eth->dest[2] = 0xff;
    eth->dest[3] = target_ip6[13];
    eth->dest[4] = target_ip6[14];
    eth->dest[5] = target_ip6[15];
    memcpy(eth->source, src_mac, 6);
    eth->type = htons(0x86DD); /* IPv6 */

    struct ipv6_header *ip6 =
        (struct ipv6_header *)(buffer + sizeof(struct ether_header_custom));
    ip6->vcf         = htonl(0x60000000); /* version=6, TC=0, FL=0 */
    ip6->payload_len = htons(sizeof(struct icmpv6_ns_pkt));
    ip6->next_header = 58;   /* ICMPv6 */
    ip6->hop_limit   = 255;  /* required by RFC 4861 */

    /* source: link-local fe80::/64 + EUI-64 from source MAC */
    memset(ip6->src, 0, 16);
    ip6->src[0] = 0xfe; ip6->src[1] = 0x80;
    ip6->src[8]  = src_mac[0] ^ 0x02; /* flip universal/local bit */
    ip6->src[9]  = src_mac[1];
    ip6->src[10] = src_mac[2];
    ip6->src[11] = 0xff;
    ip6->src[12] = 0xfe;
    ip6->src[13] = src_mac[3];
    ip6->src[14] = src_mac[4];
    ip6->src[15] = src_mac[5];

    /* destination: solicited-node multicast ff02::1:ff/104 + last 24 bits */
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
    ns->checksum = 0; /* not computed — switches forward regardless */
    ns->reserved = 0;
    memcpy(ns->target, target_ip6, 16);
    ns->opt_type = 1;     /* Source Link-Layer Address */
    ns->opt_len  = 1;     /* 1 × 8 bytes */
    memcpy(ns->opt_mac, src_mac, 6);

    return (int)(sizeof(struct ether_header_custom) +
                 sizeof(struct ipv6_header) +
                 sizeof(struct icmpv6_ns_pkt)); /* 86 bytes */
}

/*
 * build_packet_igmp — IGMPv2 Membership Report flood
 *
 * Floods random multicast groups with IGMPv2 Membership Reports (type 0x16).
 * Switches that perform IGMP snooping process these in software; exhausting
 * the snooping table forces them to either flood all multicast or drop it.
 * This is a critical failure mode for RoCE/RDMA fabrics that rely on
 * multicast for group communication.
 *
 * Wire format (60 bytes, padded):
 *   [Eth:14 — dst=01:00:5E:xx:xx:xx, src=random, EtherType=0x0800]
 *   [IPv4:20 — dst=group, TTL=1, proto=2]
 *   [IGMP:8  — type=0x16, max_resp=0, checksum=0, group=same]
 *   [zero pad to 60 bytes]
 */
int build_packet_igmp(uint8_t *buffer) {
    /* random multicast group in 224.0.0.0 - 239.255.255.255 */
    uint32_t group_h = 0xE0000000 | ((uint32_t)rand() & 0x0FFFFFFF);
    uint32_t group_n = htonl(group_h);

    uint8_t src[6];
    randomize_mac(src);

    struct ether_header_custom *eth = (struct ether_header_custom *)buffer;
    /* multicast MAC: 01:00:5E + lower 23 bits of group IP */
    eth->dest[0] = 0x01; eth->dest[1] = 0x00; eth->dest[2] = 0x5E;
    eth->dest[3] = (group_h >> 16) & 0x7F;
    eth->dest[4] = (group_h >>  8) & 0xFF;
    eth->dest[5] =  group_h        & 0xFF;
    memcpy(eth->source, src, 6);
    eth->type = htons(ETHERTYPE_IP);

    struct ip *iph = (struct ip *)(buffer + sizeof(*eth));
    iph->ip_v   = 4;
    iph->ip_hl  = 5;
    iph->ip_tos = 0xC0;  /* DSCP CS6, per RFC 2236 */
    iph->ip_ttl = 1;     /* IGMP reports use TTL=1 */
    iph->ip_p   = 2;     /* IGMP */
    iph->ip_src.s_addr = get_target_ip();
    iph->ip_dst.s_addr = group_n;
    iph->ip_len = htons((uint16_t)(sizeof(struct ip) + sizeof(struct igmp_header)));

    struct igmp_header *igmp =
        (struct igmp_header *)(buffer + sizeof(*eth) + sizeof(struct ip));
    igmp->type     = 0x16; /* IGMPv2 Membership Report */
    igmp->max_resp = 0;
    igmp->checksum = 0;    /* not computed; switch snooping processes regardless */
    igmp->group    = group_n;

    int len = (int)(sizeof(*eth) + sizeof(struct ip) + sizeof(struct igmp_header));
    if (len < 60) { memset(buffer + len, 0, 60 - len); len = 60; }
    vlan_tag_frame(buffer, &len);
    qinq_tag_frame(buffer, &len);
    return len;
}

/*
 * build_packet_lldp — Link Layer Discovery Protocol frame
 *
 * Injects LLDP frames to the nearest-bridge multicast address (01:80:C2:00:00:0E).
 * Each frame carries three mandatory TLVs (Chassis ID, Port ID, TTL) plus End-of-LLDPDU.
 * Switches process LLDP in software; flooding stresses the CPU-path and LLDP neighbor table.
 *
 * Wire format:
 *   [Eth:14 — dst=01:80:C2:00:00:0E, src=random, EtherType=0x88CC]
 *   [TLV: Chassis ID, type=1, subtype=4(MAC), 7 bytes]
 *   [TLV: Port ID,    type=2, subtype=7(local), 6 bytes]
 *   [TLV: TTL,        type=3, 2 bytes = 120s]
 *   [TLV: End,        type=0, len=0]
 */
int build_packet_lldp(uint8_t *buffer) {
    static const uint8_t lldp_dst[6] = {0x01, 0x80, 0xC2, 0x00, 0x00, 0x0E};

    uint8_t src[6];
    randomize_mac(src);

    struct ether_header_custom *eth = (struct ether_header_custom *)buffer;
    memcpy(eth->dest,   lldp_dst, 6);
    memcpy(eth->source, src,      6);
    eth->type = htons(ETHERTYPE_LLDP);

    uint8_t *p = buffer + sizeof(struct ether_header_custom);
    int off = 0;

    /* Chassis ID TLV: type=1, len=7 (1 subtype byte + 6 MAC bytes) */
    uint16_t tlv_hdr = htons((1u << 9) | 7);
    memcpy(p + off, &tlv_hdr, 2); off += 2;
    p[off++] = 4;               /* subtype: MAC address */
    memcpy(p + off, src, 6);    off += 6;

    /* Port ID TLV: type=2, len=6 (1 subtype + 5 char string "port1") */
    tlv_hdr = htons((2u << 9) | 6);
    memcpy(p + off, &tlv_hdr, 2); off += 2;
    p[off++] = 7;               /* subtype: locally assigned */
    memcpy(p + off, "port1", 5); off += 5;

    /* TTL TLV: type=3, len=2, value=120 seconds */
    tlv_hdr = htons((3u << 9) | 2);
    memcpy(p + off, &tlv_hdr, 2); off += 2;
    uint16_t ttl_val = htons(120);
    memcpy(p + off, &ttl_val, 2); off += 2;

    /* End-of-LLDPDU TLV: type=0, len=0 */
    tlv_hdr = 0;
    memcpy(p + off, &tlv_hdr, 2); off += 2;

    int len = (int)sizeof(struct ether_header_custom) + off;
    if (len < 60) { memset(buffer + len, 0, 60 - len); len = 60; }
    return len;
}

/*
 * build_packet_stp — STP Topology Change Notification BPDU
 *
 * Each TCN BPDU causes the receiving switch to flush its MAC table and
 * temporarily flood all unknown unicast — identical to a CAM flush event.
 * Sending a stream of TCN BPDUs keeps the switch in permanent flood mode
 * without filling its CAM table directly.
 *
 * STP uses 802.3 LLC encapsulation (no standard EtherType):
 *   [dst:6=01:80:C2:00:00:00][src:6][length:2=7]
 *   [LLC: 0x42 0x42 0x03]
 *   [BPDU: proto=0x0000, version=0, type=0x80 (TCN)]
 *   [zero pad to 60 bytes]
 */
int build_packet_stp(uint8_t *buffer) {
    static const uint8_t stp_dst[6] = {0x01, 0x80, 0xC2, 0x00, 0x00, 0x00};

    uint8_t src[6];
    randomize_mac(src);
    src[0] &= 0xfe; /* STP requires unicast source */

    struct ether_header_custom *eth = (struct ether_header_custom *)buffer;
    memcpy(eth->dest,   stp_dst, 6);
    memcpy(eth->source, src,     6);
    /* 802.3 length field: LLC(3) + TCN BPDU(4) = 7 */
    eth->type = htons(7);

    uint8_t *p = buffer + sizeof(struct ether_header_custom);

    /* LLC header */
    p[0] = 0x42; /* DSAP: STP */
    p[1] = 0x42; /* SSAP: STP */
    p[2] = 0x03; /* Control: Unnumbered Information */

    /* TCN BPDU */
    p[3] = 0x00; /* Protocol ID (MSB) */
    p[4] = 0x00; /* Protocol ID (LSB) */
    p[5] = 0x00; /* Protocol Version: STP */
    p[6] = 0x80; /* BPDU Type: Topology Change Notification */

    int len = (int)sizeof(struct ether_header_custom) + 7;
    memset(buffer + len, 0, 60 - len);
    return 60;
}

/*
 * build_packet_pfc — 802.1Qbb Priority Flow Control PAUSE frame
 *
 * Wire format (60 bytes, padded):
 *   [dst:6=01:80:C2:00:00:01][src:6=random][type:2=0x8808]
 *   [opcode:2=0x0101][PEV:2][quanta[0..7]:16]
 *   [zero padding to 60 bytes]
 *
 * Only the target priority class gets a non-zero quanta value.
 * VLAN tagging is intentionally not applied to PFC frames.
 */
int build_packet_pfc(uint8_t *buffer) {
    static const uint8_t pfc_dst[6] = {0x01, 0x80, 0xC2, 0x00, 0x00, 0x01};

    struct ether_header_custom *eth = (struct ether_header_custom *)buffer;

    uint8_t src[6];
    randomize_mac(src);
    memcpy(eth->source, src, 6);
    memcpy(eth->dest, pfc_dst, 6);          /* must be written after randomize */
    eth->type = htons(ETHERTYPE_PAUSE);

    uint8_t *p = buffer + sizeof(struct ether_header_custom);

    /* MAC Control opcode: 0x0101 = PFC PAUSE */
    p[0] = 0x01;
    p[1] = 0x01;

    /* Priority Enable Vector: one bit per priority class */
    uint16_t pev = htons((uint16_t)(1u << (conf.pfc_priority & 0x7)));
    memcpy(p + 2, &pev, 2);

    /* 8 × 16-bit quanta; only the target priority gets the configured value */
    memset(p + 4, 0, 16);
    uint16_t q = htons((uint16_t)conf.pfc_quanta);
    memcpy(p + 4 + (conf.pfc_priority & 0x7) * 2, &q, 2);

    /* Zero-pad to minimum Ethernet frame size */
    int total = (int)sizeof(struct ether_header_custom) + 2 + 2 + 16; /* 34 */
    memset(buffer + total, 0, 60 - total);
    return 60;
}

/* ---- Fast RNG (Xorshift128+) ---- */

struct rng_state { uint64_t s[2]; };

static inline uint64_t xorshift128plus(uint64_t s[2]) {
    uint64_t x = s[0];
    uint64_t const y = s[1];
    s[0] = y;
    x ^= x << 23;
    s[1] = x ^ y ^ (x >> 17) ^ (y >> 26);
    return s[1] + y;
}

static void rng_init(struct rng_state *rng, int seed_offset) {
    rng->s[0] = (uint64_t)time(NULL) + seed_offset;
    rng->s[1] = (uint64_t)getpid()  + seed_offset;
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
    case 1: len = build_packet_arp(buffer);  break;
    case 2: len = build_packet_dhcp(buffer); break;
    case 3: len = build_packet_pfc(buffer);  break;
    case 4: len = build_packet_nd(buffer);   break;
    case 5: len = build_packet_lldp(buffer); break;
    case 6: len = build_packet_stp(buffer);  break;
    case 7: len = build_packet_igmp(buffer); break;
    default: len = build_packet_mac(buffer); break;
    }

    struct ether_header_custom *eth = (struct ether_header_custom *)buffer;
    uint64_t local_sent = 0;

    /* fast path: mode 0, no stealth/learning/targeting/VLAN-range */
    int use_fast_mac = (conf.mode == 0 && !conf.learning && !conf.stealth &&
                        conf.target_count == 0 &&
                        !(conf.vlan_range_end > conf.vlan_id));

    /* Adaptive throttle: pause extra when bcast_rx indicates fail-open.
     * We sample every 1024 packets; if bcast_rx has grown significantly
     * since last check we insert a short sleep. */
    unsigned long long last_bcast_rx = 0;

    /* Standby: wait for TUI user to press start before injecting anything */
    while (!is_started && is_running)
        usleep(50000);

    uint64_t burst_local = 0; /* frames sent in current burst */

    while (is_running) {
        if (conf.count > 0 && (unsigned long long)total_sent >= (unsigned long long)conf.count)
            break;

        /* Pause support */
        while (is_paused && is_running)
            usleep(50000);

        /* ---- Fast Path ---- */
        if (use_fast_mac) {
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
            case 1: len = build_packet_arp(buffer);  break;
            case 2: len = build_packet_dhcp(buffer); break;
            case 3: len = build_packet_pfc(buffer);  break;
            case 4: len = build_packet_nd(buffer);   break;
            case 5: len = build_packet_lldp(buffer); break;
            case 6: len = build_packet_stp(buffer);  break;
            case 7: len = build_packet_igmp(buffer); break;
            default: len = build_packet_mac(buffer); break;
            }
        }

        /* Send */
        if (global_pd) {
            struct pcap_pkthdr pkthdr;
            gettimeofday(&pkthdr.ts, NULL);
            pkthdr.caplen = pkthdr.len = len;
            pcap_dump((u_char *)global_pd, &pkthdr, buffer);
            local_sent++;
        } else if (pcap_inject(inj, buffer, len) > 0) {
            local_sent++;
        }

        /* Burst mode: send burst_count frames back-to-back, then pause gap_ms */
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

            /* Rate limiting (skip when burst mode controls pacing) */
            if (conf.pps > 0 && conf.burst_count == 0)
                usleep((1024 * 1000000ULL / conf.pps) * conf.threads);

            /* Adaptive throttle: if broadcast RX is climbing fast, back off */
            if (conf.adaptive) {
                unsigned long long cur_bcast = (unsigned long long)bcast_rx;
                if (cur_bcast - last_bcast_rx > 2048)
                    usleep(5000); /* 5ms extra sleep when fail-open detected */
                last_bcast_rx = cur_bcast;
            }
        }
    }

    atomic_fetch_add(&total_sent, local_sent % 1024);

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
        if (rc == 0) continue; /* timeout */
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

/*
 * Automatically ramp conf.pps from sweep_start to sweep_end in steps of
 * sweep_step, holding each rate for sweep_hold seconds.
 * Records achieved PPS per step in sweep_step_pps[].
 * Sets is_running=0 when the sweep completes.
 */
void *sweep_thread_func(void *arg) {
    (void)arg;

    /* wait for user to start (TUI standby) or is_started already set (CLI) */
    while (!is_started && is_running)
        sleep(1);

    int total = (conf.sweep_end - conf.sweep_start) / conf.sweep_step + 1;
    if (total < 1) total = 1;
    if (total > MAX_SWEEP_STEPS) total = MAX_SWEEP_STEPS;
    atomic_store(&sweep_total_steps, total);

    int step = 0;
    for (int pps = conf.sweep_start;
         pps <= conf.sweep_end && is_running && step < MAX_SWEEP_STEPS;
         pps += conf.sweep_step, step++) {

        conf.pps = pps;
        atomic_store(&sweep_step_num, step + 1);

        unsigned long long sent_start = (unsigned long long)total_sent;

        for (int t = conf.sweep_hold; t > 0 && is_running; t--) {
            atomic_store(&sweep_hold_rem, t);
            sleep(1);
        }

        /* record average achieved PPS over the hold window */
        unsigned long long sent_end = (unsigned long long)total_sent;
        sweep_step_pps[step] = (conf.sweep_hold > 0)
            ? (sent_end - sent_start) / conf.sweep_hold
            : 0;

        char msg[64];
        snprintf(msg, sizeof(msg), "step %d/%d pps=%d achieved=%llu",
                 step + 1, total, pps, sweep_step_pps[step]);
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

    /* Test 1: MAC */
    memset(buf, 0, sizeof(buf));
    len = build_packet_mac(buf);
    if (len < 60) errx(1, "FAIL: MAC packet too small (%d)", len);
    struct ether_header_custom *eth = (struct ether_header_custom *)buf;
    if (ntohs(eth->type) != ETHERTYPE_IP) errx(1, "FAIL: MAC ethertype incorrect");
    printf("[PASS] MAC Builder\n");

    /* Test 2: ARP */
    memset(buf, 0, sizeof(buf));
    build_packet_arp(buf);
    eth = (struct ether_header_custom *)buf;
    if (ntohs(eth->type) != ETHERTYPE_ARP) errx(1, "FAIL: ARP ethertype incorrect");
    struct arp_header *arp = (struct arp_header *)(buf + sizeof(*eth));
    if (ntohs(arp->oper) != 1) errx(1, "FAIL: ARP opcode not Request");
    printf("[PASS] ARP Builder\n");

    /* Test 3: DHCP */
    memset(buf, 0, sizeof(buf));
    build_packet_dhcp(buf);
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
    int base_len = build_packet_mac(buf); /* includes vlan_tag_frame call */
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
    if (base_len < 64) /* 60 byte min + 4 tag */
        errx(1, "FAIL: VLAN-tagged frame too short (%d)", base_len);
    conf.vlan_id = 0;
    conf.vlan_pcp = 0;
    printf("[PASS] VLAN Tagging\n");

    /* Test 5: PFC PAUSE frame */
    memset(buf, 0, sizeof(buf));
    conf.pfc_priority = 3;
    conf.pfc_quanta   = 0xFFFF;
    int pfc_len = build_packet_pfc(buf);
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
    /* verify other quanta are zero */
    for (int i = 0; i < 8; i++) {
        if (i == 3) continue;
        uint16_t q;
        memcpy(&q, buf + 18 + i * 2, 2);
        if (q != 0) errx(1, "FAIL: PFC quanta for priority %d should be 0", i);
    }
    if (pfc_len != 60)
        errx(1, "FAIL: PFC frame length %d (expected 60)", pfc_len);
    printf("[PASS] PFC Builder\n");

    /* Test 6: IPv6 ND (Neighbor Solicitation) */
    memset(buf, 0, sizeof(buf));
    int nd_len = build_packet_nd(buf);
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
    int lldp_len = build_packet_lldp(buf);
    eth = (struct ether_header_custom *)buf;
    static const uint8_t lldp_dst_exp[6] = {0x01, 0x80, 0xC2, 0x00, 0x00, 0x0E};
    if (memcmp(eth->dest, lldp_dst_exp, 6) != 0)
        errx(1, "FAIL: LLDP dst MAC incorrect");
    if (ntohs(eth->type) != ETHERTYPE_LLDP)
        errx(1, "FAIL: LLDP EtherType incorrect (got 0x%04x)", ntohs(eth->type));
    /* verify Chassis ID TLV type=1 in first two bytes after ethernet header */
    uint16_t lldp_tlv1;
    memcpy(&lldp_tlv1, buf + sizeof(struct ether_header_custom), 2);
    if ((ntohs(lldp_tlv1) >> 9) != 1)
        errx(1, "FAIL: LLDP first TLV not Chassis ID (type %d)", ntohs(lldp_tlv1) >> 9);
    if (lldp_len != 60)
        errx(1, "FAIL: LLDP frame length %d (expected 60)", lldp_len);
    printf("[PASS] LLDP Builder\n");

    /* Test 8: STP TCN BPDU */
    memset(buf, 0, sizeof(buf));
    int stp_len = build_packet_stp(buf);
    eth = (struct ether_header_custom *)buf;
    static const uint8_t stp_dst_exp[6] = {0x01, 0x80, 0xC2, 0x00, 0x00, 0x00};
    if (memcmp(eth->dest, stp_dst_exp, 6) != 0)
        errx(1, "FAIL: STP dst MAC incorrect");
    /* length field = 7 */
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
    int qq_len = build_packet_mac(buf);  /* calls vlan_tag_frame + qinq_tag_frame */
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
    if (qq_len < 68) /* 60 min + 4 inner tag + 4 outer tag */
        errx(1, "FAIL: QinQ frame too short (%d)", qq_len);
    conf.vlan_id = 0; conf.qinq_outer_vid = 0;
    printf("[PASS] QinQ Double-Tag\n");

    /* Test 10: IGMP Membership Report */
    memset(buf, 0, sizeof(buf));
    int igmp_len = build_packet_igmp(buf);
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

    /* Test 11: payload pattern (0xDEADBEEF fill in jumbo MAC frame) */
    memset(buf, 0, sizeof(buf));
    conf.packet_size   = 128;
    conf.payload_pattern = 2; /* dead */
    int pl_len = build_packet_mac(buf);
    /* payload starts at offset 34 (14 eth + 20 ip), check first 4 bytes */
    if (buf[34] != 0xDE || buf[35] != 0xAD || buf[36] != 0xBE || buf[37] != 0xEF)
        errx(1, "FAIL: payload pattern 0xDEADBEEF not present at offset 34");
    if (pl_len != 128)
        errx(1, "FAIL: payload pattern frame length %d (expected 128)", pl_len);
    conf.packet_size = 0; conf.payload_pattern = 0;
    printf("[PASS] Payload Pattern\n");

    printf("All Tests Passed.\n");
    return 0;
}
