/*
 * flood.h — shared types, globals, and function prototypes
 */
#ifndef FLOOD_H
#define FLOOD_H

#define _GNU_SOURCE
#include <pcap.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdint.h>
#include <time.h>

/* ---- compile-time limits ---- */
#define MAX_PACKET_SIZE  9216
#define ETHER_ADDR_LEN   6
#define MAX_THREADS      16
#define MAX_TARGETS      64
#define MAX_LEARNED_MACS 4096

/* ---- ethertypes ---- */
#define ETHERTYPE_IP    0x0800
#define ETHERTYPE_ARP   0x0806
#define ETHERTYPE_VLAN  0x8100
#define ETHERTYPE_PAUSE 0x8808  /* MAC Control (PFC PAUSE) */
#define ETHERTYPE_LLDP  0x88CC  /* Link Layer Discovery Protocol */
#define ETHERTYPE_8021AD 0x88A8 /* 802.1ad QinQ outer TPID */

/* ---- portable header structs ---- */
struct ether_header_custom {
    uint8_t  dest[ETHER_ADDR_LEN];
    uint8_t  source[ETHER_ADDR_LEN];
    uint16_t type;
};

struct arp_header {
    uint16_t htype;
    uint16_t ptype;
    uint8_t  hlen;
    uint8_t  plen;
    uint16_t oper;
    uint8_t  sha[6];
    uint32_t spa;
    uint8_t  tha[6];
    uint32_t tpa;
};

struct udp_header {
    uint16_t src_port;
    uint16_t dst_port;
    uint16_t len;
    uint16_t check;
};

struct dhcp_packet {
    uint8_t  op;
    uint8_t  htype;
    uint8_t  hlen;
    uint8_t  hops;
    uint32_t xid;
    uint16_t secs;
    uint16_t flags;
    uint32_t ciaddr;
    uint32_t yiaddr;
    uint32_t siaddr;
    uint32_t giaddr;
    uint8_t  chaddr[16];
    uint8_t  sname[64];
    uint8_t  file[128];
    uint32_t magic_cookie;
    uint8_t  options[308];
};

struct target {
    uint32_t ip;
    uint32_t mask;
};

/* ---- IPv6 / ICMPv6 structs (for ND flood mode) ---- */

struct ipv6_header {
    uint32_t vcf;           /* version(4b) | traffic-class(8b) | flow-label(20b) */
    uint16_t payload_len;
    uint8_t  next_header;   /* 58 = ICMPv6 */
    uint8_t  hop_limit;
    uint8_t  src[16];
    uint8_t  dst[16];
};                          /* 40 bytes */

/* ICMPv6 Neighbor Solicitation + Source Link-Layer Address option */
struct icmpv6_ns_pkt {
    uint8_t  type;          /* 135 */
    uint8_t  code;          /* 0 */
    uint16_t checksum;      /* 0 — not computed; switches forward regardless */
    uint32_t reserved;
    uint8_t  target[16];    /* random target IPv6 */
    uint8_t  opt_type;      /* 1 = Source Link-Layer Address */
    uint8_t  opt_len;       /* 1 (units of 8 bytes) */
    uint8_t  opt_mac[6];    /* source MAC */
};                          /* 32 bytes */

struct igmp_header {
    uint8_t  type;
    uint8_t  max_resp;
    uint16_t checksum;
    uint32_t group;
};

struct config {
    char    *interface;
    int      count;
    int      pps;
    int      threads;
    int      mode;               /* 0=MAC, 1=ARP, 2=DHCP, 3=PFC, 4=ND, 5=LLDP, 6=STP, 7=IGMP */
    int      stealth;
    uint8_t  stealth_oui[3];
    int      learning;
    int      adaptive;
    char    *log_file;
    struct target targets[MAX_TARGETS];
    int      target_count;
    int      packet_size;
    int      random_client_mac;
    int      allow_multicast;
    int      self_test;
    char    *pcap_out_file;
    char    *pcap_replay_file;   /* --pcap-replay: inject frames from file */
    int      verbose;
    int      tui;                /* --tui: enable ncurses interface */
    int      nccl;               /* --nccl: show NCCL correlation panel */
    int      session_duration;   /* --duration: auto-stop after N seconds (0=unlimited) */
    int      vlan_id;            /* -V: 802.1Q VLAN ID (0=untagged, 1-4094) */
    int      vlan_pcp;           /* --vlan-pcp: 802.1p PCP bits (0-7) */
    int      pfc_priority;       /* --pfc-priority: priority class to pause (0-7, default 3) */
    int      pfc_quanta;         /* --pfc-quanta: pause duration (0-65535, default 0xFFFF) */
    /* rate sweep */
    int      sweep_enabled;      /* --sweep: automatic rate ramp */
    int      sweep_start;        /* starting PPS */
    int      sweep_end;          /* ending PPS */
    int      sweep_step;         /* PPS increment per step */
    int      sweep_hold;         /* seconds to hold each step (default 10) */
    char    *report_path;        /* --report: output path (NULL = auto) */
    /* burst mode */
    int      burst_count;        /* --burst: frames per burst (0 = off) */
    int      burst_gap_ms;       /* silence between bursts in ms */
    /* VLAN range */
    int      vlan_range_end;     /* --vlan-range: if >0, cycle vlan_id..vlan_range_end */
    /* fail-open detection */
    int      detect_failopen;    /* --detect: start sniffer, watch for echoed probe frames */
    int      qinq_outer_vid;    /* --qinq: 802.1ad outer VLAN ID (0=disabled, 1-4094) */
    int      payload_pattern;  /* --payload: 0=zeros(default), 1=ff, 2=dead, 3=incr */
};

/* ---- shared state (defined in basidium.c) ---- */
extern struct config     conf;
extern atomic_ullong     total_sent;
extern atomic_int        is_running;
extern atomic_int        is_paused;
extern atomic_int        is_started;     /* TUI: set to 1 when user presses start */
extern atomic_ullong     peak_pps;       /* highest PPS observed this session */
extern uint16_t          probe_signature; /* embedded in MAC-flood IP ID for fail-open detection */
extern atomic_int        fail_open_detected;
/* sweep state — updated by sweep_thread_func, read by TUI */
extern atomic_int        sweep_step_num;
extern atomic_int        sweep_total_steps;
extern atomic_int        sweep_hold_rem; /* seconds left in current hold */
extern atomic_ullong     thread_sent[MAX_THREADS]; /* per-thread counters */
extern atomic_ullong     bcast_rx;                 /* sniffer: bcast frames seen */
extern uint8_t         (*learned_macs)[6];
extern int               learned_count;
extern pcap_dumper_t    *global_pd;
extern pthread_mutex_t   log_mutex;
extern pthread_mutex_t   learn_mutex;
extern time_t            start_time;

#define MAX_SWEEP_STEPS 128
extern unsigned long long sweep_step_pps[MAX_SWEEP_STEPS]; /* achieved PPS per step */

/* ---- flood.c prototypes ---- */
void     log_event(const char *type, const char *msg);
void     randomize_mac(uint8_t *mac);
int      is_learned_mac(uint8_t *mac);
uint32_t get_target_ip(void);
void     vlan_tag_frame(uint8_t *buffer, int *len);  /* insert 802.1Q tag in-place */
void     qinq_tag_frame(uint8_t *buffer, int *len);  /* insert 802.1ad outer tag in-place */
void    *sniffer_thread_func(void *arg);
int      build_packet_mac(uint8_t *buffer);
int      build_packet_arp(uint8_t *buffer);
int      build_packet_dhcp(uint8_t *buffer);
int      build_packet_pfc(uint8_t *buffer);          /* 802.1Qbb PFC PAUSE */
int      build_packet_nd(uint8_t *buffer);           /* IPv6 Neighbor Discovery flood */
int      build_packet_lldp(uint8_t *buffer);         /* LLDP frame */
int      build_packet_stp(uint8_t *buffer);          /* STP TCN BPDU */
int      build_packet_igmp(uint8_t *buffer);         /* IGMPv2 Membership Report flood */
void    *worker_func(void *arg);
void    *pcap_replay_func(void *arg);
void    *sweep_thread_func(void *arg);
int      run_selftest(void);

#endif /* FLOOD_H */
