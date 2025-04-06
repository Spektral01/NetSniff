#ifndef AF_PACKET_SNIFFER_H
#define AF_PACKET_SNIFFER_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pcap.h>
#include <netinet/ip.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/icmp6.h>
#include <netinet/sctp.h>
#include <netinet/ether.h>
#include <netinet/if_ether.h>
#include <arpa/inet.h>
#include <netinet/ip_icmp.h>
#include <pthread.h>
#include <unistd.h>
#include <stdint.h>

#define MAX_PACKET_SIZE 65536

struct packet_stats {
    unsigned int ethernet;
    unsigned int wifi;
    unsigned int ppp;
    unsigned int arp;
    unsigned int lldp;
    unsigned int ip;
    unsigned int icmp;
    unsigned int igmp;
    unsigned int ospf;
    unsigned int bgp;
    unsigned int tcp;
    unsigned int udp;
    unsigned int sctp;
    unsigned int http;
    unsigned int dns;
    unsigned int dhcp;
    unsigned int smtp;
    unsigned int pop3_imap;
    unsigned int ftp_sftp;
    unsigned int snmp;
};

struct port_stats {
    unsigned int src_ports[65536];
    unsigned int dst_ports[65536];
};

struct ip_entry {
    uint32_t ip;
    unsigned int src_count;
    unsigned int dst_count;
    struct ip_entry *next;
};

struct ip_stats {
    struct ip_entry *head;
};

struct pcap_thread_data {
    pcap_t *handle;
    struct packet_stats *stats;
    struct port_stats *ports;
    struct ip_stats *ips;
};

extern volatile int stop;
extern pthread_mutex_t stats_mutex;
extern volatile unsigned long global_packet_count;
extern volatile unsigned long global_byte_count;

void update_ip_stat(struct ip_stats *ips, uint32_t ip, int is_src);
void process_packet(const u_char *packet, struct packet_stats *stats, struct port_stats *ports, struct ip_stats *ips);
void packet_handler(u_char *user_data, const struct pcap_pkthdr *pkthdr, const u_char *packet);
void *pcap_thread_func(void *arg);
void packet_handler_with_stats(u_char *user_data, const struct pcap_pkthdr *pkthdr, const u_char *packet);

#endif
