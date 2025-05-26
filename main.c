#include "af_packet_sniffer.h"
#include "csv_writer.h"
#include <sys/stat.h>
#include <sys/types.h>
#include <signal.h>

volatile int stop = 0;
volatile unsigned long global_packet_count = 0;
volatile unsigned long global_byte_count  = 0;
pthread_mutex_t stats_mutex = PTHREAD_MUTEX_INITIALIZER;

pcap_t *handle = NULL; 

void sigint_handler(int signo) {
    if (signo == SIGINT) {
        stop = 1;
        if (handle) {
            pcap_breakloop(handle);
        }
    }
}

void update_ip_stat(struct ip_stats *ips, uint32_t ip, int is_src) {
    struct ip_entry *cur = ips->head;
    while (cur) {
        if (cur->ip == ip) {
            if (is_src) cur->src_count++;
            else         cur->dst_count++;
            return;
        }
        cur = cur->next;
    }
    struct ip_entry *new_entry = malloc(sizeof(*new_entry));
    if (!new_entry) {
        perror("malloc");
        exit(1);
    }
    new_entry->ip        = ip;
    new_entry->src_count = is_src ? 1 : 0;
    new_entry->dst_count = is_src ? 0 : 1;
    new_entry->next      = ips->head;
    ips->head            = new_entry;
}

void process_packet(const u_char *packet,
                    struct packet_stats *stats,
                    struct port_stats   *ports,
                    struct ip_stats     *ips) {
    pthread_mutex_lock(&stats_mutex);
    struct ethhdr *eth = (struct ethhdr *)packet;
    stats->ethernet++;
    uint16_t proto = ntohs(eth->h_proto);

    if (proto == ETH_P_IP) {
        struct ip *ip_header = (struct ip *)(packet + sizeof(*eth));
        stats->ip++;
        uint32_t src = ntohl(ip_header->ip_src.s_addr);
        uint32_t dst = ntohl(ip_header->ip_dst.s_addr);
        update_ip_stat(ips, src, 1);
        update_ip_stat(ips, dst, 0);

        if (ip_header->ip_p == IPPROTO_TCP) {
            stats->tcp++;
            struct tcphdr *tcp = (struct tcphdr *)(packet + sizeof(*eth) + sizeof(*ip_header));
            uint16_t dport = ntohs(tcp->dest);
            ports->src_ports[ntohs(tcp->source)]++;
            ports->dst_ports[dport]++;
            if (dport == 80 || dport == 443) stats->http++;
        }
        else if (ip_header->ip_p == IPPROTO_UDP) {
            stats->udp++;
            struct udphdr *udp = (struct udphdr *)(packet + sizeof(*eth) + sizeof(*ip_header));
            ports->src_ports[ntohs(udp->source)]++;
            ports->dst_ports[ntohs(udp->dest)]++;
        }
        else if (ip_header->ip_p == IPPROTO_ICMP) stats->icmp++;
        else if (ip_header->ip_p == IPPROTO_IGMP) stats->igmp++;
        else if (ip_header->ip_p == IPPROTO_SCTP) stats->sctp++;
    }
    else if (proto == ETH_P_ARP)  stats->arp++;
    else if (proto == ETH_P_LLDP) stats->lldp++;

    pthread_mutex_unlock(&stats_mutex);
}

void packet_handler(u_char *user_data,
                    const struct pcap_pkthdr *pkthdr,
                    const u_char *packet) {
    struct pcap_thread_data *data = (struct pcap_thread_data *)user_data;
    process_packet(packet, data->stats, data->ports, data->ips);
}

void packet_handler_with_stats(u_char *user_data,
                               const struct pcap_pkthdr *pkthdr,
                               const u_char *packet) {
    packet_handler(user_data, pkthdr, packet);
    __sync_fetch_and_add(&global_packet_count, 1);
    __sync_fetch_and_add(&global_byte_count, pkthdr->len);
}

int main(int argc, char *argv[]) {
    if (argc != 2) {
        fprintf(stderr, "Usage: %s <interface>\n", argv[0]);
        return 1;
    }

    struct stat st = {0};
    if (stat("stats", &st) == -1 && mkdir("stats", 0777) == -1) {
        perror("Error creating stats directory");
        return 1;
    }

    char errbuf[PCAP_ERRBUF_SIZE];
    handle = pcap_open_live(argv[1], MAX_PACKET_SIZE, 1, 1000, errbuf);
    if (!handle) {
        fprintf(stderr, "Error opening %s: %s\n", argv[1], errbuf);
        return 1;
    }

    struct packet_stats stats = {0};
    struct port_stats    ports = {0};
    struct ip_stats      ips; ips.head = NULL;

    FILE *f;
    f = fopen("stats/packet_stats.csv",    "w"); fprintf(f, "Ethernet,Wi-Fi,PPP,ARP,LLDP,IP,ICMP,IGMP,OSPF,BGP,TCP,UDP,SCTP,HTTP,DNS,DHCP,SMTP,POP3/IMAP,FTP/SFTP,SNMP\n"); fclose(f);
    f = fopen("stats/port_stats.csv",      "w"); fprintf(f, "Port,Src Count,Dst Count\n");                                            fclose(f);
    f = fopen("stats/ip_stats.csv",        "w"); fprintf(f, "IP,Src Count,Dst Count\n");                                                fclose(f);
    f = fopen("stats/throughput_stats.csv","w"); fprintf(f, "PPS,Throughput_Kb/s\n");                                               fclose(f);

    if (signal(SIGINT, sigint_handler) == SIG_ERR) {
        perror("signal");
        return 1;
    }

    printf("Sniffer on %s — stats every 1s, Ctrl+C to stop\n", argv[1]);

    struct pcap_thread_data data = {
        .handle = handle,
        .stats  = &stats,
        .ports  = &ports,
        .ips    = &ips
    };

    while (!stop) {
        pcap_dispatch(handle, -1, packet_handler_with_stats, (u_char *)&data);

        pthread_mutex_lock(&stats_mutex);
        write_stats_to_csv(&stats);
        write_port_stats_to_csv(&ports);
        write_ip_stats_to_csv(&ips);
        write_throughput_stats_to_csv();
        pthread_mutex_unlock(&stats_mutex);
    }

    pcap_close(handle);
    printf("Stopped, final stats in stats/*.csv\n");
    return 0;
}
