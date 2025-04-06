#include "af_packet_sniffer.h"
#include "csv_writer.h"
#include <sys/stat.h>
#include <sys/types.h>

volatile int stop = 0;
pthread_mutex_t stats_mutex = PTHREAD_MUTEX_INITIALIZER;
volatile unsigned long global_packet_count = 0;
volatile unsigned long global_byte_count = 0;

void update_ip_stat(struct ip_stats *ips, uint32_t ip, int is_src) {
    struct ip_entry *cur = ips->head;
    while (cur) {
        if (cur->ip == ip) {
            if (is_src)
                cur->src_count++;
            else
                cur->dst_count++;
            return;
        }
        cur = cur->next;
    }
    struct ip_entry *new_entry = malloc(sizeof(struct ip_entry));
    if (!new_entry) {
        perror("malloc");
        exit(1);
    }
    new_entry->ip = ip;
    new_entry->src_count = (is_src ? 1 : 0);
    new_entry->dst_count = (is_src ? 0 : 1);
    new_entry->next = ips->head;
    ips->head = new_entry;
}

void process_packet(const u_char *packet, struct packet_stats *stats, struct port_stats *ports, struct ip_stats *ips) {
    pthread_mutex_lock(&stats_mutex);
    struct ethhdr *eth = (struct ethhdr *) packet;
    stats->ethernet++;
    if (ntohs(eth->h_proto) == ETH_P_IP) {
        struct ip *ip_header = (struct ip *)(packet + sizeof(struct ethhdr));
        stats->ip++;
        uint32_t src = ntohl(ip_header->ip_src.s_addr);
        uint32_t dst = ntohl(ip_header->ip_dst.s_addr);
        update_ip_stat(ips, src, 1);
        update_ip_stat(ips, dst, 0);
        if (ip_header->ip_p == IPPROTO_TCP) {
            stats->tcp++;
            struct tcphdr *tcp_header = (struct tcphdr *)(packet + sizeof(struct ethhdr) + sizeof(struct ip));
            ports->src_ports[ntohs(tcp_header->source)]++;
            ports->dst_ports[ntohs(tcp_header->dest)]++;
            if (ntohs(tcp_header->dest) == 80 || ntohs(tcp_header->dest) == 443) {
                stats->http++;
            }
        } else if (ip_header->ip_p == IPPROTO_UDP) {
            stats->udp++;
            struct udphdr *udp_header = (struct udphdr *)(packet + sizeof(struct ethhdr) + sizeof(struct ip));
            ports->src_ports[ntohs(udp_header->source)]++;
            ports->dst_ports[ntohs(udp_header->dest)]++;
        } else if (ip_header->ip_p == IPPROTO_ICMP) {
            stats->icmp++;
        } else if (ip_header->ip_p == IPPROTO_IGMP) {
            stats->igmp++;
        } else if (ip_header->ip_p == IPPROTO_SCTP) {
            stats->sctp++;
        }
    } else if (ntohs(eth->h_proto) == ETH_P_ARP) {
        stats->arp++;
    } else if (ntohs(eth->h_proto) == ETH_P_LLDP) {
        stats->lldp++;
    }
    pthread_mutex_unlock(&stats_mutex);
}

void packet_handler(u_char *user_data, const struct pcap_pkthdr *pkthdr, const u_char *packet) {
    struct pcap_thread_data *data = (struct pcap_thread_data *)user_data;
    process_packet(packet, data->stats, data->ports, data->ips);
}

void packet_handler_with_stats(u_char *user_data, const struct pcap_pkthdr *pkthdr, const u_char *packet) {
    packet_handler(user_data, pkthdr, packet);
    __sync_fetch_and_add(&global_packet_count, 1);
    __sync_fetch_and_add(&global_byte_count, pkthdr->len);
}

void *pcap_thread_func(void *arg) {
    struct pcap_thread_data *data = (struct pcap_thread_data *)arg;
    pcap_loop(data->handle, 0, packet_handler_with_stats, (u_char *)data);
    return NULL;
}

int main(int argc, char *argv[]) {
    if (argc != 2) {
        printf("Usage: %s <interface>\n", argv[0]);
        return 1;
    }
    struct stat st = {0};
    if (stat("stats", &st) == -1) {
        if (mkdir("stats", 0777) == -1) {
            perror("Error creating stats directory");
            exit(1);
        }
    }
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle = pcap_open_live(argv[1], MAX_PACKET_SIZE, 1, 1000, errbuf);
    if (handle == NULL) {
        fprintf(stderr, "Error opening device %s: %s\n", argv[1], errbuf);
        return 1;
    }
    struct packet_stats stats = {0};
    struct port_stats ports = {0};
    struct ip_stats ips;
    ips.head = NULL;
    FILE *file = fopen("stats/packet_stats.csv", "w");
    if (!file) { perror("Error opening packet_stats.csv"); return 1; }
    fprintf(file, "Ethernet,Wi-Fi,PPP,ARP,LLDP,IP,ICMP,IGMP,OSPF,BGP,TCP,UDP,SCTP,HTTP,DNS,DHCP,SMTP,POP3/IMAP,FTP/SFTP,SNMP\n");
    fclose(file);
    file = fopen("stats/port_stats.csv", "w");
    if (!file) { perror("Error opening port_stats.csv"); return 1; }
    fprintf(file, "Port,Src Count,Dst Count\n");
    fclose(file);
    file = fopen("stats/ip_stats.csv", "w");
    if (!file) { perror("Error opening ip_stats.csv"); return 1; }
    fprintf(file, "IP,Src Count,Dst Count\n");
    fclose(file);
    file = fopen("stats/throughput_stats.csv", "w");
    if (!file) { perror("Error opening throughput_stats.csv"); return 1; }
    fprintf(file, "PPS,Throughput_Kb/s\n");
    fclose(file);
    pthread_t pcap_thread, csv_thread;
    struct pcap_thread_data pcap_data;
    pcap_data.handle = handle;
    pcap_data.stats = &stats;
    pcap_data.ports = &ports;
    pcap_data.ips = &ips;
    if (pthread_create(&pcap_thread, NULL, pcap_thread_func, (void *)&pcap_data) != 0) {
        perror("Error creating pcap thread");
        return 1;
    }
    if (pthread_create(&csv_thread, NULL, csv_thread_func, (void *)&pcap_data) != 0) {
        perror("Error creating CSV thread");
        return 1;
    }
    printf("Press Enter to stop...\n");
    getchar();
    stop = 1;
    pcap_breakloop(handle);
    pthread_join(pcap_thread, NULL);
    pthread_join(csv_thread, NULL);
    pcap_close(handle);
    printf("Program terminated.\n");
    return 0;
}
