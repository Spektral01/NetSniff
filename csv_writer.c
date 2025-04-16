#include "csv_writer.h"
#include <sys/stat.h>
#include <sys/types.h>
#include <arpa/inet.h>

static void ensure_stats_directory_exists(void) {
    struct stat st = {0};
    if (stat("stats", &st) == -1) {
        if (mkdir("stats", 0777) == -1) {
            perror("Error creating stats directory");
            exit(1);
        }
    }
}

void write_stats_to_csv(struct packet_stats *stats) {
    ensure_stats_directory_exists();
    FILE *file = fopen("stats/packet_stats.csv", "a");
    if (file == NULL) {
        perror("Error opening stats/packet_stats.csv");
        return;
    }
    fprintf(file, "%u,%u,%u,%u,%u,%u,%u,%u,%u,%u,%u,%u,%u,%u,%u,%u,%u,%u,%u,%u\n",
            stats->ethernet, stats->wifi, stats->ppp, stats->arp, stats->lldp,
            stats->ip, stats->icmp, stats->igmp, stats->ospf, stats->bgp,
            stats->tcp, stats->udp, stats->sctp, stats->http, stats->dns,
            stats->dhcp, stats->smtp, stats->pop3_imap, stats->ftp_sftp, stats->snmp);
    fclose(file);
}

void write_port_stats_to_csv(struct port_stats *ports) {
    ensure_stats_directory_exists();
    FILE *file = fopen("stats/port_stats.csv", "a");
    if (file == NULL) {
        perror("Error opening stats/port_stats.csv");
        return;
    }
    for (int i = 0; i < 65536; i++) {
        if (ports->src_ports[i] > 0 || ports->dst_ports[i] > 0) {
            fprintf(file, "%d,%u,%u\n", i, ports->src_ports[i], ports->dst_ports[i]);
        }
    }
    fclose(file);
}

void write_ip_stats_to_csv(struct ip_stats *ips) {
    ensure_stats_directory_exists();
    FILE *file = fopen("stats/ip_stats.csv", "a");
    if (file == NULL) {
        perror("Error opening stats/ip_stats.csv");
        return;
    }
    char ip_str[INET_ADDRSTRLEN];
    struct ip_entry *cur = ips->head;
    while (cur) {
        uint32_t net_ip = htonl(cur->ip);
        inet_ntop(AF_INET, &net_ip, ip_str, INET_ADDRSTRLEN);
        fprintf(file, "%s,%u,%u\n", ip_str, cur->src_count, cur->dst_count);
        cur = cur->next;
    }
    fclose(file);
}

void write_throughput_stats_to_csv(void) {
    static unsigned long last_packet_count = 0, last_byte_count = 0;
    unsigned long current_packets = global_packet_count;
    unsigned long current_bytes = global_byte_count;
    unsigned long pps = current_packets - last_packet_count;
    unsigned long bytes_delta = current_bytes - last_byte_count;
    double throughput_kbps = (bytes_delta * 8) / 1000.0;
    last_packet_count = current_packets;
    last_byte_count = current_bytes;
    ensure_stats_directory_exists();
    FILE *file = fopen("stats/throughput_stats.csv", "a");
    if (file == NULL) {
        perror("Error opening stats/throughput_stats.csv");
        return;
    }
    fprintf(file, "%lu,%.2f\n", pps, throughput_kbps);
    fclose(file);
}

void *csv_thread_func(void *arg) {
    struct pcap_thread_data *data = (struct pcap_thread_data *)arg;
    while (!stop) {
        sleep(1);
        pthread_mutex_lock(&stats_mutex);
        write_stats_to_csv(data->stats);
        write_port_stats_to_csv(data->ports);
        write_ip_stats_to_csv(data->ips);
        write_throughput_stats_to_csv();
        pthread_mutex_unlock(&stats_mutex);
    }
    return NULL;
}
