#ifndef CSV_WRITER_H
#define CSV_WRITER_H

#include "af_packet_sniffer.h"

void write_stats_to_csv(struct packet_stats *stats);
void write_port_stats_to_csv(struct port_stats *ports);
void write_ip_stats_to_csv(struct ip_stats *ips);
void write_throughput_stats_to_csv(void);
void *csv_thread_func(void *arg);

#endif
