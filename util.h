#ifndef _UTIL_H_
#define _UTIL_H_
#include "queue.h"
#include "skel.h"

#define ROUTE_TABLE_MAX_LEN 100000
#define ARP_CACHE_SIZE 6

struct route_table_entry *route_table;
struct arp_entry *arp_cache;
int route_table_len, arp_cache_len;

int cmp(const void* a, const void* b);
struct route_table_entry* get_route(uint32_t dest_ip);
struct arp_entry* arp_cache_lookup(uint32_t dest_ip);

struct arp_header generate_arp_request_header(uint8_t source_mac[ETH_ALEN],
												uint32_t source_ip,
												uint32_t dest_ip);
struct arp_header generate_arp_reply_header(uint8_t source_mac[ETH_ALEN],
											struct arp_header* recv_arph);

void add_to_arp_cache(uint32_t ip, uint8_t mac[ETH_ALEN]);


void rewrite_macs(packet* m, int interface, uint8_t neighbor_mac[ETH_ALEN]);

void write_icmp_header(uint8_t type, packet* m);

uint16_t ip_incremental_checksum(uint16_t old_checksum, uint8_t ttl);

#endif