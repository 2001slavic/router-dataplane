#include "util.h"

/**
 * @brief Comparisson function for qsort (ascending by prefix and subnet mask).
 * 
 * @param a First route table entry.
 * @param b Second route table entry.
 * @return int Difference.
 */
int cmp(const void* a, const void* b) {
	struct route_table_entry* entry1 = (struct route_table_entry *)a;
	struct route_table_entry* entry2 = (struct route_table_entry *)b;

	if (entry1->prefix == entry2->prefix) return entry1->mask - entry2->mask;
	return entry1->prefix - entry2->prefix;
}

/**
 * @brief Get the best route to destination. Uses binary search.
 * 
 * @param dest_ip IP Address of destiantion.
 * @return struct route_table_entry* The best route.
 */
struct route_table_entry* get_route(uint32_t dest_ip) {
	uint32_t res_index = 0;;
	uint8_t found_solution = 0;

	uint32_t low = 0;
	uint32_t high = route_table_len - 1;

	while (low <= high) {
		uint32_t mid = low + (high - low + 1) / 2;
		if (mid == 0) break;
		uint32_t ip1 = route_table[mid].prefix;
		uint32_t ip2 = dest_ip & route_table[mid].mask;

		/* if mid is less than sought IP, then all elements from left are also
			less, so continue searching in the right (bigger) half */
		if (ip1 < ip2) low = mid + 1;
		/* if mid is bigger, continue searching in the left half */
		else if (ip1 > ip2) high = mid - 1;
		/* if match, note the index, and search for more apparitions in the
			right side of mid */
		else if (ip1 == ip2) {
			found_solution = 1;
			res_index = mid;
			low = mid + 1;
		}
	}
	/* if no solutions found -- return NULL */
	if (!found_solution) return NULL;
	return &route_table[res_index];
}

/**
 * @brief Computes checksum as per RFC 1624.
 * 
 * @param old_checksum The old checksum.
 * @param ttl Decremented TTL.
 * @return uint16_t New re-calculated checksum.
 */
uint16_t ip_incremental_checksum(uint16_t old_checksum, uint8_t ttl) {
	return old_checksum - ~(uint16_t)(ttl) - (uint16_t)(ttl);
}

/**
 * @brief Check if neighbor's MAC is in ARP cache.
 * 
 * @param dest_ip Neighbor's IP Address.
 * @return struct arp_entry* ARP entry if found in cache, otherwise - NULL.
 */
struct arp_entry* arp_cache_lookup(uint32_t dest_ip) {
	for (size_t i = 0; i < arp_cache_len; i++) {
        if (dest_ip == arp_cache[i].ip)
	    	return &arp_cache[i];
	}
    return NULL;
}

/**
 * @brief Adds an entry to ARP cache.
 * 
 * @param ip Entry IP Address.
 * @param mac Entry MAC Address.
 */
void add_to_arp_cache(uint32_t ip, uint8_t mac[ETH_ALEN]) {
	struct arp_entry entry;
	entry.ip = ip;
	memcpy(entry.mac, mac, ETH_ALEN);

	memcpy(&(arp_cache[arp_cache_len]), &entry, sizeof(struct arp_entry));
	arp_cache_len++; // (GLOBAL VARIABLE!)
}

/**
 * @brief Generates ARP request header.
 * 
 * @param source_mac Sender's MAC Address.
 * @param source_ip Sender's IP Address.
 * @param dest_ip Destination IP Address.
 * @return struct arp_header Formet ARP header with op == 1.
 */
struct arp_header generate_arp_request_header(uint8_t source_mac[ETH_ALEN],
												uint32_t source_ip,
												uint32_t dest_ip) {
	struct arp_header arph;
	arph.htype = htons(1);
	arph.ptype = htons(ETHERTYPE_IP);
	arph.hlen = ETH_ALEN;
	arph.plen = sizeof(in_addr_t);
	arph.op = htons(ARPOP_REQUEST);
	memcpy(arph.sha, source_mac, ETH_ALEN);
	arph.spa = source_ip;
	memset(arph.tha, 0, ETH_ALEN);
	arph.tpa = dest_ip;
	return arph;
}

/**
 * @brief Generates ARP reply header.
 * 
 * @param source_mac Sender's MAC address.
 * @param recv_arph Received ARP request header (the old one).
 * @return struct arp_header New ARP header for reply.
 */
struct arp_header generate_arp_reply_header(uint8_t source_mac[ETH_ALEN],
											struct arp_header* recv_arph) {
	struct arp_header arph;
	arph.htype = htons(1);
	arph.ptype = htons(ETHERTYPE_IP);
	arph.hlen = ETH_ALEN;
	arph.plen = sizeof(in_addr_t);
	arph.op = htons(ARPOP_REPLY);
	memcpy(arph.sha, source_mac, ETH_ALEN);
	arph.spa = recv_arph->tpa;
	memcpy(arph.tha, recv_arph->sha, ETH_ALEN);
	arph.tpa = recv_arph->spa;
	return arph;
}

/**
 * @brief Generates situation-aware ICMP header.
 * 
 * @param type Type of ICMP reply.
 * @param m Received packet (the old one).
 */
void write_icmp_header(uint8_t type, packet* m) {
	struct ether_header *eth = (struct ether_header *)m->payload;

	// allocate memory for the old payload
	void* old_payload = malloc(64);
	memset(old_payload, 0, 64);

	struct iphdr *iph = (struct iphdr*)
						(m->payload + sizeof(struct ether_header));
	
	struct icmphdr *icmph = (struct icmphdr*)
								(m->payload + sizeof(struct ether_header) +
								sizeof(struct iphdr));

	struct in_addr self_ip;
	inet_aton(get_interface_ip(m->interface), &self_ip);

	// write old payload for ICMP error replies
	memcpy(old_payload,
		(struct iphdr*)(m->payload + sizeof(struct ether_header)),
		64);

	// build new IP header
	iph->version = 4;
	iph->ihl = 5;
	iph->tos = 0;
	iph->id = 0;
	iph->frag_off = 0;
	iph->ttl = 64;
	iph->protocol = IPPROTO_ICMP;
	uint32_t temp_addr = iph->saddr;
	iph->saddr = self_ip.s_addr;
	iph->daddr = temp_addr;
	iph->check = 0;
	iph->check = ip_checksum((void *) iph, sizeof(struct iphdr));

	icmph->type = type;
	icmph->code = 0;

	icmph->checksum = 0;
	// preparing ICMP echo reply
	if (type == 0) {
		size_t icmph_data_size = ntohs(iph->tot_len) - sizeof(struct iphdr);
		icmph->checksum = icmp_checksum((uint16_t*)icmph, icmph_data_size);

		// taking ICMP echo request data into account (mostly for proper timestamp)
		iph->tot_len = htons(sizeof(struct iphdr) + icmph_data_size);
		m->len = sizeof(struct ether_header) + sizeof(struct iphdr) +
						icmph_data_size;
	}
	else {
		size_t address_offset = sizeof(struct ether_header) +
								sizeof(struct iphdr) +
								sizeof(struct icmphdr);
		
		// store first 64 bytes of old payload to new ICMP reply
		memcpy(m->payload + address_offset, old_payload, 64);
		iph->tot_len = htons(sizeof(struct iphdr) + sizeof(struct icmphdr) + 64);
		m->len = address_offset + 64;
		icmph->checksum = icmp_checksum((uint16_t*)icmph,
										sizeof(struct icmphdr) + 64);
	}
	
	// rewrite MACs in Ethernet header
	uint8_t dest_mac[ETH_ALEN];
	memcpy(dest_mac, eth->ether_shost, ETH_ALEN);
	rewrite_macs(m, m->interface, dest_mac);

	free(old_payload);
}

/**
 * @brief Rewrites MAC addresses, and prepares packet for future forward.
 * 
 * @param m Packet whose Ethernet header to be rewritten.
 * @param interface Interface of packet to write into packet.
 * @param neighbor_mac Target MAC (roughly).
 */
void rewrite_macs(packet* m, int interface, uint8_t neighbor_mac[ETH_ALEN]) {	
	m->interface = interface;
	struct ether_header* eth = (struct ether_header *) (m->payload);

	memcpy(eth->ether_dhost, neighbor_mac, ETH_ALEN);
	get_interface_mac(interface, eth->ether_shost);
}
