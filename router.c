#include "util.h"

int main(int argc, char *argv[])
{
	packet m;
	int rc;

	// Do not modify this line
	init(argc - 2, argv + 2);

	arp_cache_len = 0;

	// allocate memory for routing table
	route_table = calloc(ROUTE_TABLE_MAX_LEN, sizeof(struct route_table_entry));
	DIE(route_table == NULL, "memory");

	// allocate memory for ARP cache
	arp_cache = calloc(ARP_CACHE_SIZE, sizeof(struct arp_entry));
	DIE(arp_cache == NULL, "memory");

	// store routing table length (GLOBAL VARIABLE!)
	route_table_len = read_rtable(argv[1], route_table);
	DIE(!route_table_len, "read route table");

	// sort routing table by prefix and subnet mask ascendently
	qsort(route_table, route_table_len, sizeof(struct route_table_entry), cmp);

	// initialize packet queue
	queue packet_queue = queue_create();

	while (1) {
		rc = get_packet(&m);
		DIE(rc < 0, "get_packet");

		// get Ethernet header
		struct ether_header *eth = (struct ether_header *)m.payload;

		// get current interface MAC
		uint8_t interface_mac[ETH_ALEN];
		get_interface_mac(m.interface, interface_mac);

		// store broadcast MAC Address
		uint8_t broadcast_mac[ETH_ALEN];
		memset(broadcast_mac, 0xFF, ETH_ALEN);

		// get IP Address of current interface (interface on which packet arrived)
		struct in_addr self_ip;
		inet_aton(get_interface_ip(m.interface), &self_ip);

		// check if router is the destiantion, otherwise drop packet
		if (memcmp(interface_mac, eth->ether_dhost, ETH_ALEN) &&
			memcmp(eth->ether_dhost, broadcast_mac, ETH_ALEN)) {
			continue;
		}
				
		// if received ARP packet
		if (ntohs(eth->ether_type) == ETHERTYPE_ARP) {
			// get ARP header
			struct arp_header *arph = (struct arp_header *)
									(m.payload + sizeof(struct ether_header));
			
			// add entry to cache, if not already added
			if (!arp_cache_lookup(arph->spa)) {
				add_to_arp_cache(arph->spa, arph->sha);
			}
			
			// if received ARP request
			if (ntohs(arph->op) == ARPOP_REQUEST) {
				packet arp_reply; // initialize ARP reply packet
				// set length
				arp_reply.len = sizeof(struct ether_header) +
								sizeof(struct arp_header);

				// generate suitable ARP reply header
				struct arp_header arph_reply_header = generate_arp_reply_header(
															interface_mac, arph);

				// store the new ARP header to ARP packet
				memcpy(arp_reply.payload + sizeof(struct ether_header),
						&arph_reply_header, sizeof(struct arp_header));

				// get Ethernet header memory zone for the new ARP packet
				struct ether_header* arp_eth = (struct ether_header* )
												(arp_reply.payload);
				
				// set Ethernet type
				arp_eth->ether_type = ntohs(ETHERTYPE_ARP);

				// set MACs
				rewrite_macs(&arp_reply, m.interface, arph->sha);

				// send packet
				send_packet(&arp_reply);
				continue;
			}

			// process ARP reply
			if (ntohs(arph->op) == ARPOP_REPLY) {

				// initialize temporary packet queue
				queue temp_queue = queue_create();

				/* iterate through all packets awaiting in queue, send packets
					when ARP neighbor MAC is ready */
				while (!queue_empty(packet_queue)) {
					packet* check_packet = (packet *) (queue_deq(packet_queue));
					struct iphdr *check_packet_iph = (struct iphdr*)
								(check_packet->payload +
								sizeof(struct ether_header));

					struct route_table_entry *check_packet_route = get_route
													(check_packet_iph->daddr);

					// send packet if destination address is ready
					if (check_packet_route->next_hop == arph->spa){
						rewrite_macs(check_packet, check_packet_route->interface,
																	arph->sha);
						/* recalculate packet checksum, as it was duplicated
							when enqueued */
						check_packet_iph->check = 0;
						check_packet_iph->check = ip_checksum(
							(uint8_t *)check_packet_iph, sizeof(struct iphdr));
						send_packet(check_packet);
						free(check_packet);
					}
					/* if destination address is still unknown, add packet to
						temporary, to store it back in queue */
					else queue_enq(temp_queue, check_packet);
				}
				free(packet_queue); // free memory
				packet_queue = temp_queue; // assign temp queue to the initial
				continue;
			}
		}
		
		// check if packet is IPv4
		if (ntohs(eth->ether_type) != ETHERTYPE_IP) continue;

		struct iphdr *iph = (struct iphdr*)
							(m.payload + sizeof(struct ether_header));

		if (iph->protocol == IPPROTO_ICMP && self_ip.s_addr == iph->daddr) {
			struct icmphdr *icmph = (struct icmphdr*)
									(m.payload + sizeof(struct ether_header) +
									sizeof(struct iphdr));

			// reply to ICMP echo request
			if (icmph->type == 8) {
				write_icmp_header(0, &m);
				send_packet(&m);
			}
			continue;
		}
		// check checksum
		uint16_t old_checksum = iph->check;
		iph->check = 0;
		if (ip_checksum((uint8_t *) iph, sizeof(struct iphdr)) != old_checksum)
			continue;

		// check ttl
		if (iph->ttl <= 1) {
			write_icmp_header(11, &m); // send TTL exceded ICMP packet
			send_packet(&m);
			continue;
		} 

		// get route
		struct route_table_entry *route = get_route(iph->daddr);
		if (!route) {
			write_icmp_header(3, &m); // send Destination unreachable
			send_packet(&m);
			continue;
		}

		// get arp neighbor
		struct arp_entry *arp_neighbor = arp_cache_lookup(route->next_hop);
		if (!arp_neighbor) {
			// generate ARP request
			// duplicate original packet to enqueue
			packet* dup = malloc(sizeof(packet));
			memset(dup, 0, sizeof(packet));
			memcpy(dup, &m, sizeof(packet));
			dup->interface = route->interface;

			queue_enq(packet_queue, dup); // enqueue the duplicate
			packet arp_request;
			arp_request.len = sizeof (struct ether_header) +
								sizeof (struct arp_header);

			uint8_t next_hop_mac[ETH_ALEN];
			get_interface_mac(route->interface, next_hop_mac);

			// get the IP Address of best route's interface, write it to &self_ip
			inet_aton(get_interface_ip(route->interface), &self_ip);

			// generate ARP request header
			struct arp_header arph = generate_arp_request_header(next_hop_mac,
															self_ip.s_addr,
															route->next_hop);

			// copy data from standalone header to prepared packet
			memcpy(arp_request.payload + sizeof(struct ether_header), &arph,
					sizeof(struct arp_header));

			// get Ethernet header to rewrite MACs
			struct ether_header* arp_eth = (struct ether_header*)
											(arp_request.payload);

			arp_eth->ether_type = htons(ETHERTYPE_ARP);

			// rewrite MACs and send packet
			rewrite_macs(&arp_request, route->interface, broadcast_mac);
			send_packet(&arp_request);
			continue;
		}
		// update ttl and checksum
		iph->check = ip_incremental_checksum(old_checksum, iph->ttl);
		iph->ttl--;

		// rewrite packet MAC addresses
		rewrite_macs(&m, route->interface, arp_neighbor->mac);
		send_packet(&m);
	}
}
