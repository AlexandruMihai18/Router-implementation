#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <arpa/inet.h>

#include "queue.h"
#include "lib.h"
#include "protocols.h"

/* Routing table */
struct route_table_entry *rtable;
int rtable_len;

/* Arp table */
struct arp_entry *arptable;
int arptable_len;

/* Waiting packets queue */
queue waiting_packets;
int waiting_packets_len;

/* Comparator for comparing 2 routing table entries */
int comparator(struct route_table_entry first, struct route_table_entry second)
{
	if (ntohl(first.prefix) > ntohl(second.prefix)) {
		return 1;
	}

	if (ntohl(first.prefix) < ntohl(second.prefix)) {
		return -1;
	}

	if (ntohl(first.mask) > ntohl(second.mask)) {
		return 1;
	}

	if (ntohl(first.mask) < ntohl(second.mask)) {
		return -1;
	}

	return 0;
}

/* Merging the two halves in the merge sort algorithm */
void merge_halves(int left, int right) {
	int mid = (left + right) / 2;
	struct route_table_entry *aux = malloc((right - left + 1) * sizeof(struct route_table_entry));
	int counter = 0;
	int i = left, j = mid + 1;
 
    while (i <= mid && j <= right) {
		if (comparator(rtable[i], rtable[j]) == -1) {
			memcpy(&aux[counter++], &rtable[i], sizeof(struct route_table_entry));
			i++;
		} else {
			memcpy(&aux[counter++], &rtable[j], sizeof(struct route_table_entry));
			j++;
		}
	}
 
    while (i <= mid) {
		memcpy(&aux[counter++], &rtable[i], sizeof(struct route_table_entry));
		i++;
	}
 
    while (j <= right) {
		memcpy(&aux[counter++], &rtable[j], sizeof(struct route_table_entry));
		j++;
	}
 
	for (int k = left; k <= right; k++) {
		memcpy(&rtable[k], &aux[k - left], sizeof(struct route_table_entry));
	}

	free(aux);
}
 
/* Merge sort logic, complexity O(N log N) */ 
void merge_sort(int left, int right) {
	if (left >= right) {
		return;
	}

	int mid = (left + right) / 2;
 
    merge_sort(left, mid);
	merge_sort(mid + 1, right);
	merge_halves(left, right);
}

/* Get best route through binary search algorithm, complexity O(log N) */
struct route_table_entry *get_best_route(uint32_t ip_dest)
{
	int pos = -1;

	int left = 0;
	int right = rtable_len - 1;
	int mid;

	while (left <= right) {
		mid = (left + right) / 2;

		/* Finding the first fitting entry */
		if (pos == -1 && (rtable[mid].prefix == (ip_dest & rtable[mid].mask))) {
			pos = mid;
		}

		/* Find a better fitting entry */
		if (pos != -1 && (rtable[mid].prefix == (ip_dest & rtable[mid].mask))) {
			if (ntohl(rtable[mid].mask) > ntohl(rtable[pos].mask)) {
				pos = mid;
			}
		}

		/* Searching in the left half */
		if (ntohl(rtable[mid].prefix) > ntohl(ip_dest)) {
			right = mid - 1;
		}

		/* Searching in the right half */
		if (ntohl(rtable[mid].prefix) <= ntohl(ip_dest)) {
			left = mid + 1;
		}
	}

	if (pos == -1) {
		return NULL;
	}

	return &rtable[pos];
}

/*
 * Find an entry in the arp table based on the ip 
 **/
struct arp_entry *get_mac_entry(uint32_t ip)
{
	for (int i = 0; i < arptable_len; i++) {
		if (arptable[i].ip == ip) {
			return &arptable[i];
		}
	}

	return NULL;
}

/*
 * Generate and send an arp reply
 **/
int generate_arp_reply(uint32_t dest_ip, uint8_t *dest_mac)
{
	char send_buf[MAX_PACKET_LEN];
	uint8_t send_mac_addr[MAC_ADDR_LEN];
	char *send_ip_addr_text;
	uint32_t send_ip_addr_binary;

	uint16_t send_len = 0;

	struct route_table_entry *best_route = get_best_route(dest_ip);

	struct ether_header *send_eth_hdr = (struct ether_header *) send_buf;
	struct arp_header *send_arp_hdr = (struct arp_header *)(send_buf + sizeof(struct ether_header));

	/* Complete the arp header for the packet */
	send_arp_hdr->htype = htons((uint16_t) ETHERNET_TYPE);
	send_arp_hdr->ptype = htons((uint16_t) IPV4_TYPE);
	send_arp_hdr->hlen = (uint8_t) MAC_ADDR_LEN;
	send_arp_hdr->plen = (uint8_t) IPV4_LEN;
	send_arp_hdr->op = htons((uint16_t) OPCODE_ARP_REPLY);

	get_interface_mac(best_route->interface, send_mac_addr);

	memcpy(send_arp_hdr->sha, send_mac_addr, MAC_ADDR_LEN);

	send_ip_addr_text = get_interface_ip(best_route->interface);
	inet_pton(AF_INET, send_ip_addr_text, &send_ip_addr_binary);

	send_arp_hdr->spa = send_ip_addr_binary;

	memcpy(send_arp_hdr->tha, dest_mac, MAC_ADDR_LEN);
	memcpy(&send_arp_hdr->tpa, &best_route->next_hop, sizeof(uint32_t));

	send_len += sizeof(struct arp_header);

	/* Complete the ethernet header for the packet */
	memcpy(send_eth_hdr->ether_dhost, dest_mac, MAC_ADDR_LEN);
	memcpy(send_eth_hdr->ether_shost, send_mac_addr, MAC_ADDR_LEN);
	send_eth_hdr->ether_type = htons((uint16_t) ARP_TYPE);

	send_len += sizeof(struct ether_header);

	/* Send the packet through the best route interface */
	send_to_link(best_route->interface, send_buf, send_len);

	return 0;
}

int generate_arp_request(uint32_t dest_ip)
{
	char send_buf[MAX_PACKET_LEN];
	uint8_t send_mac_addr[MAC_ADDR_LEN];
	char *send_ip_addr_text;
	uint32_t send_ip_addr_binary;

	uint16_t send_len = 0;

	struct route_table_entry *best_route = get_best_route(dest_ip);

	struct ether_header *send_eth_hdr = (struct ether_header *) send_buf;
	struct arp_header *send_arp_hdr = (struct arp_header *)(send_buf + sizeof(struct ether_header));

	/* Complete the arp header for the packet */
	send_arp_hdr->htype = htons((uint16_t) ETHERNET_TYPE);
	send_arp_hdr->ptype = htons((uint16_t) IPV4_TYPE);
	send_arp_hdr->hlen = (uint8_t) MAC_ADDR_LEN;
	send_arp_hdr->plen = (uint8_t) IPV4_LEN;
	send_arp_hdr->op = htons((uint16_t) OPCODE_ARP_REQUEST);

	get_interface_mac(best_route->interface, send_mac_addr);

	memcpy(send_arp_hdr->sha, send_mac_addr, MAC_ADDR_LEN);

	send_ip_addr_text = get_interface_ip(best_route->interface);
	inet_pton(AF_INET, send_ip_addr_text, &send_ip_addr_binary);

	send_arp_hdr->spa = send_ip_addr_binary;

	memset(send_arp_hdr->tha, 0, MAC_ADDR_LEN);
	memcpy(&send_arp_hdr->tpa, &best_route->next_hop, sizeof(uint32_t));

	send_len += sizeof(struct arp_header);

	/* Complete the ethernet header for the packet */
	memcpy(send_eth_hdr->ether_shost, send_mac_addr, MAC_ADDR_LEN);
	memset(send_eth_hdr->ether_dhost, BROADCAST_PREF, MAC_ADDR_LEN);
	send_eth_hdr->ether_type = htons((uint16_t) ARP_TYPE);

	send_len += sizeof(struct ether_header);

	/* Send the packet through the best route interface */
	send_to_link(best_route->interface, send_buf, send_len);

	return 0;
}

int icmp_handler_request(int interface, void *buf, int len)
{
	char send_buf[MAX_PACKET_LEN];
	char *ip_addr_text;
	uint32_t ip_addr_binary;

	uint16_t send_len = 0;

	struct ether_header *eth_hdr = (struct ether_header *) buf;
	struct iphdr *ip_hdr = (struct iphdr *)(buf + sizeof(struct ether_header));
	struct icmphdr *icmp_hdr = (struct icmphdr *)(buf + sizeof(struct ether_header) + sizeof(struct iphdr));
	void *payload = (void *)(buf + sizeof(struct ether_header) + sizeof(struct iphdr) + sizeof(struct icmphdr));

	int payload_size = len - (sizeof(struct ether_header) + sizeof(struct iphdr) + sizeof(struct icmphdr));
	
	struct ether_header *send_eth_hdr = (struct ether_header *) send_buf;
	struct iphdr *send_ip_hdr = (struct iphdr *)(send_buf + sizeof(struct ether_header));
	struct icmphdr *send_icmp_hdr = (struct icmphdr *)(send_buf + sizeof(struct ether_header) + sizeof(struct iphdr));  

	/* Complete the icmp header for the packet */
	send_icmp_hdr->type = 0;
	send_icmp_hdr->code = 0;
	send_icmp_hdr->checksum = 0;

	send_icmp_hdr->un.echo.id = icmp_hdr->un.echo.id;
	send_icmp_hdr->un.echo.sequence = icmp_hdr->un.echo.sequence;

	send_len += sizeof(struct icmphdr);

	/* Copy the payload from the initial packet in order to send it to the destination */
	void *send_payload = (void *)(send_buf + sizeof(struct ether_header) + sizeof(struct iphdr) + sizeof(struct icmphdr));

	memcpy(send_payload, payload, payload_size);

	send_len += payload_size;

	send_icmp_hdr->checksum = htons(checksum((void *) send_icmp_hdr, send_len));

	/* Complete the ip header for the packet */
	memcpy(send_ip_hdr, ip_hdr, sizeof(struct iphdr));

	send_len += sizeof(struct iphdr);

	send_ip_hdr->ttl = STANDARD_TTL;
	send_ip_hdr->check = 0;
	send_ip_hdr->tot_len = htons(send_len);

	ip_addr_text = get_interface_ip(interface);
	inet_pton(AF_INET, ip_addr_text, &ip_addr_binary);

	memcpy(&send_ip_hdr->daddr, &ip_hdr->saddr, sizeof(uint32_t));
	send_ip_hdr->saddr = ip_addr_binary;

	send_ip_hdr->check = htons(checksum((void *) send_ip_hdr, sizeof(struct iphdr)));

	/* Complete the ethernet header for the packet */
	memcpy(send_eth_hdr->ether_shost, eth_hdr->ether_dhost, MAC_ADDR_LEN);
	memcpy(send_eth_hdr->ether_dhost, eth_hdr->ether_shost, MAC_ADDR_LEN);
	send_eth_hdr->ether_type = eth_hdr->ether_type;

	send_len += sizeof(struct ether_header);

	/* Send the packet through the interface the packet came from */
	send_to_link(interface, send_buf, send_len);

	return 0;
}

int icmp_handler_error(int interface, void *buf, int len, uint8_t type)
{
	char send_buf[MAX_PACKET_LEN];
	char *ip_addr_text;
	uint32_t ip_addr_binary;

	uint16_t send_len = 0;

	struct ether_header *eth_hdr = (struct ether_header *) buf;
	struct iphdr *ip_hdr = (struct iphdr *)(buf + sizeof(struct ether_header));
	
	struct ether_header *send_eth_hdr = (struct ether_header *) send_buf;
	struct iphdr *send_ip_hdr = (struct iphdr *)(send_buf + sizeof(struct ether_header));
	struct icmphdr *send_icmp_hdr = (struct icmphdr *)(send_buf + sizeof(struct ether_header) + sizeof(struct iphdr));  

	/* Complete the icmp header for the packet */
	send_icmp_hdr->type = type;
	send_icmp_hdr->code = 0;
	send_icmp_hdr->checksum = 0;

	memset(&send_icmp_hdr->un, 0, sizeof(send_icmp_hdr->un));

	send_len += sizeof(struct icmphdr);

	/* Complete the payload with the required information from the old ip header */
	void *send_payload = (void *)(send_buf + sizeof(struct ether_header) + sizeof(struct iphdr) + sizeof(struct icmphdr));

	memcpy(send_payload, ip_hdr, sizeof(struct iphdr) + ICMP_ERROR_PAYLOAD);

	send_len += sizeof(struct iphdr) + ICMP_ERROR_PAYLOAD;

	send_icmp_hdr->checksum = htons(checksum((void *) send_icmp_hdr, send_len));

	/* Complete the ip header for the packet */
	memcpy(send_ip_hdr, ip_hdr, sizeof(struct iphdr));

	send_len += sizeof(struct iphdr);

	send_ip_hdr->ttl = STANDARD_TTL;
	send_ip_hdr->check = 0;
	send_ip_hdr->tot_len = htons(send_len);
	send_ip_hdr->version = 4;
	send_ip_hdr->protocol = 1;

	ip_addr_text = get_interface_ip(interface);
	inet_pton(AF_INET, ip_addr_text, &ip_addr_binary);

	memcpy(&send_ip_hdr->daddr, &ip_hdr->saddr, sizeof(uint32_t));
	send_ip_hdr->saddr = ip_addr_binary;

	send_ip_hdr->check = htons(checksum((void *) send_ip_hdr, sizeof(struct iphdr)));

	/* Complete the ethernet header for the packet */

	memcpy(send_eth_hdr->ether_shost, eth_hdr->ether_dhost, MAC_ADDR_LEN);
	memcpy(send_eth_hdr->ether_dhost, eth_hdr->ether_shost, MAC_ADDR_LEN);
	send_eth_hdr->ether_type = eth_hdr->ether_type;

	send_len += sizeof(struct ether_header);

	/* Send the packet through the interface that the packet came from */
	send_to_link(interface, send_buf, send_len);

	return 0;
}

int send_solved_packet(uint32_t next_hop_ip_addr, void *buf, int len)
{
	struct ether_header *eth_hdr = (struct ether_header *) buf;
	struct iphdr *ip_hdr = (struct iphdr *)(buf + sizeof(struct ether_header));
	uint8_t mac_addr[MAC_ADDR_LEN];

	struct route_table_entry *best_route = get_best_route(ip_hdr->daddr);

	struct arp_entry *mac_best_route = get_mac_entry(best_route->next_hop);

	get_interface_mac(best_route->interface, mac_addr);

	/* Complete the ethernet header for the packet */
	memcpy(eth_hdr->ether_shost, mac_addr, MAC_ADDR_LEN);

	memcpy(eth_hdr->ether_dhost, mac_best_route->mac, MAC_ADDR_LEN);

	printf("Interface: %d | sent solved packet\n", best_route->interface);

	/* Send the packet through the best route interface */
	send_to_link(best_route->interface, buf, len);

	return 0;
}

int update_arp_table(struct arp_header *arp_hdr)
{
	/* Add a new entry in the arptable solved by the arp */
	arptable[arptable_len].ip = arp_hdr->spa;
	memcpy(arptable[arptable_len].mac, arp_hdr->sha, MAC_ADDR_LEN);

	arptable_len++;

	struct enq_packet *packet;
	int solved_packets = 0;

	/* Send the waiting packets to their destionations */
	for (int i = 0; i < waiting_packets_len; i++) {
		packet = queue_deq(waiting_packets);

		if (packet->next_hop_ip_addr == arp_hdr->spa) {
			send_solved_packet(packet->next_hop_ip_addr, packet->buf, packet->len);
			free_enq_packet(&packet);
			solved_packets++;
		} else {
			queue_enq(waiting_packets, packet);
		}
	}

	waiting_packets_len -= solved_packets;

	return 0;
}

int ip_handler(int interface, void *buf, int len)
{
	struct ether_header *eth_hdr = (struct ether_header *) buf;
	struct iphdr *ip_hdr = (struct iphdr *)(buf + sizeof(struct ether_header));
	uint8_t mac_addr[MAC_ADDR_LEN];
	char *ip_addr_text;
	uint32_t ip_addr_binary;

	uint16_t check = ntohs(ip_hdr->check);
	ip_hdr->check = 0;
	int sum_ok = (checksum((void *) ip_hdr, sizeof(struct iphdr)) == check);

	printf("[ROUTER] checksum: %s\n", sum_ok ? "GOOD" : "BAD");

	if (!sum_ok) {
		perror("Failed checksum");
		return -1;
	}

	ip_hdr->check = check;
	ip_addr_text = get_interface_ip(interface);
	inet_pton(AF_INET, ip_addr_text, &ip_addr_binary);

	if (ip_addr_binary == ip_hdr->daddr) {
		icmp_handler_request(interface, buf, len);
		return 0;
	}

	if (ip_hdr->ttl <= 1) {
		icmp_handler_error(interface, buf, len, ICMP_TTL);
		perror("Failed ttl check");
		return -1;
	}

	uint8_t old_ttl = ip_hdr->ttl;
	ip_hdr->ttl = old_ttl - 1;

	struct route_table_entry *best_route = get_best_route(ip_hdr->daddr);

	if (!best_route) {
		icmp_handler_error(interface, buf, len, ICMP_DEST_UNREACHABLE);
		perror("Failed destination search");
		return -1;
	}

	ip_hdr->check = 0;
	uint16_t new_check = checksum((void *) ip_hdr, sizeof(struct iphdr));	
	ip_hdr->check = htons(new_check);

	struct arp_entry *mac_best_route = get_mac_entry(best_route->next_hop);

	if (!mac_best_route) {
		printf("Need to create arp_request\n");
		struct enq_packet *enq_packet = create_enq_packet(best_route->next_hop, buf, len);
		queue_enq(waiting_packets, enq_packet);
		waiting_packets_len++;

		generate_arp_request(ip_hdr->daddr);
		
		return 0;
	}

	get_interface_mac(best_route->interface, mac_addr);

	memcpy(eth_hdr->ether_shost, mac_addr, MAC_ADDR_LEN);

	memcpy(eth_hdr->ether_dhost, mac_best_route->mac, MAC_ADDR_LEN);

	printf("Interface: %d\n", best_route->interface);

	send_to_link(best_route->interface, buf, len);

	return 0;
}

int arp_handler(int interface, void *buf, int len)
{
	struct arp_header *arp_hdr = (struct arp_header *)(buf + sizeof(struct ether_header));
	uint16_t opcode = ntohs(arp_hdr->op);

	switch (opcode) {
		case OPCODE_ARP_REQUEST:
			generate_arp_reply(arp_hdr->spa, arp_hdr->sha);
			break;
		case OPCODE_ARP_REPLY:
			update_arp_table(arp_hdr);
			break;
		default:
			perror("Wrong opcode for arp");
			break;
	}

	return 0;
}


int main(int argc, char *argv[])
{
	char buf[MAX_PACKET_LEN];

	// Do not modify this line
	init(argc - 2, argv + 2);

	rtable = malloc(sizeof(struct route_table_entry) * MAX_RTABLE_ENTRIES);
	DIE(rtable == NULL, "rtable malloc failed");
	
	arptable = malloc(sizeof(struct arp_entry) * MAX_ARPTABLE_ENTRIES);
	DIE(arptable == NULL, "arptable malloc failed");

	waiting_packets = queue_create();
	waiting_packets_len = 0;

	rtable_len = read_rtable(argv[1], rtable);
	merge_sort(0, rtable_len - 1);
	arptable_len = 0;

	while (1) {

		int interface;
		size_t len;

		interface = recv_from_any_link(buf, &len);
		DIE(interface < 0, "recv_from_any_links");
		printf("We have received a packet\n");

		struct ether_header *eth_hdr = (struct ether_header *) buf;
		/* Note that packets received are in network order,
		any header field which has more than 1 byte will need to be conerted to
		host order. For example, ntohs(eth_hdr->ether_type). The oposite is needed when
		sending a packet on the link, */
		
		uint16_t protocol = ntohs(eth_hdr->ether_type);

		switch (protocol)
		{
			case IPV4_TYPE:
				ip_handler(interface, buf, len);
				break;
		
			case ARP_TYPE:
				arp_handler(interface, buf, len);
				break;

			default:
				break;
		}

	}

	free(rtable);
	free(arptable);

	return 0;
}
