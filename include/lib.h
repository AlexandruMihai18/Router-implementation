#ifndef _SKEL_H_
#define _SKEL_H_

#include <unistd.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

#define MAX_PACKET_LEN 1600
#define ROUTER_NUM_INTERFACES 3
#define MAX_RTABLE_ENTRIES 80000
#define MAX_ARPTABLE_ENTRIES 10
#define MAC_ADDR_LEN 6
#define IPV4_LEN 4
#define ICMP_ERROR_PAYLOAD 64
#define ICMP_TTL 11
#define ICMP_DEST_UNREACHABLE 3
#define STANDARD_TTL 64
#define IPV4_TYPE 0x0800
#define ARP_TYPE 0x0806
#define ETHERNET_TYPE 1
#define OPCODE_ARP_REQUEST 1
#define OPCODE_ARP_REPLY 2
#define BROADCAST_PREF 0xff

int send_to_link(int interface, char *frame_data, size_t length);

/*
 * @brief Receives a packet. Blocking function, blocks if there is no packet to
 * be received.
 *
 * @param frame_data - region of memory in which the data will be copied; should
 *        have at least MAX_PACKET_LEN bytes allocated 
 * @param length - will be set to the total number of bytes received.
 * Returns: the interface it has been received from.
 */
int recv_from_any_link(char *frame_data, size_t *length);

/* Route table entry */
struct route_table_entry {
	uint32_t prefix;
	uint32_t next_hop;
	uint32_t mask;
	int interface;
} __attribute__((packed));

/* ARP table entry when skipping the ARP exercise */
struct arp_entry {
    uint32_t ip;
    uint8_t mac[6];
};

/* Enqueue packet waiting for an ARP reply */
struct enq_packet
{
	uint32_t next_hop_ip_addr;
	char *buf;
	int len;
};

char *get_interface_ip(int interface);

/**
 * @brief Get the interface mac object. The function writes
 * the MAC at the pointer mac. uint8_t *mac should be allocated.
 *
 * @param interface
 * @param mac
 */
void get_interface_mac(int interface, uint8_t *mac);

/**
 * @brief IPv4 checksum per  RFC 791. To compute the checksum
 * of an IP header we must set the checksum to 0 beforehand.
 *
 * also works as ICMP checksum per RFC 792. To compute the checksum
 * of an ICMP header we must set the checksum to 0 beforehand.

 * @param data memory area to checksum
 * @param size in bytes
 */
uint16_t checksum(uint16_t *data, size_t len);

/**
 * hwaddr_aton - Convert ASCII string to MAC address (colon-delimited format)
 * @txt: MAC address as a string (e.g., "00:11:22:33:44:55")
 * @addr: Buffer for the MAC address (ETH_ALEN = 6 bytes)
 * Returns: 0 on success, -1 on failure (e.g., string not a MAC address)
 */
int hwaddr_aton(const char *txt, uint8_t *addr);

/* Populates a route table from file, rtable should be allocated
 * e.g. rtable = malloc(sizeof(struct route_table_entry) * 80000);
 * This function returns the size of the route table.
 */
int read_rtable(const char *path, struct route_table_entry *rtable);

/* Parses a static mac table from path and populates arp_table.
 * arp_table should be allocated and have enough space. This
 * function returns the size of the arp table.
 * */
int parse_arp_table(char *path, struct arp_entry *arp_table);


/**
 * @brief Homework infrastructure function.
 *
 * @param argc
 * @param argv
 */
void init(int argc, char *argv[]);

/** 
 * Create a packet that will be later transmitted after an ARP reply
 * from the next hop
 * */
struct enq_packet *create_enq_packet(uint32_t next_hop_ip_addr, void *buf, int len);

/**
 * Free the resources after sending the enqueued packet
 * */
void free_enq_packet(struct enq_packet **enq_packet);

#define DIE(condition, message, ...) \
	do { \
		if ((condition)) { \
			fprintf(stderr, "[(%s:%d)]: " # message "\n", __FILE__, __LINE__, ##__VA_ARGS__); \
			perror(""); \
			exit(1); \
		} \
	} while (0)

#endif /* _SKEL_H_ */
