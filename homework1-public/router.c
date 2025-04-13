#include "protocols.h"
#include "queue.h"
#include "lib.h"
#include <arpa/inet.h>
#include <string.h>
#include <stdint.h>

#define BROADCAST_MAC "\xFF\xFF\xFF\xFF\xFF\xFF"
#define ETHERTYPE_IP 0x0800

queue q;
struct route_table_entry rtable[100000];
struct arp_table_entry arptable[100000];
int rtable_len, arptable_len;

int is_for_router(int argc, uint32_t ip_dest) {
	for (int i = 0; i < argc - 2; i++) {
		uint32_t ip_interface = inet_addr(get_interface_ip(i));
		if (ip_dest == ip_interface)
			return 1;
	}
	return 0;
}

struct route_table_entry *find_best_route(uint32_t ip_dest) {
	struct route_table_entry *best = NULL;
	int max_prefix_len = -1;

	for (int i = 0; i < rtable_len; i++) {
		uint32_t prefix = rtable[i].prefix;
		uint32_t mask = rtable[i].mask;
		uint32_t result = ip_dest & mask;

		if (result == (prefix & mask) ) {
			int prefix_len = __builtin_popcount(ntohl(mask));
			if (prefix_len > max_prefix_len) {
				max_prefix_len = prefix_len;
				best = &rtable[i];
			}
		}
	}
	return best;
}

uint8_t* find_mac_adress_arp(struct route_table_entry *next, struct ether_hdr *ether_hdr, struct ip_hdr *ip_hdr) {
	if (next->next_hop == 0) {
		next->next_hop = ip_hdr->dest_addr;
	}
	for (int i = 0; i < arptable_len; i++) {
		struct arp_table_entry *entry = &arptable[i];
		if (entry->ip == next->next_hop) {
			return entry->mac;
		}
	}

	return NULL;
}

void send_arp_request(struct route_table_entry *next, struct ether_hdr *ether_hdr, struct ip_hdr *ip_hdr, size_t router_interface) {

	uint16_t ip_len = ntohs(ip_hdr->tot_len);
	char *buf = malloc(sizeof(struct ether_hdr) + ip_len + sizeof(struct route_table_entry));
	memcpy(buf, ether_hdr, sizeof(struct ether_hdr));
	memcpy(buf + sizeof(struct ether_hdr), ip_hdr, ip_len);

	struct route_table_entry *copy_next = malloc(sizeof(struct route_table_entry));
	memcpy(copy_next, next, sizeof(struct route_table_entry));
	memcpy(buf + sizeof(struct ether_hdr) + ip_len, copy_next, sizeof(struct route_table_entry));

	queue_enq(q, buf);

	struct ether_hdr *ether_packet = malloc(sizeof(struct ether_hdr));
	struct arp_hdr *arp_packet = malloc(sizeof(struct arp_hdr));
	memset(ether_packet, 0, sizeof(struct ether_hdr));
	memset(arp_packet, 0, sizeof(struct arp_hdr));

	ether_packet->ethr_type = htons(ETHERTYPE_ARP);
	uint8_t *interface_mac = malloc (6 * sizeof (uint8_t));
	get_interface_mac(router_interface, interface_mac);
	memcpy(ether_packet->ethr_shost, interface_mac, 6);
	memcpy(ether_packet->ethr_dhost, BROADCAST_MAC, 6);

	arp_packet->hw_type = htons(1);
	arp_packet->proto_type = htons(ETHERTYPE_IP);
	arp_packet->hw_len = 6;
	arp_packet->proto_len = 4;
	arp_packet->opcode = htons(1);
	memcpy(arp_packet->shwa, interface_mac, 6);
	arp_packet->sprotoa = inet_addr(get_interface_ip(router_interface));
	memset(arp_packet->thwa , 0 ,6);
	arp_packet->tprotoa = next->next_hop;

	char *buff = calloc(1, sizeof(struct ether_hdr) + sizeof(struct arp_hdr));
	memcpy(buff, ether_packet, sizeof(struct ether_hdr));
	memcpy(buff + sizeof(struct ether_hdr), arp_packet, sizeof(struct arp_hdr));
	send_to_link(sizeof(struct ether_hdr) + sizeof(struct arp_hdr), buff, next->interface);

	free(buff);
	free(ether_packet);
	free(arp_packet);
}

void send_error_icmp (struct ip_hdr *ip_hdr, struct ether_hdr *ether_hdr, int type, size_t router_interface) {

	struct icmp_hdr *icmp_hdr = malloc(sizeof(struct icmp_hdr));
	icmp_hdr->mtype = type;
	icmp_hdr->mcode = 0;

	//modific header ether
	struct ether_hdr *original_ether = malloc(sizeof(struct ether_hdr));
	memcpy(original_ether, ether_hdr, sizeof(struct ether_hdr));

	uint8_t *aux = malloc(6 * sizeof(uint8_t));
	memcpy(aux, ether_hdr->ethr_shost, 6);
	memcpy(ether_hdr->ethr_shost, ether_hdr->ethr_dhost, 6);
	memcpy(ether_hdr->ethr_dhost, aux, 6);

	//modific header ip
	struct ip_hdr *original_ip = malloc(sizeof(struct ip_hdr));
	memcpy(original_ip, ip_hdr, sizeof(struct ip_hdr));

	uint32_t aux2 = ip_hdr->source_addr;
	ip_hdr->source_addr = ip_hdr->dest_addr;
	ip_hdr->dest_addr = aux2;

	ip_hdr->tos = 0;
	ip_hdr->frag = 0;
	ip_hdr->ver = 4;
	ip_hdr->ihl = 5;
	ip_hdr->id = 4;
	ip_hdr->checksum = 0;
	ip_hdr->tot_len = htons(sizeof(struct ip_hdr) + sizeof(struct icmp_hdr) + 28);
	ip_hdr->checksum = checksum((uint16_t*)ip_hdr, sizeof(struct ip_hdr));
	ip_hdr->ttl = 64;
	ip_hdr->proto = 1;

	char *buf = malloc(sizeof(struct ether_hdr) + sizeof(struct ip_hdr) + sizeof(struct icmp_hdr) + 28);
	char *original_payload = (char *)original_ip + sizeof(struct ip_hdr);

	memcpy(buf, ether_hdr, sizeof(struct ether_hdr));
	memcpy(buf + sizeof(struct ether_hdr), ip_hdr, sizeof(struct ip_hdr));
	memcpy(buf + sizeof(struct ether_hdr) + sizeof(struct ip_hdr), icmp_hdr, sizeof(struct icmp_hdr));
	memcpy(buf + sizeof(struct ether_hdr) + sizeof(struct ip_hdr) + sizeof(struct icmp_hdr), original_ip, 20);
	memcpy(buf + sizeof(struct ether_hdr) + sizeof(struct ip_hdr) + sizeof(struct icmp_hdr) + 20, original_payload, 8);

	struct icmp_hdr *checksum_icmp = (struct icmp_hdr*) (buf + sizeof(struct ether_hdr) + sizeof(struct ip_hdr));
	checksum_icmp->check = 0;
	checksum_icmp->check = checksum((uint16_t*)checksum_icmp, sizeof(struct icmp_hdr) + 28);

	send_to_link(sizeof(struct ether_hdr) + sizeof(struct ip_hdr) + sizeof(struct icmp_hdr) + 28, buf, router_interface);
}


void send_icmp_echo_reply(struct ip_hdr *ip_hdr, struct ether_hdr *ether_hdr, int interface) {

	struct icmp_hdr *icmp_hdr = (struct icmp_hdr *)((char *)ip_hdr + sizeof(struct ip_hdr));
	icmp_hdr->mcode = 0;
	icmp_hdr->mtype = 0;
	int icmp_len = ntohs(ip_hdr->tot_len) - sizeof(struct ip_hdr);

	uint8_t *aux = malloc(6 * sizeof(uint8_t));
	memcpy(aux, ether_hdr->ethr_shost, 6);
	memcpy(ether_hdr->ethr_shost, ether_hdr->ethr_dhost, 6);
	memcpy(ether_hdr->ethr_dhost, aux, 6);

	uint32_t aux2 = ip_hdr->dest_addr;
	ip_hdr->dest_addr = ip_hdr->source_addr;
	ip_hdr->source_addr = aux2;
	ip_hdr->checksum = 0;
	ip_hdr->tot_len = htons(sizeof(struct ip_hdr) + icmp_len);
	ip_hdr->checksum = checksum((uint16_t*)(ip_hdr), sizeof(struct ip_hdr));

	//find next-hop
	struct route_table_entry *next = find_best_route(ip_hdr->source_addr);
	if (!next) {
		printf("Destination unreachable\n");
		return;
	}

	uint8_t *mac = find_mac_adress_arp(next, ether_hdr, ip_hdr);
	uint8_t *interface_mac = malloc (6 * sizeof (uint8_t));
	get_interface_mac(next->interface, interface_mac);
	memcpy(ether_hdr->ethr_shost, interface_mac, 6);

	memcpy(ether_hdr->ethr_dhost, mac, 6);

	char *buf = malloc(sizeof(struct ether_hdr) + sizeof(struct ip_hdr) + icmp_len);

	memcpy(buf, ether_hdr, sizeof(struct ether_hdr));
	memcpy(buf + sizeof(struct ether_hdr), ip_hdr, sizeof(struct ip_hdr));
	memcpy(buf + sizeof(struct ether_hdr) + sizeof(struct ip_hdr), (char*)ip_hdr + sizeof(struct ip_hdr), icmp_len);

	struct icmp_hdr *checksum_icmp = (struct icmp_hdr*) (buf + sizeof(struct ether_hdr) + sizeof(struct ip_hdr));
	checksum_icmp->check = 0;
	checksum_icmp->check = checksum((uint16_t*)checksum_icmp, icmp_len);

	send_to_link(sizeof(struct ether_hdr) + sizeof(struct ip_hdr) + icmp_len, buf, next->interface);

}

void process_ip_packet(struct ip_hdr *ip_hdr, struct ether_hdr *ether_hdr, size_t router_interface) {

	uint16_t original_checksum = ntohs(ip_hdr->checksum);
	ip_hdr->checksum = 0;
	uint16_t new_checksum = checksum((uint16_t*)ip_hdr, sizeof(struct ip_hdr));

	if (original_checksum != new_checksum) {
		printf("Bad checksum\n");
		return;
	}

	struct route_table_entry *next = find_best_route(ip_hdr->dest_addr);
	if (!next) {
		printf("Destination unreachable\n");
		send_error_icmp(ip_hdr, ether_hdr, 3, router_interface);
		return;
	}

	if (ip_hdr->ttl <= 1) {
		//treb trimis catre emitator time excedeed
		send_error_icmp(ip_hdr, ether_hdr, 11, router_interface);
		printf("TTL\n");
		return;
	}
	ip_hdr->ttl--;

	ip_hdr->checksum = htons(checksum((uint16_t*)ip_hdr, sizeof(struct ip_hdr)));

	if (next->next_hop == 0) {
		next->next_hop = ip_hdr->dest_addr;
	}


	uint8_t *mac = find_mac_adress_arp(next, ether_hdr, ip_hdr);
	if (!mac) {
		send_arp_request(next, ether_hdr, ip_hdr, next->interface);
		return;
	}

	uint8_t *interface_mac = malloc (6 * sizeof (uint8_t));
	get_interface_mac(next->interface, interface_mac);
	memcpy(ether_hdr->ethr_shost, interface_mac, 6);

	memcpy(ether_hdr->ethr_dhost ,mac, 6);

	uint16_t ip_len = ntohs(ip_hdr->tot_len);

	char *buf = malloc(sizeof(struct ether_hdr) + ip_len);
	memcpy(buf, ether_hdr, sizeof(struct ether_hdr));
	memcpy(buf + sizeof(struct ether_hdr), ip_hdr, ip_len);

	send_to_link(sizeof(struct ether_hdr) + ip_len, buf, next->interface);

	free(interface_mac);
	free(buf);
}

void process_arp_request(struct arp_hdr* arp_hdr, size_t router_interface, int argc) {

	uint32_t router_ip = inet_addr(get_interface_ip(router_interface));

	if (is_for_router(argc, arp_hdr->sprotoa)) {

		uint8_t *interface_mac = malloc (6 * sizeof (uint8_t));
		get_interface_mac(router_interface, interface_mac);

		uint32_t interface_ip = inet_addr(get_interface_ip(router_interface));

		struct ether_hdr *ether_hdr = malloc(sizeof(struct ether_hdr));
		struct arp_hdr *arp_reply = malloc(sizeof(struct arp_hdr));

		ether_hdr->ethr_type = htons(ETHERTYPE_ARP);
		memcpy(ether_hdr->ethr_dhost, arp_hdr->shwa, 6);
		memcpy(ether_hdr->ethr_shost, interface_mac ,6);

		arp_reply->hw_type = htons(1);
        arp_reply->proto_type = htons(ETHERTYPE_IP);
        arp_reply->hw_len = 6;
        arp_reply->proto_len = 4;
        arp_reply->opcode = htons(2); //arp reply

		memcpy(arp_reply->shwa, interface_mac, 6);

		arp_reply->sprotoa = interface_ip;

		memcpy(arp_reply->thwa, arp_hdr->shwa, 6);

		arp_reply->tprotoa = arp_hdr->sprotoa;

		char *buf = malloc(sizeof(struct ether_hdr) + sizeof(struct arp_hdr));
		memcpy(buf, ether_hdr, sizeof(struct ether_hdr));
		memcpy(buf + sizeof(struct ether_hdr), arp_reply, sizeof(struct arp_hdr));

		send_to_link(sizeof(struct ether_hdr) + sizeof(struct arp_hdr), buf, router_interface);

	} else {
		printf("Arp packet not for me\n");
		return;
	}
}

void process_arp_reply(struct arp_hdr* arp_hdr, size_t router_interface) {

	int done = 0;
	for (int i = 0; i < arptable_len; i++) {
		if (arptable[i].ip == arp_hdr->sprotoa) {
			memcpy(arptable[i].mac, arp_hdr->shwa, 6);
			done = 1;
			break;
		}
	}

	// Dacă nu am găsit intrarea, o adăugăm
	if (!done) {
		arptable[arptable_len].ip = arp_hdr->sprotoa;
		memcpy(arptable[arptable_len].mac, arp_hdr->shwa, 6);
		arptable_len++;
	}

	queue temp = create_queue();
	while (!queue_empty(q)) {
		char *packet = queue_deq(q);
		struct ether_hdr *ether_hdr = (struct ether_hdr*) packet;
		struct ip_hdr *ip_hdr = (struct ip_hdr*) (packet + sizeof(struct ether_hdr));

		uint16_t ip_len = ntohs(ip_hdr->tot_len);
		struct route_table_entry *next = (struct route_table_entry*) (packet + sizeof(struct ether_hdr) + ip_len);

		if (next->next_hop == arp_hdr->sprotoa || ip_hdr->dest_addr == arp_hdr->sprotoa) {

			memcpy(ether_hdr->ethr_dhost, arp_hdr->shwa, 6);

			uint16_t ip_len = ntohs(ip_hdr->tot_len);
			char *buf = malloc(sizeof(struct ether_hdr) + ip_len);
			memcpy(buf, ether_hdr, sizeof(struct ether_hdr));
			memcpy(buf + sizeof(struct ether_hdr), ip_hdr, ip_len);
			send_to_link(sizeof(struct ether_hdr) + ip_len, buf, router_interface);
			free(buf);
		} else {
			queue_enq(temp , packet);
		}
	}

	while(!queue_empty(temp)) {
		queue_enq(q, queue_deq(temp));
	}

}

void process_arp_packet(struct arp_hdr* arp_hdr, size_t router_interface, int argc) {
	if (ntohs(arp_hdr->opcode) == 1) {
		//arp request
		process_arp_request(arp_hdr, router_interface, argc);

	} else if (ntohs(arp_hdr->opcode) == 2) {
		//arp reply
		process_arp_reply(arp_hdr, router_interface);

	} else {
		printf("Unrecognized arp packet\n");
		return;
	}
}


int main(int argc, char *argv[])
{
	char buf[MAX_PACKET_LEN];

	// Do not modify this line
	init(argv + 2, argc - 2);

	q = create_queue();
	rtable_len = read_rtable(argv[1], rtable);
	arptable_len = 0;

	char local_buf[MAX_PACKET_LEN];

	while (1) {

		size_t interface;
		size_t len;

		interface = recv_from_any_link(buf, &len);
		DIE(interface < 0, "recv_from_any_links");

		memcpy(local_buf, buf, len);

    // TODO: Implement the router forwarding logic

    /* Note that packets received are in network order,
		any header field which has more than 1 byte will need to be conerted to
		host order. For example, ntohs(eth_hdr->ether_type). The oposite is needed when
		sending a packet on the link, */

		if (len < sizeof(struct ether_hdr) + sizeof(struct ip_hdr)) {
			printf("Ignored packet, too short\n");
			continue;
		}

		struct ether_hdr *ether_hdr = (struct ether_hdr*) local_buf;
		struct ip_hdr *ip_hdr = (struct ip_hdr*) (local_buf + sizeof(struct ether_hdr));

		uint8_t *interface_mac = malloc(6 * sizeof (uint8_t));
		get_interface_mac(interface, interface_mac);
		uint32_t ip_uint = inet_addr((get_interface_ip(interface)));

		if (ntohs(ether_hdr->ethr_type) != ETHERTYPE_IP && ntohs(ether_hdr->ethr_type) != ETHERTYPE_ARP) {
			printf("Ignored non IPv4 or ARP packet\n");
			continue;
		}

		if (ntohs(ether_hdr->ethr_type) == ETHERTYPE_ARP) {
			struct arp_hdr *arp_hdr = (struct arp_hdr*) (buf + sizeof(struct ether_hdr));
			printf("Processing ARP packet\n");
			process_arp_packet(arp_hdr, interface, argc);

		} else {
			if (is_for_router(argc, ip_hdr->dest_addr) == 1) {
				//pachetul e pt mine
				if (ip_hdr->proto == IPPROTO_ICMP) {
					struct icmp_hdr *icmp_hdr = (struct icmp_hdr *)((char *)ip_hdr + sizeof(struct ip_hdr));
					if (icmp_hdr->mtype == 8) {
						//echo request
						send_icmp_echo_reply(ip_hdr, ether_hdr, interface);
						printf("Processing ICMP echo request\n");
					}
				}
			} else {
				if (ntohs(ether_hdr->ethr_type) == ETHERTYPE_IP)
				printf("Processing IP packet\n");
				process_ip_packet(ip_hdr, ether_hdr, interface);
			}
		}

	}
	return 0;
}

