#include "protocols.h"
#include "queue.h"
#include "lib.h"

#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <arpa/inet.h>

#define MAX_RT_ENTRIES    100000
#define MAX_ARP_ENTRIES   10000

/* Definim constantelor pentru ARP */
#define ARP_REQUEST 1
#define ARP_REPLY   2

/* Definim constantelor pentru ICMP */
#define ICMP_ECHO_REQUEST  8
#define ICMP_ECHO_REPLY    0
#define ICMP_DEST_UNREACH  3
#define ICMP_TIME_EXCEEDED 11

static int nr_interfaces;

static struct route_table_entry rtable[MAX_RT_ENTRIES];
static int rtable_len;

static struct arp_table_entry arp_table[MAX_ARP_ENTRIES];
static int arp_table_len;

typedef struct waiting_package {
    char *buf;
    size_t len;
    int interface;
    uint32_t hop_ip;
} waiting_package_t;

typedef struct TrieNode {
    struct TrieNode *child[2];
    struct route_table_entry *entry;
} TrieNode;

struct queue *waiting_queue;

TrieNode *create_node() {
    TrieNode *node = malloc(sizeof(TrieNode));
    DIE(node == NULL, "malloc failed trie");
    node->child[0] = NULL;
    node->child[1] = NULL;
    node->entry = NULL;
    return node;
}

static int get_prefix_length(uint32_t mask_net) {
    uint32_t mask = ntohl(mask_net);
    int len = 0;
    while (mask & 0x80000000) {
        len++;
        mask <<= 1;
    }
    return len;
}

static void insert_route(TrieNode *root, struct route_table_entry *entry) {
    int len = get_prefix_length(entry->mask);
    uint32_t prefix = ntohl(entry->prefix);
    TrieNode *current = root;

    for (int j = 0; j < len; j++) {
        int bit = (prefix >> (31 - j)) & 1;
        if (current->child[bit] == NULL) {
            current->child[bit] = create_node();
        }
        current = current->child[bit];
    }
    current->entry = entry;
}

struct route_table_entry *get_best_route(uint32_t ip_dest) {
    static TrieNode *root = NULL;

    if (!root) {
        root = create_node();
        for (int i = 0; i < rtable_len; i++) {
            insert_route(root, &rtable[i]);
        }
    }
    TrieNode *current = root;
    struct route_table_entry *best = NULL;
    uint32_t dest = ntohl(ip_dest);

    for (int i = 0; i < 32; i++) {
        if (current->entry != NULL) {
            best = current->entry;
        }
        int bit = (dest >> (31 - i)) & 1;
        if (current->child[bit] == NULL) {
            break;
        }
        current = current->child[bit];
    }
    return best;
}

struct arp_table_entry *get_arp_entry(uint32_t given_ip) {
    for (int i = 0; i < arp_table_len; i++) {
        if (arp_table[i].ip == given_ip) {
            return &arp_table[i];
        }
    }
    return NULL;
}

void check_arp (uint32_t given_ip, uint8_t *given_mac) {
    for (int i = 0; i < arp_table_len; i++) {
        if (arp_table[i].ip == given_ip) {
           memcpy(arp_table[i].mac, given_mac, 6);
           return;
        }
    }
    if (arp_table_len < MAX_ARP_ENTRIES) {
        arp_table[arp_table_len].ip = given_ip;
        memcpy(arp_table[arp_table_len].mac, given_mac, 6);
        arp_table_len ++;
    } else {
        fprintf(stderr, "cache full la arp\n");
    }
}

void arp_req(uint32_t hop_urm, int interface) {
    char buf[MAX_PACKET_LEN];
    memset(buf, 0, MAX_PACKET_LEN);

    struct ether_hdr *eth_hdr = (struct ether_hdr *) buf;
    struct arp_hdr *arp_hdr = (struct arp_hdr *)(buf + sizeof(struct ether_hdr));

    memset(eth_hdr->ethr_dhost, 0xFF, 6);
    eth_hdr->ethr_type = htons(0x0806);
    get_interface_mac(interface, eth_hdr->ethr_shost);

    // Header ARP
    arp_hdr->hw_type = htons(1);       // Ethernet
    arp_hdr->hw_len = 6;
    arp_hdr->proto_type = htons(0x0800); // IPv4
    arp_hdr->proto_len = 4;
    arp_hdr->opcode = htons(ARP_REQUEST);
    get_interface_mac(interface, arp_hdr->shwa);
    arp_hdr->sprotoa = inet_addr(get_interface_ip(interface));
    memset(arp_hdr->thwa, 0, 6);
    arp_hdr->tprotoa = hop_urm;

    size_t len = sizeof(struct ether_hdr) + sizeof(struct arp_hdr);
    send_to_link(len, buf, interface);
}

void arp_reply (char *buf, size_t len, int interface) {
    struct ether_hdr *eth_hdr = (struct ether_hdr *) buf;
    struct arp_hdr *arp_hdr = (struct arp_hdr *)(buf + sizeof(struct ether_hdr));

    arp_hdr->opcode = htons(ARP_REPLY);
    get_interface_mac(interface, arp_hdr->shwa);
    memcpy(arp_hdr->thwa, eth_hdr->ethr_shost, 6);
    arp_hdr->sprotoa = inet_addr(get_interface_ip(interface));
    memcpy(eth_hdr->ethr_dhost, eth_hdr->ethr_shost, 6);
    get_interface_mac(interface, eth_hdr->ethr_shost);
    send_to_link(len, buf, interface);
}

int is_waiting(uint32_t hop_urm) {
    int found = 0;
    queue temp = create_queue();
    while(!queue_empty(waiting_queue)) {
        waiting_package_t *package = queue_deq(waiting_queue);
        if (package->hop_ip == hop_urm) {
            found = 1;
        }
        queue_enq(temp, package);
    }
    while (!queue_empty(temp)) {
        waiting_package_t *package = queue_deq(temp);
        queue_enq(waiting_queue, package);
    }
    return found;
}

/* Modificat: verificăm înainte de adăugarea în coadă */
void choose_arp(uint32_t hop, char *package, size_t len, int interface) {
    /* Dacă nu există deja un pachet în așteptare pentru acest IP, trimitem ARP request */
    if (!is_waiting(hop)) {
        arp_req(hop, interface);
    }
    waiting_package_t *package1 = malloc(sizeof(waiting_package_t));
    DIE(package1 == NULL, "malloc la pachet");
    package1->buf = malloc(len);
    DIE(package1->buf == NULL, "malloc la pachet buf");
    memcpy(package1->buf, package, len);
    package1->len = len;
    package1->interface = interface;
    package1->hop_ip = hop;
    queue_enq(waiting_queue, package1);
}

void waiting_packages(uint32_t ip) {
    queue new_queue = create_queue();
    while (!queue_empty(waiting_queue)) {
        waiting_package_t *package = queue_deq(waiting_queue);
        if (package->hop_ip == ip) {
            struct ether_hdr *eth_hdr = (struct ether_hdr *) package->buf;
            struct arp_table_entry *entry = get_arp_entry(ip);
            if (entry) {
                memcpy(eth_hdr->ethr_dhost, entry->mac, 6);
                get_interface_mac(package->interface, eth_hdr->ethr_shost);
                send_to_link(package->len, package->buf, package->interface);
            }
            free(package->buf);
            free(package);
        } else {
            queue_enq(new_queue, package);
        }
    }
    waiting_queue = new_queue;
}

void handle_package(char *buf, size_t len, int interface) {
    struct arp_hdr *arp_hdr = (struct arp_hdr *) (buf + sizeof(struct ether_hdr));
    uint16_t op = ntohs(arp_hdr->opcode);
    if (op == ARP_REQUEST) {
        for(int i = 0; i < nr_interfaces; i++) {
            if (arp_hdr->tprotoa == inet_addr(get_interface_ip(i))) {
                check_arp(arp_hdr->sprotoa, arp_hdr->shwa);
                arp_reply(buf, len, interface);
                return;
            }
        }
    } else if (op == ARP_REPLY) {
        check_arp(arp_hdr->sprotoa, arp_hdr->shwa);
        waiting_packages(arp_hdr->sprotoa);
    }
}

void icmp_reply(char *buf, size_t len, int interface) {

    struct ether_hdr *eth = (struct ether_hdr *) buf;
    struct ip_hdr *ip = (struct ip_hdr*) (buf + sizeof(struct ether_hdr));
    struct icmp_hdr *icmp = (struct icmp_hdr*)((uint8_t *)ip + sizeof(struct ip_hdr));

    size_t tot_len = ntohs(ip->tot_len);
    size_t icmp_len = tot_len - sizeof(struct ip_hdr);

    char package[MAX_PACKET_LEN];
    memset(package, 0, MAX_PACKET_LEN);

    struct ip_hdr *new_ip = (struct ip_hdr *)(package + sizeof(struct ether_hdr));
    new_ip->ihl = 5;
    new_ip->ver = 4;
    new_ip->tos = 0;
    new_ip->tot_len = htons(sizeof(struct ip_hdr) + icmp_len);
    new_ip->id = ip->id;
    new_ip->frag = 0;
    new_ip->ttl = 64;
    new_ip->proto = 1;  //ICMP
    new_ip->checksum = 0;
    new_ip->source_addr = ip->dest_addr;
    new_ip->dest_addr = ip->source_addr;
    new_ip->checksum = htons(checksum((uint16_t *)new_ip, sizeof(struct ip_hdr)));


    struct icmp_hdr *new_icmp = (struct icmp_hdr *)(package + sizeof(struct ether_hdr) + sizeof(struct ip_hdr));
    memcpy(new_icmp, icmp, icmp_len);
    new_icmp->mtype = 0;
    new_icmp->check = 0;
    new_icmp->check = htons(checksum((uint16_t *)new_icmp, icmp_len));

    struct ether_hdr *new_eth = (struct ether_hdr *)package;
    memcpy(new_eth->ethr_dhost, eth->ethr_shost, 6);
    get_interface_mac(interface, new_eth->ethr_shost);
    new_eth->ethr_type = htons(0x0800);

    size_t send_len = sizeof(struct ether_hdr) + sizeof(struct ip_hdr) + icmp_len;
    send_to_link(send_len, package, interface);

}

void icmp_error(char *buf, size_t len, int interface, uint8_t type, uint8_t code) {

    struct ether_hdr *eth = (struct ether_hdr *)buf;
    struct ip_hdr *ip = (struct ip_hdr *)(buf + sizeof(struct ether_hdr));

    char package[MAX_PACKET_LEN];
    memset(package, 0, MAX_PACKET_LEN);


    struct ether_hdr *new_eth = (struct ether_hdr *)package;
    memcpy(new_eth->ethr_dhost, eth->ethr_shost, 6);
    get_interface_mac(interface, new_eth->ethr_shost);
    new_eth->ethr_type = htons(0x0800);

    struct ip_hdr *new_ip = (struct ip_hdr *)(package + sizeof(struct ether_hdr));
    new_ip->ihl = 5;
    new_ip->ver = 4;
    new_ip->tos = 0;
    new_ip->tot_len = htons(20 + 8 + 8);
    new_ip->id = 0;
    new_ip->frag = 0;
    new_ip->ttl = 64;
    new_ip->proto = 1;  // ICMP
    new_ip->checksum = 0;
    new_ip->source_addr = ip->dest_addr;
    new_ip->dest_addr = ip->source_addr;
    new_ip->checksum = htons(checksum((uint16_t *)new_ip, sizeof(struct ip_hdr)));

    struct icmp_hdr *new_icmp = (struct icmp_hdr *)((uint8_t *)new_ip + sizeof(struct ip_hdr));
    new_icmp->mtype = type;
    new_icmp->mcode = code;
    new_icmp->check = 0;

    *((uint32_t *)&new_icmp->un_t) = 0;

    size_t copy_len = sizeof(struct ip_hdr) + 8;
    size_t available = 0;
    if (len > sizeof(struct ether_hdr)) {
        available = (len - sizeof(struct ether_hdr));
    }
    if (copy_len > available)
        copy_len = available;
    memcpy((uint8_t *)new_icmp + sizeof(struct icmp_hdr), ip, copy_len);

    uint16_t icmp_len = sizeof(struct icmp_hdr) + copy_len;
    new_icmp->check = htons(checksum((uint16_t *)new_icmp, icmp_len));

    size_t send_len = sizeof(struct ether_hdr) + ntohs(new_ip->tot_len);
    send_to_link(send_len, package, interface);
}



int main(int argc, char *argv[])
{
    char buf[MAX_PACKET_LEN];

    // Do not modify this line
    init(argv + 2, argc - 2);

    /* Populate route table */
    rtable_len = read_rtable(argv[1], rtable);
    DIE(rtable_len <= 0, "Cannot read route table");

    arp_table_len = 0;
    waiting_queue = create_queue();
    nr_interfaces = argc - 2;

    while (1) {
        size_t interface;
        size_t len;

        interface = recv_from_any_link(buf, &len);
        DIE(interface < 0, "recv_from_any_links");

        struct ether_hdr *eth_hdr = (struct ether_hdr *) buf;
        if (ntohs(eth_hdr->ethr_type) == 0x0806) {
            handle_package(buf, len, interface);
            continue;
        }
        if (ntohs(eth_hdr->ethr_type) != 0x0800)
            continue;

        struct ip_hdr *ip_hdr = (struct ip_hdr *)(buf + sizeof(struct ether_hdr));
        /* Verify IP checksum */
        uint16_t original_checksum = ip_hdr->checksum;
        ip_hdr->checksum = 0;
        if (htons(checksum((uint16_t *) ip_hdr, sizeof(struct ip_hdr))) != original_checksum) {
            continue;
        }
        ip_hdr->checksum = original_checksum;

        /* Check if packet is destined for router */
        int is_for_router = 0;
        for (int i = 0; i < (argc - 2); i++) {
            uint32_t if_ip = inet_addr(get_interface_ip(i));
            if (ip_hdr->dest_addr == if_ip) {
                is_for_router = 1;
                break;
            }
        }
        if (is_for_router) {
            if (ip_hdr->proto == 1) {  /* ICMP */
                struct icmp_hdr *icmp = (struct icmp_hdr *)((uint8_t *)ip_hdr + sizeof(struct ip_hdr));
                if (icmp->mtype == ICMP_ECHO_REQUEST) {
                    icmp_reply(buf, len, interface);
                }
            }
            continue;
        }
        /* Update TTL */
        ip_hdr->ttl--;
        if (ip_hdr->ttl <= 0) {
            icmp_error(buf, len, interface, ICMP_TIME_EXCEEDED, 0);
            continue;
        }

        ip_hdr->checksum = 0;
        ip_hdr->checksum = htons(checksum((uint16_t *) ip_hdr, sizeof(struct ip_hdr)));

        /* Find best route using LPM */
        struct route_table_entry *best = get_best_route(ip_hdr->dest_addr);
        if (!best) {
            icmp_error(buf, len, interface, ICMP_DEST_UNREACH, 0);
            continue;
        }


        uint32_t next_hop_ip = best->next_hop;
        if (next_hop_ip == 0)
            next_hop_ip = ip_hdr->dest_addr;

        /* ARP lookup */
        struct arp_table_entry *arp_entry = get_arp_entry(next_hop_ip);
        if (!arp_entry) {
            choose_arp(next_hop_ip, buf, len, best->interface);
            continue;
        }

        /* Rewrite L2 addresses: dest = next hop MAC; source = interface MAC */
        memcpy(eth_hdr->ethr_dhost, arp_entry->mac, 6);
        get_interface_mac(best->interface, eth_hdr->ethr_shost);

        /* Forward packet on correct interface */
        send_to_link(len, buf, best->interface);
    }

    return 0;
}