/**********************************************************************
 * file:  sr_router.c
 * date:  Mon Feb 18 12:50:42 PST 2002
 * Contact: casado@stanford.edu
 *
 * Description:
 *
 * This file contains all the functions that interact directly
 * with the routing table, as well as the main entry method
 * for routing.
 *
 **********************************************************************/

#include <stdio.h>
#include <assert.h>


#include "sr_if.h"
#include "sr_rt.h"
#include "sr_router.h"
#include "sr_protocol.h"
#include "sr_arpcache.h"
#include "sr_utils.h"
#include "sr_message.c"


/*---------------------------------------------------------------------
 * Method: sr_init(void)
 * Scope:  Global
 *
 * Initialize the routing subsystem
 *
 *---------------------------------------------------------------------*/

void sr_init(struct sr_instance* sr)
{
    /* REQUIRES */
    assert(sr);

    /* Initialize cache and cache cleanup thread */
    sr_arpcache_init(&(sr->cache));

    pthread_attr_init(&(sr->attr));
    pthread_attr_setdetachstate(&(sr->attr), PTHREAD_CREATE_JOINABLE);
    pthread_attr_setscope(&(sr->attr), PTHREAD_SCOPE_SYSTEM);
    pthread_attr_setscope(&(sr->attr), PTHREAD_SCOPE_SYSTEM);
    pthread_t thread;

    pthread_create(&thread, &(sr->attr), sr_arpcache_timeout, sr);
    
    /* Add initialization code here! */

} /* -- sr_init -- */

/*---------------------------------------------------------------------
 * Method: sr_handlepacket(uint8_t* p,char* interface)
 * Scope:  Global
 *
 * This method is called each time the router receives a packet on the
 * interface.  The packet buffer, the packet length and the receiving
 * interface are passed in as parameters. The packet is complete with
 * ethernet headers.
 *
 * Note: Both the packet buffer and the character's memory are handled
 * by sr_vns_comm.c that means do NOT delete either. Make a copy of the
 * packet instead if you intend to keep it around beyond the scope of
 * the method call.
 *
 *---------------------------------------------------------------------*/

void sr_handlepacket(struct sr_instance* sr,
        uint8_t * packet/* lent */,
        unsigned int len,
        char* interface/* lent */)
{
	/* REQUIRES */
	assert(sr);
	assert(packet);
	assert(interface);

	printf("*** -> Received packet of length %d \n",len);

	/* When the router receives any packet, it should be determined what
	* type of the protocol is.
	*/
	sr_ethernet_hdr_t *packet_header = (sr_ethernet_hdr_t *) packet;
	uint16_t ethernet_protocol_type = htons(packet_header->ether_type);

	if(ethernet_protocol_type == ethertype_arp){
		sr_handlepacket_arp(sr, packet, len, interface);
	}else if(ethernet_protocol_type == ethertype_ip){
		sr_handlepacket_ip(sr, packet, len, interface);
	}
}/* end sr_handlepacket */

/*---------------------------------------------------------------------
 * Method: sr_handlepacket_arp(struct sr_instance* sr,
 *      						uint8_t*  packet,
 *      						unsigned int len,
 *								char* interface)
 * Scope:  Local
 *
 * When the ethernet type is Address Resolution Protocol
 *
 *---------------------------------------------------------------------*/
void sr_handlepacket_arp(struct sr_instance* sr,
        uint8_t*  packet,
        unsigned int len,
		char* interface){
	/* REQUIRES */
	assert(sr);
	assert(packet);
	assert(interface);

	/* Set the packet to the ethernet header and ARP header */
	sr_ethernet_hdr_t *eth_header = (sr_ethernet_hdr_t *) packet;
    sr_arp_hdr_t* arp_header = ((sr_arp_hdr_t*)(packet + sizeof(sr_ethernet_hdr_t)));

    if(htons(arp_header->ar_op) == arp_op_request){
    	/* If the packet is ARP request, then the router tries to caches
    	 * the information of the sender. */
    	send_arp_packet(sr, packet, len, interface);
    }else if(htons(arp_header->ar_op) == arp_op_reply){
    	Debug("ARP reply\n");
		struct sr_if *interface_for_ip = get_interface_for_ip(sr->if_list, arp_header->ar_tip);
		if (interface_for_ip) {
			struct sr_arpreq *request = sr_arpcache_insert(&(sr->cache), arp_header->ar_sha, arp_header->ar_sip);
			if (request) {
				struct sr_packet *cur_packet = request->packets;
				while(cur_packet) {
					forward_packet(sr, cur_packet->iface, arp_header->ar_sha, cur_packet->len, cur_packet->buf);
					cur_packet = cur_packet->next;
				}
			}
		}
    }
}/* end sr_handlepacket_arp */

/*---------------------------------------------------------------------
 * Method: sr_handlepacket_ip(struct sr_instance* sr,
								uint8_t * packet,
								unsigned int len,
								char* interface)
 * Scope:  Global
 *
 * When the ethernet type is Internet Protocol
 *
 *---------------------------------------------------------------------*/
void sr_handlepacket_ip(struct sr_instance* sr,
		uint8_t * packet,
		unsigned int len,
		char* interface){
	/* REQUIRES */
	assert(sr);
	assert(packet);
	assert(interface);
	Debug("IP\n");

	sr_ip_hdr_t* ip_header = ((sr_ip_hdr_t*)(packet + sizeof(sr_ethernet_hdr_t)));
	sr_icmp_hdr_t* icmp_header =  ((sr_icmp_hdr_t*)(packet + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t)));

	/* Check Sum */
	uint16_t given_len = ip_header->ip_sum;
	ip_header->ip_sum = 0;
	if(given_len != cksum((uint8_t*)ip_header, sizeof(sr_ip_hdr_t))) {
		printf(" The Received Packet is corrupted. Checksum Failed. \n");
		return;
	}
	ip_header->ip_sum = given_len;

	struct sr_if *dest;
	if(is_for_me(&(sr->if_list), ip_header->ip_dst)){

		Debug("IP packet is for me\n");
		/* Check whether the packet is in the interfaces of the router. */

		if(ip_header->ip_p == ip_protocol_tcp || ip_header->ip_p == ip_protocol_udp){
			/* If the router receives TCP or UDP packet, then send back the
			 * ICMP error packet to the sender. */
			fprintf(stderr, " Received Unsupported %s Packet \n", ip_header->ip_p == ip_protocol_tcp ? "TCP" : "UDP");
			send_ip_error_packet(sr, packet, interface, icmp_type3, icmp_code3);
		}else{
			/* If the router receives the packet, consider the packet with the Type 0(Echo). */
			if(icmp_header->icmp_type == icmp_type0){
				send_icmp_echo(sr, interface, len, packet);
			}else{
				fprintf(stderr, " Received Unknown Type Of ICMP Packet \n");
			}
		}
	}else{
		Debug("IP is not for me\n");
		/* If the packet is not in the interfaces of the router, the router
		 * needs to find the longest prefix match interface to send the packet.*/
		if(ip_header->ip_ttl > 0){
			/* Since the packet is going through the router, TTL should be deducted. */
			ip_header->ip_ttl--;

			Debug("IP packet ttl succeed \n");
			/* Find the longest prefix match from the routing table. */
			struct sr_rt *dest;
			if((dest = sr_longest_prefix_match(sr->routing_table, ip_header)) != 0){
				struct sr_arpentry *arp_entry;
				if((arp_entry = sr_arpcache_lookup(&(sr->cache), ip_header->ip_dst)) != NULL){
					forward_packet(sr, dest->interface, arp_entry->mac, len, packet);
					free(arp_entry);
				}else{
					fprintf(stderr, "IP->MAC mapping not in ARP cache %u \n", ip_header->ip_dst);
					sr_arpcache_queuereq(&(sr->cache), ip_header->ip_dst, packet, len, dest->interface);
					fprintf(stderr, "Added Arp Req to queu \n");
				}
			}else{
				Debug("Cannot transmit the packet\n");
				send_ip_error_packet(sr, packet, interface, icmp_type3, icmp_code);
			}
		}else{
			fprintf(stderr, "Received Packet TTL(%u) Expired in Transit \n", ip_header->ip_ttl);
			send_ip_error_packet(sr, packet, interface, icmp_type11, icmp_code);
		}
	}
}/* end sr_handlepacket_ip */

/*---------------------------------------------------------------------
 * Method: sr_longest_prefix_match(struct sr_rt*, sr_ip_hdr_t*)
 * Scope:  Global
 *
 * This method is called to find the longest prefix match in the
 * routing table. It returns 0 if there is no matching even one
 * bit. Otherwise, returns the longest prefix match routing table.
 *
 *---------------------------------------------------------------------*/
struct sr_rt *sr_longest_prefix_match(struct sr_rt *rtable, sr_ip_hdr_t *ip_header){
	struct sr_rt *best = 0;
	while(rtable){
		if((ip_header->ip_dst & rtable->mask.s_addr) == (rtable->dest.s_addr & rtable->mask.s_addr)){
			if(best == 0 || rtable->mask.s_addr > best->mask.s_addr){
				best = rtable;
			}
		}
		rtable = rtable->next;
	}
	return best;
}/* end sr_longest_prefix_match */


/*---------------------------------------------------------------------
 * Method: sr_handlepacket_arp(struct sr_instance* sr,
 *      						uint8_t*  packet,
 *      						unsigned int len,
 *								char* interface)
 * Scope:  Local
 *
 * When the ethernet type is Address Resolution Protocol
 *
 *---------------------------------------------------------------------*/
void forward_packet(struct sr_instance *sr, char *interface,
					unsigned char *dest_mac, unsigned int len, uint8_t *pkt) {

	uint8_t *packet = (uint8_t *) malloc(len);
	memcpy(packet, pkt, len);
	struct sr_if *interfaces = (struct sr_if *)sr_get_interface(sr, interface);

	sr_ethernet_hdr_t *ether_hdr = (sr_ethernet_hdr_t *) packet;
	ether_hdr->ether_type = htons(ethertype_ip);
	memcpy(ether_hdr->ether_shost, interfaces->addr, ETHER_ADDR_LEN);
	memcpy(ether_hdr->ether_dhost, &(dest_mac), ETHER_ADDR_LEN);

	/* Recompute checksum. */
	sr_ip_hdr_t *ip_header = (sr_ip_hdr_t *)(packet + sizeof(sr_ethernet_hdr_t));
	ip_header->ip_sum = 0;
	ip_header->ip_sum = cksum(packet + sizeof(sr_ethernet_hdr_t), sizeof(sr_ip_hdr_t));

	sr_send_packet(sr, packet, len, interface);
	free(packet);
}

void send_icmp_echo(struct sr_instance* sr, uint8_t* packet, unsigned int len, char* interface) {

	uint8_t *_packet = (uint8_t *) malloc(len);
	memcpy(_packet, packet, len);
	struct sr_if *interfaces = (struct sr_if *)sr_get_interface(sr, interface);

	sr_ethernet_hdr_t *eth_header = (sr_ethernet_hdr_t *)_packet;
	sr_ip_hdr_t *ip_header = (sr_ip_hdr_t *)(_packet + sizeof(sr_ethernet_hdr_t));

	eth_header->ether_type = htons(ethertype_ip);
	uint8_t shost[ETHER_ADDR_LEN];
	memcpy(shost, interfaces->addr, ETHER_ADDR_LEN);
	uint8_t dhost[ETHER_ADDR_LEN];
	memcpy(dhost, eth_header->ether_shost, ETHER_ADDR_LEN);

	memcpy(eth_header->ether_shost, shost, ETHER_ADDR_LEN);
	memcpy(eth_header->ether_dhost, dhost, ETHER_ADDR_LEN);

	build_ip_header(_packet + sizeof(sr_ethernet_hdr_t), ip_header, interfaces);
	build_icmp_header(_packet + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t), packet, icmp_type0, icmp_code);

	sr_send_packet(sr, _packet, len, interface);
	free(_packet);
}

/*---------------------------------------------------------------------
 * Method: is_for_me(struct sr_if* interfaces, uint32_t* dest_ip)
 * Scope:  Global
 *
 * Check whether the given destination ip address is provided for
 * one of the interfaces of the router
 *
 *---------------------------------------------------------------------*/
int is_for_me(struct sr_if* interfaces, uint32_t* dest_ip){
	while(interfaces){
		if(&interfaces->ip == dest_ip){ return 1; }
		interfaces = interfaces->next;
	}
	return 0;
}

/*---------------------------------------------------------------------
 * Method: sr_handlepacket_arp(struct sr_instance* sr,
 *      						uint8_t*  packet,
 *      						unsigned int len,
 *								char* interface)
 * Scope:  Local
 *
 * When the ethernet type is Address Resolution Protocol
 *
 *---------------------------------------------------------------------*/
struct sr_if* get_interface_for_ip(struct sr_if* interfaces, uint32_t ip) {
 	while (interfaces) {
 		if ((memcmp(&ip, &(interfaces->ip), sizeof(ip))) == 0) {
 			return interfaces;
 		} else {
 			interfaces = interfaces->next;
 		}
 	}
  	return 0;
}
