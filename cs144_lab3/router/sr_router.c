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
#include <stdlib.h>
#include <string.h>

#include "sr_if.h"
#include "sr_rt.h"
#include "sr_router.h"
#include "sr_protocol.h"
#include "sr_arpcache.h"
#include "sr_utils.h"

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
 * by sr_vns_comm.c that means do NOT delete either.  Make a copy of the
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

	/* When the router receives a packet, it should be determined what
	 * type of the protocol is. */
	sr_ethernet_hdr_t *packet_header = (sr_ethernet_hdr_t *) packet;
	uint16_t ethernet_protocol_type = htons(packet_header->ether_type);

	if(ethernet_protocol_type == ethertype_arp){
		sr_handlepacket_arp(sr, packet, len, interface);
	}else if(ethernet_protocol_type == ethertype_ip){
		sr_handlepacket_ip(sr, packet, len, interface);
	}
}/* end sr_ForwardPacket */

int interface_exist(struct sr_if *interface_list, uint32_t addr){
	while (interface_list != NULL){
		if (interface_list->ip == addr){
			return 1;
		}
		interface_list = interface_list->next;
	}
	return 0;
}

void build_ethernet_header(uint8_t *_packet, uint8_t *addr, struct sr_if* interface, uint16_t ethertype){
	sr_ethernet_hdr_t *eth_hdr = (sr_ethernet_hdr_t *)_packet;
	memcpy(eth_hdr->ether_dhost, addr, ETHER_ADDR_LEN);
	memcpy(eth_hdr->ether_shost, interface->addr, ETHER_ADDR_LEN);
	if(ethertype == ethertype_arp){
		eth_hdr->ether_type = htons(ethertype_arp);
	}else if(ethertype == ethertype_ip){
		eth_hdr->ether_type = htons(ethertype_ip);
	}
}/* end build_ether_header */

void build_arp_header(uint8_t *_packet, sr_arp_hdr_t* arp_orig, struct sr_if* interface, uint16_t ethertype){
	sr_arp_hdr_t *arp_hdr = (sr_arp_hdr_t *)(_packet + sizeof(sr_ethernet_hdr_t));

	arp_hdr->ar_hrd = arp_orig->ar_hrd;
	arp_hdr->ar_pro = arp_orig->ar_pro;/*htons(ethertype_ip);*/
	arp_hdr->ar_hln = arp_orig->ar_hln;
	arp_hdr->ar_pln = arp_orig->ar_pln;
	arp_hdr->ar_op = htons(arp_op_reply);
	memcpy(arp_hdr->ar_sha, interface->addr, ETHER_ADDR_LEN);
	arp_hdr->ar_sip = arp_orig->ar_tip;
	memcpy(arp_hdr->ar_tha, arp_orig->ar_sha, ETHER_ADDR_LEN);
	arp_hdr->ar_tip = arp_orig->ar_sip;
}/* end build_arp_header */

void sr_handlepacket_arp(struct sr_instance* sr,
        uint8_t * packet/* lent */,
        unsigned int len,
        char* interface/* lent */){
	/* Transform the packet to the arp header by adding the size of sr_ethernet_hdr_t. */
	sr_ethernet_hdr_t *eth_hdr = (sr_ethernet_hdr_t *)packet;
	sr_arp_hdr_t *arp_hdr = (sr_arp_hdr_t *)(packet + sizeof(sr_ethernet_hdr_t));

	/* In case, the packet is the arp request packet .. */
	if (ntohs(arp_hdr->ar_op) == arp_op_request){
		/* If the router has the interface of the arp_request, the send the arp reply.
		 * Otherwise, the router drops the packet. */
		if(interface_exist(sr->if_list, arp_hdr->ar_tip)){
			/* Build an arp reply packet */
			int length = sizeof(sr_ethernet_hdr_t) + sizeof(sr_arp_hdr_t);
			uint8_t *_packet = (uint8_t *)malloc(length);

			/* Transform the packet to the ethernet header and arp header to fill the informations. */
			/*sr_ethernet_hdr_t *eth_hdr_2send = (sr_ethernet_hdr_t *)arp_packet;*/
			/*sr_arp_hdr_t *arp_hdr_2send = (sr_arp_hdr_t *)(arp_packet + sizeof(sr_ethernet_hdr_t));*/

			/* build the Ethernet and ARP header */
/*			memcpy(eth_hdr_2send->ether_dhost, arp_hdr->ar_sha, ETHER_ADDR_LEN);
//			memcpy(eth_hdr_2send->ether_shot, sr->if_list->addr, ETHER_ADDR_LEN);
//			ethernet_header->ether_type = htons(ETHERTYPE_ARP);*/
			build_ethernet_header(_packet, eth_hdr->ether_shost, sr->if_list, ethertype_arp);
			build_arp_header(_packet, arp_hdr, sr->if_list, ethertype_arp);

			/* build the ARP header */
/*			arp_hdr_2send->ar_hrd = htons(ARP_HRD_ETHER);      // Hardware length
//			arp_hdr_2send->ar_pro = arp_hdr->ar_pro;           // Protocol length
//			arp_hdr_2send->ar_hln = arp_hdr->ar_hln;           // # bytes in MAC address
//			arp_hdr_2send->ar_pln = arp_hdr->ar_pln;           // # bytes in IP address
//			arp_hdr_2send->ar_op = htons(ARP_REPLY);
//			memcpy(arp_hdr_2send->ar_sha, interface_list->addr, ETHER_ADDR_LEN);
//			arp_hdr_2send->ar_sip = arp_hdr->ar_tip;
//			memcpy(arp_hdr_2send->ar_tha, arp_hdr->ar_sha, ETHER_ADDR_LEN);
//			arp_hdr_2send->ar_tip = arp_hdr->ar_sip;*/

			sr_send_packet(sr, _packet, length, interface);
			free(_packet);
		}
	}else if (ntohs(arp_hdr->ar_op) == arp_op_reply){
		/* In case, the packet is the arp reply packet .. */
		struct sr_arpreq *arp_packet = sr_arpcache_insert(&sr->cache, arp_hdr->ar_sha, arp_hdr->ar_sip);
		if(arp_packet == NULL){ return; }

		struct sr_packet *packets = arp_packet->packets;
		sr_ethernet_hdr_t *eth_hdr_2send;
		while (packets != NULL) {
			eth_hdr_2send = (sr_ethernet_hdr_t *)(packets->buf);
			memcpy(eth_hdr_2send->ether_dhost, arp_hdr->ar_sha, ETHER_ADDR_LEN);
			sr_send_packet(sr, packets->buf, packets->len, packets->iface);
			packets = packets->next;
		}
		sr_arpreq_destroy(&sr->cache, arp_packet);
	}
}

void sr_handlepacket_ip(struct sr_instance* sr,
        uint8_t * packet/* lent */,
        unsigned int len,
        char* interface/* lent */){

	/*sr_ethernet_hdr_t* eth_hdr = (sr_ethernet_hdr_t *)packet;*/
	sr_ip_hdr_t* ip_hdr = (sr_ip_hdr_t*)(packet + sizeof(sr_ethernet_hdr_t));
	/*sr_icmp_hdr_t* icmp_hdr =  ((sr_icmp_hdr_t*)(packet + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t)));*/

	/* Check Sum */
	uint16_t given_len = ip_hdr->ip_sum;
	ip_hdr->ip_sum = 0;
	if(given_len != cksum((uint8_t*)ip_hdr, sizeof(sr_ip_hdr_t))) {
		fprintf(stderr, " The Received Packet is corrupted. Checksum Failed. \n");
		return;
	}
	ip_hdr->ip_sum = given_len;
	/* end of Check Sum*/

/*	int sanity_check = sanity_check_ip(ip_packet,len);
//	uint8_t * ethernet_data = (uint8_t *) (ip_packet + sizeof(sr_ethernet_hdr_t));
//	sr_ip_hdr_t * ip_header = (sr_ip_hdr_t *)(ip_packet + sizeof(sr_ethernet_hdr_t));
//	if (sanity_check == -1) return; //makes sure ip format is correct
//	if (sanity_check == -2) //TTL <=1, we need to send ICMP message
//	{
//		ip_header->ip_ttl--;
//		sr_send_icmp_message(sr, ethernet_data, IPPROTO_ICMP_TIME_EXCEEDED, IPPROTO_ICMP_DEFAULT_CODE);
//		return;
//	}*/

	if(interface_exist(sr->if_list, ip_hdr->ip_dst)){
		/* If the router finds any matches of the destination to one of our
		 * interfaces.. */
		if(ip_hdr->ip_p == IPPROTO_TCP || ip_hdr->ip_p == IPPROTO_UDP){
			/* If the router receives any packet of TCP or UDP, then re-send a
			 * packet of destination unreachable back. */
			sr_send_icmp_message(sr, packet, icmp_type3, icmp_code3);
		}else if (ip_hdr->ip_p == IPPROTO_ICMP){
			/* If the received packet is ICMP type, then firstly do checksum
			 * for icmp header and send a packet echo reply in case of the
			 * received packet is echo request. */
			sr_icmp_hdr_t * icmp_hdr = (sr_icmp_hdr_t *)(packet + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t));

			/* Check Sum */
			uint16_t given_len = icmp_hdr->icmp_sum;
			icmp_hdr->icmp_sum = 0;
			if (given_len != cksum(icmp_hdr, len - sizeof(sr_ip_hdr_t))){
				fprintf(stderr, " The Received Packet is corrupted. Checksum Failed. \n");
				return;
			}
			icmp_hdr->icmp_sum = given_len;
			/* end of Check Sum */

			if (icmp_hdr->icmp_type == icmp_type8){
			    uint8_t *eth_data = (uint8_t *) (packet + sizeof(sr_ethernet_hdr_t));
			    sr_send_icmp_message(sr, eth_data, icmp_type0, icmp_code0);
				return;
			}
		}
	}else{
		/* Longest Prefix Matching */
		struct sr_rt *matching_ip = sr_longest_prefix_match(sr->routing_table, ip_hdr);
		if (matching_ip == NULL){
			/* If the router cannot find the longest prefix matching ip, then
			 * re-send a packet of ICMP destination unreachable.*/
		    uint8_t *eth_data = (uint8_t *)(packet + sizeof(sr_ethernet_hdr_t));
		    sr_send_icmp_message(sr, eth_data, icmp_type3, icmp_code3);
			return;
		}
		/* end of Longest Prefix Matching*/

		ip_hdr->ip_ttl--;
		uint8_t * _packet = malloc(len);
		sr_ethernet_hdr_t *eth_header = (sr_ethernet_hdr_t *)_packet;

		struct sr_if *router_interface = sr_get_interface(sr, matching_ip->interface);
		if (router_interface == NULL){ return; }

		memcpy(eth_header->ether_shost, router_interface->addr, ETHER_ADDR_LEN);
		eth_header->ether_type = htons(ethertype_ip);
		memcpy(_packet + sizeof(sr_ethernet_hdr_t), ip_hdr, (len - sizeof(sr_ethernet_hdr_t)));

		struct sr_arpentry * arp_entry = sr_arpcache_lookup(&sr->cache, matching_ip->gw.s_addr);

		if (arp_entry == NULL){
			/*struct sr_arpreq  *new_arp_request = sr_arpcache_queuereq(&sr->cache, matching_ip->gw.s_addr, _packet, len, matching_ip->interface);*/
			/*handle_arpreq(sr, new_arp_request);*/
		}else{
			memcpy(eth_header->ether_dhost,arp_entry->mac,ETHER_ADDR_LEN);

			/* Set Check Sum */
			ip_hdr->ip_sum = 0;
			ip_hdr->ip_sum = cksum(ip_hdr, sizeof(sr_ip_hdr_t));

			sr_send_packet(sr, _packet, len, matching_ip->interface);

		}
		free(_packet);
	}
}

struct sr_rt *sr_longest_prefix_match(struct sr_rt *rtable, sr_ip_hdr_t *ip_hdr){
	struct sr_rt *best = 0;
	struct sr_rt *cur = rtable;
	while(cur){
		if((ip_hdr->ip_dst & cur->mask.s_addr) == (cur->dest.s_addr & cur->mask.s_addr)){
			if(best == 0 || cur->mask.s_addr > best->mask.s_addr){
				best = cur;
			}
		}
		cur = cur->next;
	}
	return best;
}/* end sr_longest_prefix_match */

void build_ip_header(uint8_t *_packet, sr_ip_hdr_t *ip_hdr, uint32_t length, uint32_t dest,
		struct sr_if *interface, uint8_t icmp_type, uint8_t icmp_code){
	sr_ip_hdr_t *ip_hdr_2send = (sr_ip_hdr_t *)(_packet + sizeof(sr_ethernet_hdr_t));
	ip_hdr_2send->ip_hl = ip_hdr->ip_hl;
	ip_hdr_2send->ip_v = ip_hdr->ip_v;
	ip_hdr_2send->ip_tos = ip_hdr->ip_tos;
	ip_hdr_2send->ip_len = htons(length - sizeof(sr_ethernet_hdr_t));
	ip_hdr_2send->ip_id = 0;
	ip_hdr_2send->ip_off = htons (IP_DF | 0);
	ip_hdr_2send->ip_ttl = IP_PACKET_TTL;
	ip_hdr_2send->ip_p = ip_protocol_icmp;
	ip_hdr_2send->ip_dst = dest;
	if (icmp_type == icmp_type0 || (icmp_code == icmp_code3 && icmp_type == icmp_type3)){
		ip_hdr_2send->ip_src = ip_hdr->ip_dst;
	}else{
		ip_hdr_2send->ip_src = interface->ip;
	}
	ip_hdr_2send->ip_sum = 0;
	ip_hdr_2send->ip_sum = cksum(ip_hdr_2send, sizeof(sr_ip_hdr_t));
}

void sr_send_icmp_message(struct sr_instance *sr, uint8_t *packet, uint16_t icmp_type, uint16_t icmp_code) {
	int length;

	/*sr_ethernet_hdr_t *eth_hdr = (sr_ethernet_hdr_t *)packet;*/
	sr_ip_hdr_t *ip_hdr = (sr_ip_hdr_t *)(packet + sizeof(sr_ethernet_hdr_t));
	/*sr_icmp_hdr_t *icmp_hdr = (sr_ip_hdr_t *)(packet + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t));*/

	if (icmp_type == icmp_type0){
		length = sizeof(sr_ethernet_hdr_t) + ntohs(ip_hdr->ip_len);
	}else if (icmp_type == icmp_type3 || icmp_type == icmp_type11){
		length = sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t) + sizeof(sr_icmp_t3_hdr_t);
	}

	/*//Obtain information from the next hop*/
	uint32_t *newDest = ip_hdr->ip_src;
	/* Longest Prefix Match */
	struct sr_rt *matching_ip = sr_longest_prefix_match(sr->routing_table, ip_hdr);
	if (matching_ip == NULL){
		/* If the router cannot find the longest prefix matching ip, then
		 * re-send a packet of ICMP destination unreachable.*/
		uint8_t *eth_data = (uint8_t *) (packet + sizeof(sr_ethernet_hdr_t));
		sr_send_icmp_message(sr, eth_data, icmp_type3, icmp_code3);
		return;
	}
	/* end of Longest Prefix Matching*/

	/* Find the destination port to send the packet along the longest prefix
	 * matching ip */
	struct sr_if *interface = sr_get_interface(sr, matching_ip->interface);
	uint8_t *_packet = (uint8_t *)malloc(length);

	/* build the Ethernet header */
	/*sr_ethernet_hdr_t *eth_hdr_2send = (sr_ethernet_hdr_t *)_packet;*/
	/*sr_ip_hdr_t *ip_hdr_2send = (sr_ip_hdr_t *)(_packet + sizeof(sr_ethernet_hdr_t));*/

	struct sr_arpentry *arp_entry = sr_arpcache_lookup(&sr->cache, matching_ip->gw.s_addr);
	if(arp_entry == NULL){
		build_ethernet_header(_packet, '\0', interface, ethertype_ip);
	}
	build_ethernet_header(_packet, arp_entry->mac, interface, ethertype_ip);

	/* build the IP header */
	build_ip_header(_packet, ip_hdr, length, ip_hdr->ip_src, interface, icmp_type, icmp_code);

	/* build ICMP header regarding to the type of ICMP */
	if(icmp_type == icmp_type0){
		sr_icmp_hdr_t *icmp_hdr_2send = (sr_icmp_hdr_t *)(_packet + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t));
		icmp_hdr_2send->icmp_type = icmp_type;
		icmp_hdr_2send->icmp_code = icmp_code;
		memcpy((uint8_t *)icmp_hdr_2send + sizeof(sr_icmp_hdr_t), (uint8_t *)ip_hdr + sizeof(sr_ip_hdr_t) + sizeof(sr_icmp_hdr_t), length - sizeof(sr_ethernet_hdr_t) - sizeof(sr_ip_hdr_t) - sizeof(sr_icmp_hdr_t));
		icmp_hdr_2send->icmp_sum = 0;
		icmp_hdr_2send->icmp_sum = cksum(icmp_hdr_2send, length - sizeof(sr_ethernet_hdr_t) - sizeof(sr_ip_hdr_t));
	}else if(icmp_type == icmp_type3 || icmp_type == icmp_type11){
		sr_icmp_t3_hdr_t *icmp_t3_hdr = (sr_icmp_t3_hdr_t *)(_packet + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t));
		icmp_t3_hdr->icmp_type = icmp_type;
		icmp_t3_hdr->icmp_code = icmp_code;
		icmp_t3_hdr->icmp_sum = 0;
		icmp_t3_hdr->unused = 0;
		icmp_t3_hdr->next_mtu = 0;
		memcpy(icmp_t3_hdr->data, ip_hdr, ICMP_DATA_SIZE);
		icmp_t3_hdr->icmp_sum = cksum(icmp_t3_hdr, sizeof(sr_icmp_t3_hdr_t));
	}

	if (arp_entry){
		sr_send_packet (sr, _packet, length, matching_ip->interface);
	}else{
		/*struct sr_arpreq *arpRequest = sr_arpcache_queuereq (&sr->cache, matching_ip->gw.s_addr, _packet, length, matching_ip->interface);
		handle_arpreq(sr, arpRequest);*/
	}
	free(_packet);
}
