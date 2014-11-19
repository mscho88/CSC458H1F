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

int interface_exist(struct sr_if *interface_list, sr_arp_hdr_t *arp_hdr){
	while (interface_list != NULL){
		if (interface_list->ip == arp_hdr->ar_tip){
			return 1;
		}
		interface_list = interface_list->next;
	}
	return 0;
}

void build_ether_header(uint8_t *_packet, uint8_t *addr, struct sr_if* interface, uint16_t ethertype){
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
	sr_arp_hdr_t *arp_hdr = (sr_arp_hdr_t *)_packet;

	arp_hdr->ar_hrd = arp_orig->ar_hrd;
	arp_hdr->ar_pro = arp_orig->ar_pro;//htons(ethertype_ip);
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
	if (ntohs(arp_hdr->ar_op) == ARP_REQUEST){
		/* If the router has the interface of the arp_request, the send the arp reply.
		 * Otherwise, the router drops the packet. */
		if(interface_exist(sr->if_list, arp_hdr)){
			/* Build an arp reply packet */
			int length = sizeof(sr_ethernet_hdr_t) + sizeof(sr_arp_hdr_t);
			uint8_t *arp_packet = (uint8_t *)malloc(length);

			/* Transform the packet to the ethernet header and arp header to fill the informations. */
			sr_ethernet_hdr_t *eth_hdr_2send = (sr_ethernet_hdr_t *)arp_packet;
			sr_arp_hdr_t *arp_hdr_2send = (sr_arp_hdr_t *)(arp_packet + sizeof(sr_ethernet_hdr_t));

			/* build the Ethernet header */
/*			memcpy(eth_hdr_2send->ether_dhost, arp_hdr->ar_sha, ETHER_ADDR_LEN);
//			memcpy(eth_hdr_2send->ether_shot, sr->if_list->addr, ETHER_ADDR_LEN);
//			ethernet_header->ether_type = htons(ETHERTYPE_ARP);*/
			build_ethernet_header(arp_packet, eth_hdr->ether_shost, sr->if_list, ethertype_arp);
			build_arp_header(arp_packet, arp_hdr, sr->if_list, ethertype_arp);

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

			sr_send_packet(sr, arp_packet, length, interface);
			free(arp_packet);
		}
	}else if (ntohs(arp_hdr->ar_op) == ARP_REPLY){
		/* In case, the packet is the arp reply packet .. */
		struct sr_arpreq *arp_packet;
		if(arp_packet = sr_arpcache_insert(&sr->cache, arp_hdr->ar_sha, arp_hdr->ar_sip) != NULL){
			struct sr_packet *packets = arp_packet->packets;
			while (packets != NULL) {
				sr_ethernet_hdr_t *eth_hdr_2send = (sr_ethernet_hdr_t *)(packets->buf);
				memcpy(eth_hdr_2send->ether_dhost, arp_hdr->ar_sha, ETHER_ADDR_LEN);
				sr_send_packet(sr, packets->buf, packets->len, packets->iface);
				packets = packets->next;
			}
			sr_arpreq_destroy(&sr->cache, arp_packet);
		}
	}
}

void sr_handlepacket_ip(struct sr_instance* sr,
        uint8_t * packet/* lent */,
        unsigned int len,
        char* interface/* lent */){
}

