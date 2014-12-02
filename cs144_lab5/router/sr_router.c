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
#include "sr_nat.h"


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
    if(sr->nat_active){
    	sr_nat_init(sr->nat);
    }
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
	    if(sr->nat_active){
	    	/* Set the IN&OUT BOUND ip port address */
	    	/*struct sr_if *in_iface = sr_get_interface(sr, INBOUND);*/
	    	sr->nat->internal_ip = sr_get_interface(sr, INBOUND)->ip;
	    	/*struct sr_if *out_iface = sr_get_interface(sr, OUTBOUND);*/
	    	sr->nat->external_ip = sr_get_interface(sr, OUTBOUND)->ip;
	    }
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
	if(addr != NULL){
		memcpy(eth_hdr->ether_dhost, addr, ETHER_ADDR_LEN);
	}else{
	    memset(eth_hdr->ether_dhost, 255, ETHER_ADDR_LEN);
	}
	memcpy(eth_hdr->ether_shost, interface->addr, ETHER_ADDR_LEN);
	if(ethertype == ethertype_arp){
		eth_hdr->ether_type = htons(ethertype_arp);
	}else if(ethertype == ethertype_ip){
		eth_hdr->ether_type = htons(ethertype_ip);
	}
}/* end build_ether_header */

void build_arp_header(uint8_t *_packet, sr_arp_hdr_t* arp_orig, struct sr_if* interface, uint16_t ethertype){
	sr_arp_hdr_t *arp_hdr = (sr_arp_hdr_t *)(_packet + sizeof(sr_ethernet_hdr_t));
	if(ethertype == arp_op_reply){
		arp_hdr->ar_hrd = arp_orig->ar_hrd;
		arp_hdr->ar_pro = arp_orig->ar_pro;
		arp_hdr->ar_hln = arp_orig->ar_hln;
		arp_hdr->ar_pln = arp_orig->ar_pln;
		arp_hdr->ar_op = htons(ethertype);
		memcpy(arp_hdr->ar_sha, interface->addr, ETHER_ADDR_LEN);
		arp_hdr->ar_sip = arp_orig->ar_tip;
		memcpy(arp_hdr->ar_tha, arp_orig->ar_sha, ETHER_ADDR_LEN);
		arp_hdr->ar_tip = arp_orig->ar_sip;
	}else if(ethertype == arp_op_request){
		arp_hdr->ar_hrd = htons(0x0001);
		arp_hdr->ar_pro = htons(0x0800);
		arp_hdr->ar_hln = ETHER_ADDR_LEN;
		arp_hdr->ar_pln = sizeof(uint32_t);
		arp_hdr->ar_op = htons(ethertype);
		memcpy(arp_hdr->ar_sha, interface->addr, ETHER_ADDR_LEN);
		arp_hdr->ar_sip = interface->ip;
		memset(arp_hdr->ar_tha, 255, ETHER_ADDR_LEN);
	}
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
			sr_ethernet_hdr_t *eth_hdr_2send = (sr_ethernet_hdr_t *)_packet;
			sr_arp_hdr_t *arp_hdr_2send = (sr_arp_hdr_t *)(_packet + sizeof(sr_ethernet_hdr_t));

			struct sr_if *iface = sr_get_interface(sr, interface);

			/* build the Ethernet and ARP header */
			memcpy(eth_hdr_2send->ether_dhost, eth_hdr->ether_shost, sizeof(uint8_t) * ETHER_ADDR_LEN);
			memcpy(eth_hdr_2send->ether_shost, iface->addr, sizeof(uint8_t) * ETHER_ADDR_LEN);
			eth_hdr_2send->ether_type = htons(ethertype_arp);

			arp_hdr_2send->ar_hrd = htons(arp_hrd_ethernet);
			arp_hdr_2send->ar_pro = htons(ethertype_ip);
			arp_hdr_2send->ar_hln = ETHER_ADDR_LEN;
			arp_hdr_2send->ar_pln = 4;
			arp_hdr_2send->ar_op = htons(arp_op_reply);
			memcpy(arp_hdr_2send->ar_sha, iface->addr, ETHER_ADDR_LEN);
			arp_hdr_2send->ar_sip = iface->ip;
			memcpy(arp_hdr_2send->ar_tha, arp_hdr->ar_sha, ETHER_ADDR_LEN);
			arp_hdr_2send->ar_tip = arp_hdr->ar_sip;

			sr_send_packet(sr, _packet, length, interface);
			free(_packet);

		}

	}else if (ntohs(arp_hdr->ar_op) == arp_op_reply){
		/* In case, the packet is the arp reply packet .. */
		sr_arp_hdr_t *arp_header_in = (sr_arp_hdr_t*) (packet + sizeof(sr_ethernet_hdr_t));

		uint32_t ip = arp_header_in->ar_sip;
		unsigned char mac[ETHER_ADDR_LEN];

		memcpy(mac, arp_header_in->ar_sha, ETHER_ADDR_LEN);

		struct sr_arpreq* req = sr_arpcache_insert(&(sr->cache), mac, ip);

		if(req){
			struct sr_packet* pack = req->packets;
			while(pack){
				sr_ethernet_hdr_t *packet_eth_header = (sr_ethernet_hdr_t*) pack->buf;
				memcpy(packet_eth_header->ether_dhost, mac, ETHER_ADDR_LEN);

				sr_send_packet(sr, pack->buf, pack->len, pack->iface);

				pack = pack->next;
			}
			sr_arpreq_destroy(&(sr->cache), req);
		}
	}
}

void sr_nat_handle_icmp(struct sr_instance* sr,
    uint8_t * packet/* lent */,
    unsigned int len,
    char* interface/* lent */){

	sr_ip_hdr_t *ip_hdr = (sr_ip_hdr_t *)(packet + sizeof(sr_ethernet_hdr_t));
	sr_icmp_t3_hdr_t *icmp_t3_hdr = (sr_icmp_t3_hdr_t *)(packet + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t));
	sr_icmp_hdr_t* icmp_hdr = (sr_icmp_hdr_t*)(packet + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t));
	uint16_t* id = (uint16_t*)(packet+sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t) + sizeof(sr_icmp_hdr_t));

	struct sr_nat_mapping *mappings ;

	struct sr_rt *matching_ip = sr_longest_prefix_match(sr->routing_table, ip_hdr->ip_dst);

	if (strcmp(matching_ip->interface, OUTBOUND) == 0){
		/* If the packet is for outbound packet .. */

		mappings = sr_nat_lookup_internal(sr->nat, ip_hdr->ip_src, icmp_t3_hdr->unused, nat_mapping_icmp);
		print_nat_mappings(sr->nat);
		if(mappings == NULL){
			mappings = sr_nat_insert_mapping(sr->nat, ip_hdr->ip_src, icmp_t3_hdr->unused, nat_mapping_icmp);
			sr->nat->mappings = mappings;
		}

		/* Find the interface of the external port */
		struct sr_if *ext_iface = sr_get_interface(sr, OUTBOUND);

		/* Set the source ip address of the received packet as its external interface ip address. */
		ip_hdr->ip_src = ext_iface->ip;

		/* Recalculate the Check Sum */
		ip_hdr->ip_sum = 0;
		icmp_hdr->icmp_sum = 0;

		ip_hdr->ip_sum = cksum(ip_hdr, sizeof(sr_ip_hdr_t));
		icmp_hdr->icmp_sum = cksum(icmp_hdr, len - sizeof(sr_ethernet_hdr_t) - sizeof(sr_ip_hdr_t));
		/* end of setting the Check Sum */
	}else if(strcmp(matching_ip->interface, INBOUND) == 0){
		/* If the packet is for inbound packet .. */
		printf("It works for inbound\n");
		mappings = sr_nat_lookup_external(sr->nat, 0, nat_mapping_icmp);
		if(mappings == NULL){
			return;
		}

		memset(((sr_ethernet_hdr_t *)packet)->ether_dhost, 0, ETHER_ADDR_LEN);
		ip_hdr->ip_dst = mappings->ip_int;
		*id = mappings->aux_int;

		ip_hdr->ip_sum = 0;
		ip_hdr->ip_sum = cksum(ip_hdr, sizeof(sr_ip_hdr_t));
		icmp_hdr->icmp_sum = 0;
		icmp_hdr->icmp_sum = cksum(icmp_hdr, len - sizeof(sr_ethernet_hdr_t) - sizeof(sr_ip_hdr_t));
	}
}

void sr_nat_handle_tcp(struct sr_instance* sr,
    uint8_t * packet/* lent */,
    unsigned int len,
    char* interface/* lent */,
	struct sr_rt *matching_ip){

}

void sr_handlepacket_ip(struct sr_instance* sr,
        uint8_t * packet/* lent */,
        unsigned int len,
        char* interface/* lent */){
	sr_ip_hdr_t *ip_hdr = (sr_ip_hdr_t*) (packet + sizeof(sr_ethernet_hdr_t));

	struct sr_if* iface = sr_get_interface(sr, interface);

	/* Sanity Check */
	if (len < sizeof(sr_ethernet_hdr_t) || len > 1514){
		return;
	}
	/* end of Sanity Check */

	/* TTL Check*/
	if(ip_hdr->ip_ttl < 1){
		/* TTL timeout */
		sr_send_icmp_message(sr, packet, icmp_type11, icmp_code0);
		return;
	}
	/* end of TTL Check */

	if(sr->nat_active){
		/* Since NAT is on active, figure out what the external and internal IP and port */
		/* Firstly, we need to check whether the destination is outbound or not */
		struct sr_rt *matching_ip = sr_longest_prefix_match(sr->routing_table, ip_hdr->ip_dst);

		if(ip_hdr->ip_p == ip_protocol_icmp){
			sr_nat_handle_icmp(sr, packet, len, interface);
		}else if(ip_hdr->ip_p == ip_protocol_tcp){
			sr_nat_handle_tcp(sr, packet, len, interface, matching_ip);
		}
	}

	sr_icmp_hdr_t *icmp_hdr;
	if (ip_hdr->ip_dst == iface->ip) {
		/* the packet is for me */
		if (ip_hdr->ip_p == ip_protocol_icmp){
			/* ICMP */
			icmp_hdr = (sr_icmp_hdr_t*) (packet + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t));
			if (icmp_hdr->icmp_type == icmp_type8 && icmp_hdr->icmp_code == icmp_code0) {
				sr_send_icmp_message(sr, packet, icmp_type0, icmp_code0);
			}
		}else if(ip_hdr->ip_p == ip_protocol_tcp){
			/* TCP */
			sr_tcp_hdr_t *tcp_hdr = (sr_tcp_hdr_t *)(packet + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t));

			/* TCP header Check Sum*/
			uint16_t orig_cs_val = tcp_hdr->checksum;
			tcp_hdr->checksum = 0;
			cksum(packet, ntohs(ip_hdr->ip_len) - sizeof(sr_ip_hdr_t) + sizeof(sr_tcp_pseudo_hdr_t));
			tcp_hdr->checksum = orig_cs_val;
			/* end of TCP header Check Sum */

		}else{
			/* UDP : ICMP port unreachable and ICMP destination unreachable */
			sr_send_icmp_message(sr, packet, icmp_type3, icmp_code3);
		}
	}else{
		/* the packet is not for me */

		/* firstly, find the longest prefix match from the routing table */
		struct sr_rt *matching_ip = sr_longest_prefix_match(sr->routing_table, ip_hdr->ip_dst);

		if(matching_ip == NULL){
			/* any matching prefix is found, then send a packet back :
			 * ICMP port unreachable and ICMP echo reply */
			sr_send_icmp_message(sr, packet, icmp_type3, icmp_type0);
			return;
		}

		struct sr_if *best_iface = sr_get_interface(sr, matching_ip->interface);

		sr_ethernet_hdr_t *eth_hdr = (sr_ethernet_hdr_t*) packet;
		memcpy(eth_hdr->ether_shost, best_iface->addr, ETHER_ADDR_LEN);

		/* Decrement TTL and recalculate the check sum */
		ip_hdr->ip_ttl--;
		ip_hdr->ip_sum = 0;
		ip_hdr->ip_sum = cksum(packet + sizeof(sr_ethernet_hdr_t), sizeof(sr_ip_hdr_t));

		struct sr_arpentry *cached_entry;
		if((cached_entry = sr_arpcache_lookup(&(sr->cache), ip_hdr->ip_dst))){
			memcpy(eth_hdr->ether_dhost, cached_entry->mac, ETHER_ADDR_LEN);
			memcpy(eth_hdr->ether_shost, best_iface->addr, ETHER_ADDR_LEN);
			sr_send_packet(sr, packet, len, matching_ip->interface);
		} else {
			sr_arpcache_queuereq(&(sr->cache), 	matching_ip->gw.s_addr, packet, len, matching_ip->interface);
		}
		free(cached_entry);

	}
}

struct sr_rt *sr_longest_prefix_match(struct sr_rt *rtable, uint32_t ip_dest){
	struct sr_rt *best = NULL;
	struct sr_rt *cur = rtable;
	while(cur != NULL){
		if((ip_dest & cur->mask.s_addr) == (cur->dest.s_addr & cur->mask.s_addr)){
			if(best == NULL || cur->mask.s_addr > best->mask.s_addr){
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
	ip_hdr_2send->ip_ttl = INIT_TTL;
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
	sr_ip_hdr_t *ip_hdr = (sr_ip_hdr_t *)(packet + sizeof(sr_ethernet_hdr_t));

	if (icmp_type == icmp_type0){
		length = sizeof(sr_ethernet_hdr_t) + ntohs(ip_hdr->ip_len);
	}else if (icmp_type == icmp_type3 || icmp_type == icmp_type11){
		length = sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t) + sizeof(sr_icmp_t3_hdr_t);
	}

	/* Longest Prefix Match */
	struct sr_rt *matching_ip = sr_longest_prefix_match(sr->routing_table, ip_hdr->ip_src);
	if (matching_ip == NULL){
		/* If the router cannot find the longest prefix matching ip, then
		 * re-send a packet of ICMP destination unreachable.*/
		return;
	}
	/* end of Longest Prefix Matching*/

	/* Find the destination port to send the packet along the longest prefix
	 * matching ip */
	struct sr_if *interface = sr_get_interface(sr, matching_ip->interface);
	uint8_t *_packet = (uint8_t *)malloc(length);

	/* build the Ethernet header */
	struct sr_arpentry *arp_entry = sr_arpcache_lookup(&sr->cache, matching_ip->gw.s_addr);
	if(arp_entry == NULL){
		build_ethernet_header(_packet, NULL, interface, ethertype_ip);
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
		sr_arpcache_handle(sr, sr_arpcache_queuereq(&sr->cache, matching_ip->gw.s_addr, _packet, length, matching_ip->interface));
	}
	free(arp_entry);
	free(_packet);
}


void sr_arpcache_handle(struct sr_instance *sr, struct sr_arpreq *req) {
    time_t cur_time = time(NULL);
    struct sr_packet *packets;

    if (difftime(cur_time, req->sent) > 1.0) {
        if (req->times_sent >= 5) {
            packets = req->packets;
            while (packets){
                sr_send_icmp_message(sr, packets->buf, icmp_type3, icmp_code1);
                packets = packets->next;
            }
            sr_arpreq_destroy(&sr->cache, req);
        }else{

            int len = sizeof(sr_ethernet_hdr_t) + sizeof(sr_arp_hdr_t);
			uint8_t *_packet = (uint8_t *)malloc(len);
			struct sr_if *interface = sr_get_interface(sr, req->packets->iface);

			/* Build the Ethernet and ARP header
			 * Note : This case ARP header is constructed as ARP request. */
			build_ethernet_header(_packet, NULL, interface, ethertype_arp);
			build_arp_header(_packet, (sr_arp_hdr_t *)(_packet + sizeof(sr_ethernet_hdr_t)), interface, arp_op_request);
			sr_arp_hdr_t *arp_hdr = (sr_arp_hdr_t *)(_packet + sizeof(sr_ethernet_hdr_t));
			arp_hdr->ar_tip = req->ip;

			sr_send_packet(sr, _packet, len, req->packets->iface);

			/* Renew the cached ARP packets */
			req->sent = cur_time;
            req->times_sent++;

            free(_packet);

        }
    }
}

