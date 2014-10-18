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

#define IPv4_MIN_LEN 20
#define ICMP_MIN_LEN 8

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

  /* When the router receives any packet, it should be determined what
   * type of the protocol is. After that, it is required to figure out
   * where to send the packet by comparing the address in the routing
   * table. It may drop the packet if there exists no address to send.
   */
  sr_ethernet_hdr_t *packet_header = (sr_ethernet_hdr_t *) packet;

  uint16_t ethernet_protocol_type = htons(packet_header->ether_type);

  if(ethernet_protocol_type == ethertype_arp){
  	  Debug("*** -> Received Address Resolution Protocol \n");
  	  sr_handlepacket_arp(sr, packet, len, interface);
  }else if(ethernet_protocol_type == ethertype_ip){
	  Debug("*** -> Received Internet Protocol \n");
	  sr_handlepacket_ip(sr, packet, len, interface);
  }else{
	  Debug("*** -> Received unknown packet of length %d \n", len);
  }
}/* end sr_handlepacket */

/*---------------------------------------------------------------------
 * Method: sr_handlepacket(uint8_t* p,char* interface)
 * Scope:  Global
 *
 * This method is called when the ethernet type is Address Resolution
 * Protocol.
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

	/* Set the packet to the ARP header */
	sr_ethernet_hdr_t *eth_header = (sr_ethernet_hdr_t *) packet;
    sr_arp_hdr_t* arp_orig_header = ((sr_arp_hdr_t*)(packet + sizeof(sr_ethernet_hdr_t)));

    if(htons(arp_orig_header->ar_op) == arp_op_request){
    	/* If the packet is ARP request, then the router tries to caches
    	 * the information of the sender. */
    	struct sr_arpentry *arp_entry;
    	if((arp_entry = sr_arpcache_lookup(&(sr->cache), arp_orig_header->ar_sip)) == NULL){
    		/* If ARP cache is saved, the router sends back the message
    		 * to the sender. */
    		struct sr_arpreq *arp_cache;
    		if((arp_cache = sr_arpcache_insert(&(sr->cache), arp_orig_header->ar_sha, arp_orig_header->ar_sip)) == NULL){
    			/* Send ARP reply message */
        		send_packet(sr, packet, interface, htons(eth_header->ether_type), 0);
    		}else{
    			Debug("Error on caching the sender information. \n");
    		}
    	}else{
    		/* Send ARP reply message */
    		send_packet(sr, packet, interface, htons(eth_header->ether_type), 0);
    	}
    }else if(htons(arp_orig_header->ar_op) == arp_op_reply){
    	/* If the packet is ARP reply, then the router ....*/
    	Debug("*** -> Address Resolution Protocol reply \n");
    }
}/* end sr_handlepacket_arp */

/*---------------------------------------------------------------------
 * Method: send_packet(struct sr_instance* sr, uint8_t* packet, char* interface)
 * Scope:  Global
 *
 * This method is called when the router needs to send a packet.
 *
 *---------------------------------------------------------------------*/
void send_packet(struct sr_instance* sr, uint8_t* packet, char* interface, uint16_t protocol, int type){
	unsigned int length;

	sr_ethernet_hdr_t* eth_header = (sr_ethernet_hdr_t *)packet;
	if(protocol == ethertype_arp){
		sr_arp_hdr_t* arp_header = ((sr_arp_hdr_t*)(packet + sizeof(sr_ethernet_hdr_t)));

		length = sizeof(sr_ethernet_hdr_t) + sizeof(sr_arp_hdr_t);

		struct sr_if *interfaces = sr_get_interface(sr, interface);

		uint8_t* _packet = (uint8_t*)malloc(length);

		build_ether_header(_packet, eth_header, interfaces);
		build_arp_header(_packet + sizeof(sr_ethernet_hdr_t), arp_header, interfaces);

		sr_send_packet(sr, (uint8_t*)_packet, length, interfaces->name);
		free(_packet);
	}else if(protocol == ethertype_ip){
		sr_ip_hdr_t* ip_header = ((sr_ip_hdr_t*)(packet + sizeof(sr_ethernet_hdr_t)));
		sr_icmp_hdr_t* icmp_header =  ((sr_icmp_hdr_t*)(packet + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t)));

		length = sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t) + sizeof(sr_icmp_hdr_t);

		struct sr_if *interfaces = sr_get_interface(sr, interface);

		uint8_t* _packet = (uint8_t*)malloc(length);

		build_ether_header(_packet, eth_header, interfaces);
		build_ip_header(_packet + sizeof(sr_ethernet_hdr_t), ip_header, interfaces);
		build_icmp_header(_packet + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t), icmp_header, interfaces);

		print_hdr_ip(_packet + sizeof(sr_ethernet_hdr_t));
		print_hdr_icmp(_packet + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t));
		sr_send_packet(sr, (uint8_t*)_packet, length, interfaces->name);
		free(_packet);
	}
}

/*---------------------------------------------------------------------
 * Method: build_ether_header(uint8_t *_packet, sr_ethernet_hdr_t* eth_orig_header, struct sr_if* if_walker)
 * Scope:  Global
 *
 * This method is called when the ethernet type is Internet Protocol.
 *
 *---------------------------------------------------------------------*/
void build_ether_header(uint8_t *_packet, sr_ethernet_hdr_t* eth_orig_header, struct sr_if* if_walker){
	sr_ethernet_hdr_t *eth_tmp_header = (sr_ethernet_hdr_t *)_packet;
	memcpy(eth_tmp_header->ether_dhost, eth_orig_header->ether_shost, ETHER_ADDR_LEN);
	memcpy(eth_tmp_header->ether_shost, if_walker->addr, ETHER_ADDR_LEN);
	eth_tmp_header->ether_type = htons(ethertype_arp);
}
/*---------------------------------------------------------------------
 * Method: sr_handlepacket(uint8_t* p,char* interface)
 * Scope:  Global
 *
 * This method is called when the ethernet type is Internet Protocol.
 *
 *---------------------------------------------------------------------*/
void build_arp_header(uint8_t *_packet, sr_arp_hdr_t* arp_orig_header, struct sr_if* if_walker){
	sr_arp_hdr_t *arp_tmp_header = (sr_arp_hdr_t *)_packet;
	arp_tmp_header->ar_hrd = arp_orig_header->ar_hrd;
	arp_tmp_header->ar_pro = htons(ethertype_ip);
	arp_tmp_header->ar_hln = ETHER_ADDR_LEN;
	arp_tmp_header->ar_pln = arp_orig_header->ar_pln;
	arp_tmp_header->ar_op = htons(arp_op_reply);
	memcpy(arp_tmp_header->ar_sha, if_walker->addr, ETHER_ADDR_LEN);
	arp_tmp_header->ar_sip = if_walker->ip;
	memcpy(arp_tmp_header->ar_tha, arp_orig_header->ar_sha, ETHER_ADDR_LEN);
	arp_tmp_header->ar_tip = arp_orig_header->ar_sip;
}

void build_ip_header(uint8_t *_packet, sr_ip_hdr_t* ip_header, struct sr_if* if_walker){
	sr_ip_hdr_t *ip_tmp_header = (sr_ip_hdr_t *)_packet;
	ip_tmp_header->ip_hl = ip_header->ip_hl;
	ip_tmp_header->ip_v = ip_header->ip_v;
	ip_tmp_header->ip_tos = ip_header->ip_tos;
	ip_tmp_header->ip_len = ip_header->ip_len;
	ip_tmp_header->ip_id = ip_header->ip_id;
	ip_tmp_header->ip_off = ip_header->ip_off;
	ip_tmp_header->ip_ttl = ip_header->ip_ttl;
	ip_tmp_header->ip_p = ip_header->ip_p;
	ip_tmp_header->ip_src = if_walker->ip;
	ip_tmp_header->ip_dst = ip_header->ip_src;

	ip_tmp_header->ip_sum = 0;
	ip_tmp_header->ip_sum = cksum((uint8_t*)ip_header, IPv4_MIN_LEN);
}

void build_icmp_header(uint8_t *_packet, sr_icmp_hdr_t* icmp_header, struct sr_if* if_walker){
	sr_icmp_hdr_t *icmp_tmp_header = (sr_icmp_hdr_t *)_packet;

	icmp_tmp_header->icmp_code = icmp_header->icmp_code;
	if(icmp_header->icmp_type == icmp_protocol_type8){
		icmp_tmp_header->icmp_type = icmp_protocol_type0;
	}
	icmp_tmp_header->icmp_sum = 0;
	icmp_tmp_header->icmp_sum = cksum((uint8_t*)icmp_header, IPv4_MIN_LEN + ICMP_MIN_LEN);
	printf("icmp %u\n", icmp_tmp_header->icmp_sum);
}

/*---------------------------------------------------------------------
 * Method: sr_handlepacket(uint8_t* p,char* interface)
 * Scope:  Global
 *
 * This method is called when the ethernet type is Internet Protocol.
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

	sr_ethernet_hdr_t* eth_orig_header = (sr_ethernet_hdr_t*)packet;
	sr_ip_hdr_t* ip_orig_header = ((sr_ip_hdr_t*)(packet + sizeof(sr_ethernet_hdr_t)));
	sr_icmp_hdr_t* icmp_header =  ((sr_icmp_hdr_t*)(packet + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t)));

	/* Check Sum */
	uint16_t given_len = ip_orig_header->ip_sum;
	ip_orig_header->ip_sum = 0;
	if(given_len != cksum((uint8_t*)ip_orig_header, IPv4_MIN_LEN)) {
		printf("The Received Packet is corrupted. Checksum Failed. \n");
		return;
	}
	ip_orig_header->ip_sum = given_len;

	/* Check whether there exists the destination from the packet is in the route table.*/
	struct sr_if *dest;
	if(is_for_me(sr->if_list, ip_orig_header->ip_dst)){
		/* In the routing table, the destination can be verified.*/
		if(icmp_header->icmp_type == icmp_protocol_type0){
			/* ICMP Echo Reply */
			printf("ICMP Echo Reply\n");
		}else if(icmp_header->icmp_type == icmp_protocol_type8){
			/* ICMP Echo Request */
			printf("ICMP Echo Request\n");

		}else if(icmp_header->icmp_type == icmp_protocol_type11){
			/* Time Exceeded */
			printf("ICMP Time Exceeded\n");
		}else if(icmp_header->icmp_type == icmp_protocol_type30){
			/* Traceroute */
			printf("ICMP Traceroute\n");
		}else{
			/* ICMP Port Unreachable */
			fprintf(stderr, "ICMP port unreachable. \n");
		}
	}else{
		struct sr_rt *match_dest;
		if((match_dest = sr_longest_prefix_match(sr->routing_table, ip_orig_header)) != 0){
			struct sr_arpentry *arp_entry;
			if((arp_entry = sr_arpcache_lookup(&sr->cache, ip_orig_header->ip_dst)) != NULL){

			}else{
				/*send_packet(); arp request send*/
			}
		}else{
			/* no match found error */
			/* ICMP net unreachable */
			send_packet(sr, packet, interface, htons(eth_orig_header->ether_type), icmp_header->icmp_type);
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
		if((rtable->dest.s_addr & rtable->mask.s_addr) == (ip_header->ip_dst & rtable->mask.s_addr)){
			if(best == 0 || rtable->mask.s_addr > best->mask.s_addr){
				best = rtable;
			}
		}
		rtable = rtable->next;
	}
	return best;
}/* end sr_longest_prefix_match */

/*---------------------------------------------------------------------
 * Method: is_for_me(struct sr_if*, uint32_t*)
 * Scope:  Global
 *
 * This method is called to check whether the destination ip address
 * in the received packet is for the router or not. returns 1 if it
 * is, and 0 otherwise.
 *
 *---------------------------------------------------------------------*/
int is_for_me(struct sr_if* interfaces, uint32_t* dest_ip){
	while(interfaces){
		if(interfaces->ip == dest_ip){
			return 1;
		}
		interfaces = interfaces->next;
	}
	return 0;
}/* end sr_get_interface_by_ip */
