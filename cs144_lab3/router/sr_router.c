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
#define ETHER_HEADER_LEN 14
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
        		send_packet(sr, packet, len, interface, htons(eth_header->ether_type));
    		}else{
    			Debug("Error on caching the sender information. \n");
    		}
    	}else{
    		/* Send ARP reply message */
    		send_packet(sr, packet, len, interface, htons(eth_header->ether_type));
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
void send_packet(struct sr_instance* sr, uint8_t* packet, unsigned int len, char* interface, uint16_t protocol){
	unsigned int length;

	sr_ethernet_hdr_t* eth_header = (sr_ethernet_hdr_t *)packet;
	if(protocol == ethertype_arp){
		sr_arp_hdr_t* arp_header = ((sr_arp_hdr_t*)(packet + sizeof(sr_ethernet_hdr_t)));

		length = sizeof(sr_ethernet_hdr_t) + sizeof(sr_arp_hdr_t);

		struct sr_if *interfaces = sr_get_interface(sr, interface);

		uint8_t* _packet = (uint8_t*)malloc(length);

		build_ether_header(_packet, eth_header, interfaces, protocol);
		build_arp_header(_packet + sizeof(sr_ethernet_hdr_t), arp_header, interfaces);

		sr_send_packet(sr, (uint8_t*)_packet, length, interfaces->name);
		free(_packet);
	}else if(protocol == ethertype_ip){
		sr_ip_hdr_t* ip_header = ((sr_ip_hdr_t*)(packet + sizeof(sr_ethernet_hdr_t)));
		sr_icmp_hdr_t* icmp_header;

		icmp_header =  ((sr_icmp_hdr_t*)(packet + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t)));
		length = sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t) + sizeof(sr_icmp_hdr_t);

		struct sr_if *interfaces = sr_get_interface(sr, interface);
		uint8_t* _packet = (uint8_t*)malloc(length);
		build_ether_header(_packet, eth_header, interfaces, protocol);
		build_ip_header(_packet + sizeof(sr_ethernet_hdr_t), ip_header, interfaces);
		/*build_icmp_header(_packet + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t), icmp_header, interfaces);*/

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
void build_ether_header(uint8_t *_packet, sr_ethernet_hdr_t* eth_orig_header, struct sr_if* if_walker, uint16_t protocol){
	sr_ethernet_hdr_t *eth_tmp_header = (sr_ethernet_hdr_t *)_packet;
	memcpy(eth_tmp_header->ether_dhost, eth_orig_header->ether_shost, ETHER_ADDR_LEN);
	memcpy(eth_tmp_header->ether_shost, if_walker->addr, ETHER_ADDR_LEN);
	if(protocol == ethertype_arp){
		eth_tmp_header->ether_type = htons(ethertype_arp);
	}else if(protocol == ethertype_ip){
		eth_tmp_header->ether_type = htons(ethertype_ip);

	}
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
/*
void build_icmp_header(uint8_t *_packet, sr_icmp_hdr_t* icmp_header, struct sr_if* if_walker){
	sr_icmp_hdr_t *icmp_tmp_header = (sr_icmp_hdr_t *)_packet;
	icmp_tmp_header->icmp_code = icmp_header->icmp_code;
	icmp_tmp_header->icmp_type = 0;
	icmp_tmp_header->icmp_sum = cksum((uint8_t*)icmp_header, (IPv4_MIN_LEN + 8 > temporary_len - ETHER_HEADER_LEN ? IPv4_MIN_LEN + 8 : temporary_len - ETHER_HEADER_LEN));
}*/


void send_icmp_error(uint8_t type, uint8_t code, struct sr_instance *sr,
		char *interface, unsigned int len, uint8_t *pkt) {

	int new_len = sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t) + sizeof(sr_icmp_t3_hdr_t);
	uint8_t *packet = (uint8_t *) malloc(new_len);
	struct sr_if *rt_if = (struct sr_if *)malloc(sizeof(struct sr_if));
	rt_if = (struct sr_if *)sr_get_interface(sr, interface);

	/* Prepare ethernet header. */
	sr_ethernet_hdr_t *ether_hdr = (sr_ethernet_hdr_t *) pkt;
	sr_ethernet_hdr_t *ether_newhdr = (sr_ethernet_hdr_t *) packet;
	ether_newhdr->ether_type = htons(ethertype_ip);
	memcpy(ether_newhdr->ether_shost, rt_if->addr, ETHER_ADDR_LEN);
	memcpy(ether_newhdr->ether_dhost, ether_hdr->ether_shost, ETHER_ADDR_LEN);

	/* Prepare IP header. */
	sr_ip_hdr_t *ip_hdr = (sr_ip_hdr_t *)(pkt + sizeof(sr_ethernet_hdr_t));
	sr_ip_hdr_t *ip_newhdr = (sr_ip_hdr_t *)(packet + sizeof(sr_ethernet_hdr_t));
	memcpy(ip_newhdr, ip_hdr, sizeof(sr_ip_hdr_t));
	ip_newhdr->ip_src = rt_if->ip;
	ip_newhdr->ip_dst = ip_hdr->ip_src;
	ip_newhdr->ip_len = htons(56);
	ip_newhdr->ip_id = 0;
	ip_newhdr->ip_hl = 5;
	ip_newhdr->ip_off = 0;
	ip_newhdr->ip_ttl = 64;
	ip_newhdr->ip_p = ip_protocol_icmp;
	ip_newhdr->ip_sum = 0;
	ip_newhdr->ip_sum = cksum(packet + sizeof(sr_ethernet_hdr_t), sizeof(sr_ip_hdr_t));

	/* Prepare the ICMP t3 header. */
	sr_icmp_t3_hdr_t *icmp_t3_hdr = (sr_icmp_t3_hdr_t *)(packet +
									sizeof(sr_ethernet_hdr_t) +
									sizeof(sr_ip_hdr_t));
	icmp_t3_hdr->icmp_type = type;
	icmp_t3_hdr->icmp_code = code;
	icmp_t3_hdr->icmp_sum = 0;
	memcpy(icmp_t3_hdr->data,  ip_hdr, 20);
	memcpy(icmp_t3_hdr->data + 20, pkt + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t), 8);
	icmp_t3_hdr->icmp_sum = cksum(packet + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t),
							sizeof(sr_icmp_t3_hdr_t));

	/* Send the ICMP error packet. */
	sr_send_packet(sr, packet, new_len, interface);
}
void forward_packet(struct sr_instance *sr, char *interface,
					unsigned char *dest_mac, unsigned int len, uint8_t *pkt) {

	uint8_t *packet = (uint8_t *) malloc(len);
	memcpy(packet, pkt, len);
	struct sr_if *rt_if = (struct sr_if *)malloc(sizeof(struct sr_if));
	rt_if = (struct sr_if *)sr_get_interface(sr, interface);

	/* Prepare ethernet header. */
	sr_ethernet_hdr_t *ether_hdr = (sr_ethernet_hdr_t *) packet;
	ether_hdr->ether_type = htons(ethertype_ip);
	memcpy(ether_hdr->ether_shost, rt_if->addr, ETHER_ADDR_LEN);
	memcpy(ether_hdr->ether_dhost, &(dest_mac), ETHER_ADDR_LEN);

	/* Recompute checksum. */
	sr_ip_hdr_t *ip_hdr = (sr_ip_hdr_t *)(packet + sizeof(sr_ethernet_hdr_t));
	ip_hdr->ip_sum = 0;
	ip_hdr->ip_sum = cksum(packet + sizeof(sr_ethernet_hdr_t), sizeof(sr_ip_hdr_t));

	/* Forward to next hop. */
	print_hdrs(packet, len);
	sr_send_packet(sr, packet, len, interface);
	free(packet);
}

/*
void build_icmp_header(uint8_t *_packet, sr_icmp_hdr_t* icmp_header, struct sr_if* if_walker){
	sr_icmp_hdr_t *icmp_tmp_header = (sr_icmp_hdr_t *)_packet;

	icmp_tmp_header->icmp_code = icmp_header->icmp_code;
	if(icmp_header->icmp_type == icmp_protocol_type8){
		icmp_tmp_header->icmp_type = 3;
	}
	icmp_tmp_header->icmp_sum = cksum((uint8_t*)icmp_header, (IPv4_MIN_LEN + 8 > temporary_len - ETHER_HEADER_LEN ? IPv4_MIN_LEN + 8 : temporary_len - ETHER_HEADER_LEN));
	printf("icmp %u\n", icmp_tmp_header->icmp_sum);
}*/

/*---------------------------------------------------------------------
 * Method: sr_handlepacket(uint8_t* p,char* interface)
 * Scope:  Global
 *
 * This method is called when the ethernet type is Internet Protocol.
 *
 *---------------------------------------------------------------------*/
void sr_handlepacket_ip(struct sr_instance* sr, uint8_t * packet,
		unsigned int len, char* interface){
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
		printf(" The Received Packet is corrupted. Checksum Failed. \n");
		return;
	}
	ip_orig_header->ip_sum = given_len;

	struct sr_if *dest;
	if(is_for_me(&(sr->if_list), ip_orig_header->ip_dst)){
		/* Check whether the packet is in the interfaces of the router. */
		if(ip_orig_header->ip_p == ip_protocol_tcp ||
				ip_orig_header->ip_p == ip_protocol_udp){
			/* If the router receives TCP or UDP packet, then send back the
			 * ICMP error packet to the sender. */
			fprintf(stderr, " Received Unsupported %s Packet \n",
					ip_orig_header->ip_p == ip_protocol_tcp ? "TCP" : "UDP");
			/***************/
			send_icmp_error(icmp_type3, icmp_code3, sr, interface, len, packet);
		}else{
			/* If the router receives the packet, consider the packet with the Type 0(Echo). */
			if(icmp_header->icmp_type == icmp_type0){
				/***************/
				send_icmp_echo(sr, interface, len, packet);
			}else{
				fprintf(stderr, " Received Unknown Type Of ICMP Packet \n");
			}
		}
	}else{
		/* If the packet is not in the interfaces of the router, the router
		 * needs to find the longest prefix match interface to send the packet.*/
		if(ip_orig_header->ip_ttl > 0){
			/* Since the packet is going through the router, TTL should be deducted. */
			ip_orig_header->ip_ttl--;

			/* Find the longest prefix match from the routing table. */
			struct sr_rt *dest;
			if((dest = sr_longest_prefix_match(&(sr->routing_table), ip_orig_header)) != 0){
				struct sr_arpentry *arp_entry;
				if((arp_entry = sr_arpcache_lookup(&(sr->cache), ip_orig_header->ip_dst)) != NULL){
					/***************/
					forward_packet(sr, dest->interface, arp_entry->mac, len, packet);
					free(arp_entry);
				}else{
					/*send_packet(); arp request send*/
					Debug("");
					fprintf(stderr, "IP->MAC mapping not in ARP cache %u \n", ip_orig_header->ip_dst);
					/*Case where ip->mapping is not in cache*/
					/***************/
					sr_arpcache_queuereq(&(sr->cache), ip_orig_header->ip_dst, packet, len, dest->interface);
					fprintf(stderr, "Added Arp Req to queu \n");
				}
			}else{
				print_addr_ip(dest->dest);
				print_addr_ip(dest->gw);
				print_addr_ip(dest->mask);
				/* no match found error */
				/* ICMP net unreachable */
				/* important*/
				/*send_packet(sr, packet, interface, htons(eth_orig_header->ether_type), 3);*/
				fprintf(stderr, "Could Not Be Determined To Transmit The Packet To ");
				print_addr_ip_int(ip_orig_header->ip_dst);
				fprintf(stderr, "Sending The Packet Back To ");
				print_addr_ip_int(ip_orig_header->ip_src);
				send_icmp_error(icmp_type3, icmp_code, sr, interface, len, packet);
			}
		}else{
			fprintf(stderr, "Received Packet TTL(%u) Expired in Transit \n", ip_orig_header->ip_ttl);
			send_icmp_error(icmp_type11, 0, sr, interface, len, packet);
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

void send_icmp_echo(struct sr_instance *sr, char *interface, unsigned int len, uint8_t *pkt) {

	uint8_t *packet = (uint8_t *) malloc(len);
	memcpy(packet, pkt, len);
	struct sr_if *rt_if = (struct sr_if *)malloc(sizeof(struct sr_if));
	rt_if = (struct sr_if *)sr_get_interface(sr, interface);

	/* Prepare ethernet header. */
	sr_ethernet_hdr_t *ether_hdr = (sr_ethernet_hdr_t *) packet;
	ether_hdr->ether_type = htons(ethertype_ip);
	uint8_t shost[ETHER_ADDR_LEN];
	uint8_t dhost[ETHER_ADDR_LEN];
	memcpy(shost, rt_if->addr, ETHER_ADDR_LEN);
	memcpy(dhost, ether_hdr->ether_shost, ETHER_ADDR_LEN);
	memcpy(ether_hdr->ether_shost, shost, ETHER_ADDR_LEN);
	memcpy(ether_hdr->ether_dhost, dhost, ETHER_ADDR_LEN);

	/* Prepare IP header. */
	sr_ip_hdr_t *ip_hdr = (sr_ip_hdr_t *)(packet + sizeof(sr_ethernet_hdr_t));
	uint32_t dest = ip_hdr->ip_src;
	uint32_t src = rt_if->ip;
	ip_hdr->ip_src = src;
	ip_hdr->ip_dst = dest;
	ip_hdr->ip_sum = 0;
	ip_hdr->ip_sum = cksum(packet + sizeof(sr_ethernet_hdr_t), sizeof(sr_ip_hdr_t));

	/* Prepare the ICMP reply header. */
	sr_icmp_hdr_t *icmp_hdr_rply = (sr_icmp_hdr_t *)(packet +
													sizeof(sr_ethernet_hdr_t) +
													sizeof(sr_ip_hdr_t));
	icmp_hdr_rply->icmp_type = 0;
	icmp_hdr_rply->icmp_code = 0;
	icmp_hdr_rply->icmp_sum = 0;
	icmp_hdr_rply->icmp_sum = cksum(packet + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t),
									sizeof(sr_icmp_hdr_t));

	/* Now send the packet. */
	sr_send_packet(sr, packet, len, interface);
	free(packet);
}


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
