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
 truct in_addr routingDest*
 *---------------------------------------------------------------------*/

void sr_init(struct sr_instance* sr)
{
    /* REQUIRES */
    assert(sr);

    /* Initialize cache and cache cleanup thread */
    sr_arpcache_init(&(sr->cache));
    if(sr->nat_active){
    	sr_nat_init(&(sr->nat));
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

    /* Sanity Check*/
	if (len < sizeof(sr_ethernet_hdr_t) || len > 1514){
		return;
	}
	/* end Sanity Check */

	/* Set the external IP when NAT is in active */
    if(sr->nat_active && sr->nat.nat_external_ip == 0){
        sr->nat.nat_external_ip = sr_get_interface(sr, OUTBOUND)->ip;
    }

    /* When the router receives a packet, it should be determined what
	 * type of the protocol is. */
	sr_ethernet_hdr_t *eth_hdr = (sr_ethernet_hdr_t *) packet;
	uint16_t ethernet_protocol_type = htons(eth_hdr->ether_type);

    switch(ethernet_protocol_type){
    case ethertype_arp :
    	sr_handlepacket_arp(sr, packet, len, interface);
    	break;
    case ethertype_ip :
    	sr_handlepacket_ip(sr, packet, len, interface);
    	break;
    default :
    	break;
    }
}/* end sr_handlepacket */

/*---------------------------------------------------------------------
 * Method: sr_handlepacket_arp(struct sr_instance *, uint8_t,
 *								unsigned int, char*)
 * Scope:  Global
 *
 * This function handles ARP packet. ARP packet can be in two cases :
 * arp request and arp reply.
 *
 *---------------------------------------------------------------------*/
void sr_handlepacket_arp(struct sr_instance* sr,
        uint8_t * packet/* lent */,
        unsigned int len,
        char* interface/* lent */){
	assert(sr);
	assert(packet);
	assert(interface);

	/* Sanity Check */
	if (len < sizeof(sr_ethernet_hdr_t) + sizeof(sr_arp_hdr_t)){
		return;
	}
	/* end Sanity Check */

	struct sr_if *iface = sr_get_interface(sr, interface);
	sr_ethernet_hdr_t *eth_hdr = (sr_ethernet_hdr_t *)packet;
	sr_arp_hdr_t *arp_hdr = (sr_arp_hdr_t *)(packet + sizeof(sr_ethernet_hdr_t));
	if(ntohs(arp_hdr->ar_op) == arp_op_request){

		sr_arpcache_insert(&sr->cache, arp_hdr->ar_sha, arp_hdr->ar_sip);

		if(iface->ip == arp_hdr->ar_tip){
			arp_hdr->ar_op  = htons(arp_op_reply);
			memcpy(arp_hdr->ar_tha, arp_hdr->ar_sha, ETHER_ADDR_LEN);
			arp_hdr->ar_tip = arp_hdr->ar_sip;
			memcpy(arp_hdr->ar_sha, iface->addr, ETHER_ADDR_LEN);
			arp_hdr->ar_sip = iface->ip;
			memcpy(eth_hdr->ether_shost, arp_hdr->ar_sha, ETHER_ADDR_LEN);
			memcpy(eth_hdr->ether_dhost, arp_hdr->ar_tha, ETHER_ADDR_LEN);

			sr_send_packet(sr, packet, len, interface);
		}
	}else if(ntohs(arp_hdr->ar_op) == arp_op_reply){
		struct sr_arpreq* request = sr_arpcache_insert(&(sr->cache), arp_hdr->ar_sha, arp_hdr->ar_sip);
		if(request != NULL){
			struct sr_packet* package = request->packets;
			while(package){
				sr_handlepacket(sr, package->buf, package->len, package->iface);
				package = package->next;
			}
			sr_arpreq_destroy(&sr->cache, request);
		}
	}
}/* end sr_handlepacket_arp */

/*---------------------------------------------------------------------
 * Method: sr_handlepacket_ip(struct sr_instance *, uint8_t,
 *								unsigned int, char*)
 * Scope:  Global
 *
 * This function handles IP packet.
 *
 *---------------------------------------------------------------------*/
void sr_handlepacket_ip(struct sr_instance* sr,
        uint8_t * packet/* lent */,
        unsigned int len,
        char* interface/* lent */){
	sr_ip_hdr_t *ip_hdr = (sr_ip_hdr_t *)(packet + sizeof(sr_ethernet_hdr_t));

	/* Sanity Check */
	if (len < sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t)) {
		return;
	}
	/* end Sanity Check */

	/* Checksum */
	int orig_sum = ip_hdr->ip_sum;
	ip_hdr->ip_sum = 0;
	if(orig_sum != cksum(ip_hdr, sizeof(sr_ip_hdr_t))){
		return;
	}
	ip_hdr->ip_sum = orig_sum;
	/* end Checksum */


	struct sr_if* dest_if = sr_find_interface(sr, ip_hdr->ip_dst);

	if(ip_hdr->ip_p == ip_protocol_icmp){
		/* Sanity Check */
		if (len < sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t) + sizeof(sr_icmp_hdr_t)){
			return;
		}
		/* end Sanity Check*/

		sr_icmp_t3_hdr_t *icmp_t3_hdr = (sr_icmp_t3_hdr_t*) (packet + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t));

		/* Checksum */
		orig_sum = icmp_t3_hdr->icmp_sum;
		icmp_t3_hdr->icmp_sum = 0;
		if(orig_sum != cksum(icmp_t3_hdr, ntohs(ip_hdr->ip_len) - sizeof(sr_ip_hdr_t))){
			return;
		}
		icmp_t3_hdr->icmp_sum = orig_sum;
		/* end Checksum */
	}else if(ip_hdr->ip_p == ip_protocol_tcp){
		/* Sanity Check*/
		if (len < sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t) + sizeof(sr_tcp_hdr_t)){
			return;
		}
		/* end Sanity Check */
		sr_tcp_hdr_t *tcp_hdr = (sr_tcp_hdr_t*) (packet + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t));

		/* Checksum */
		if(tcp_cksum(packet,len) != tcp_hdr->checksum){
			return;
		}
		/* end Checksum */
	}

	if(dest_if->name){
		if(sr->nat_active){
			if(strcmp(interface, OUTBOUND) + strcmp(dest_if->name, OUTBOUND) == 0){
				/* External to External */
				sr_nat_mapping_type mapping_type;
				uint16_t aux_ext;
				if(ip_hdr->ip_p == ip_protocol_icmp){
					sr_icmp_t3_hdr_t *icmp_t3_hdr = (sr_icmp_t3_hdr_t*) (packet + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t));
					mapping_type = nat_mapping_icmp;
					aux_ext = icmp_t3_hdr->unused;

					struct sr_nat_mapping *mapping = sr_nat_lookup_external(&(sr->nat),aux_ext, mapping_type);
					printf("hello3\n");
					if(mapping != NULL){
						printf("hello4\n");
						sr_nat_translate(sr, packet, len, mapping, nat_trans_ext_to_int);
						sr_handlepacket(sr, packet, len, INBOUND);
						free(mapping);
						return;
					}
				}else if(ip_hdr->ip_p == ip_protocol_tcp){
					printf("hello1\n");
					sr_tcp_hdr_t *tcp_hdr = (sr_tcp_hdr_t*) (packet + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t));
					mapping_type = nat_mapping_tcp;
					aux_ext = tcp_hdr->dest_port;
					printf("hello2\n");
					struct sr_nat_mapping *mapping = sr_nat_lookup_external(&(sr->nat),aux_ext, mapping_type);
					printf("hello3\n");
					if(mapping != NULL){
						printf("hello4\n");
						sr_nat_translate(sr, packet, len, mapping, nat_trans_ext_to_int);
						sr_handlepacket(sr, packet, len, INBOUND);
						free(mapping);
						return;
					}
				}

			}else if(strcmp(interface, INBOUND) + strcmp(dest_if->name, INBOUND) == 0){
				/* Internal to Internal */
				/* nothing to be set */
			}else{
				/* Internal/External to External/Internal respectively */
				sr_send_icmp(sr, packet, len, icmp_code3, icmp_type0, interface);
			}
			printf("hello5\n");
		}

		if(ip_hdr->ip_p == ip_protocol_icmp){
			sr_icmp_hdr_t *icmp_hdr = (sr_icmp_hdr_t*) (packet + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t));
			if(icmp_hdr->icmp_type == 8){
				if(icmp_hdr->icmp_code == 0){
					sr_send_icmp(sr, packet, len, icmp_code0, icmp_type0, interface);
				}
			}
			return;
		}else if(ip_hdr->ip_p == ip_protocol_tcp || ip_hdr->ip_p == ip_protocol_udp){
			sr_send_icmp(sr, packet, len, icmp_code3, icmp_type3, interface);
		}
	}else{
		/* if there is any routing table for the packet .. */
		if(sr->routing_table == 0){
			sr_send_icmp(sr, packet, len, icmp_code3, icmp_type0, interface);
			return;
		}

		char* matching_iface = sr_longest_prefix_match(sr, ip_hdr->ip_dst);
		if(sr_longest_prefix_match(sr, ip_hdr->ip_dst) == NULL){
			sr_send_icmp(sr, packet, len, icmp_code3, icmp_type0, interface);
			return;
		}

		if(ip_hdr->ip_ttl <= 1){
			sr_send_icmp(sr, packet, len, icmp_type11, icmp_code0, interface);
			return;
		}

		if(sr->nat_active){
			if (strcmp(interface, INBOUND) == 0 && strcmp(matching_iface, OUTBOUND) == 0){
				sr_nat_mapping_type proto_type;
				uint16_t src_port = 0;
				struct sr_nat_connection* conn = NULL;
				if(ip_hdr->ip_p == ip_protocol_icmp){
					sr_icmp_t3_hdr_t *icmp_t3_hdr = (sr_icmp_t3_hdr_t*) (packet + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t));
					src_port = icmp_t3_hdr->unused;
					proto_type = nat_mapping_icmp;
				}else if(ip_hdr->ip_p == ip_protocol_tcp){
					sr_tcp_hdr_t *tcp_hdr = (sr_tcp_hdr_t*) (packet + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t));
					src_port = tcp_hdr->src_port;
					printf("%i\n", tcp_hdr->src_port);
					proto_type = nat_mapping_tcp;
					conn = build_connections(ip_hdr, tcp_hdr);
				}
				/* If there any mapping regarding to the src IP address, insert it to mappings */
				struct sr_nat_mapping *mappings = sr_nat_lookup_internal(&sr->nat, ip_hdr->ip_src, src_port, proto_type);
				if(mappings == NULL){
					mappings = sr_nat_insert_mapping(&sr->nat, ip_hdr->ip_src, src_port, proto_type);
					/* If the protocol is TCP, then connections must be set.
					 * Otherwise, it is ICMP where connections must be set to NULL. */
					mappings->conns = proto_type == nat_mapping_tcp ? conn : NULL;

					mappings = sr_nat_lookup_internal(&sr->nat, ip_hdr->ip_src, src_port, proto_type);
				}
				sr_nat_translate(sr, packet, len, mappings, nat_trans_int_to_ext);
				sr_handlepacket(sr, packet, len, OUTBOUND);

				/* if any mapping found, then it need to be freed */
				if(mappings){
					free(mappings);
				}
				return;
			}
			else if (strcmp(interface, OUTBOUND) + strcmp(matching_iface, INBOUND) == 0){
				sr_send_icmp(sr, packet, len, icmp_code3, icmp_type0, interface);
				return;
			}
		}
		sr_ethernet_hdr_t *eth_hdr = (sr_ethernet_hdr_t *)packet;
		struct sr_arpentry* arp_cache = sr_arpcache_lookup(&sr->cache, ip_hdr->ip_dst);
		if(arp_cache == NULL){
			struct sr_arpreq* currentRequest = sr_arpcache_queuereq(&sr->cache, ip_hdr->ip_dst, packet, len, interface);
		}else{
			struct sr_if* curInterface = sr_get_interface(sr, matching_iface);
			ip_hdr->ip_ttl--;

			ip_hdr->ip_sum = 0;
			ip_hdr->ip_sum = cksum((packet + sizeof(sr_ethernet_hdr_t)), sizeof(sr_ip_hdr_t));

			/* build the Ethernet header */
			memcpy(eth_hdr->ether_shost, curInterface->addr, ETHER_ADDR_LEN);
			memcpy(eth_hdr->ether_dhost, arp_cache->mac, ETHER_ADDR_LEN);

			sr_send_packet(sr, packet, len, matching_iface);
			free(arp_cache);
		}
	}
}

/*---------------------------------------------------------------------
 * Method: sr_nat_connection_state(struct sr_nat_connection* ,
									sr_tcp_hdr_t *)
 * Scope:  Global
 *
 * Check the connection state of the connection
 *
 *---------------------------------------------------------------------*/
void sr_nat_connection_state(struct sr_nat_connection* conn, sr_tcp_hdr_t *tcp_hdr){
	if(conn->state == tcp_state_syn_sent){
		int ackBit = ((tcp_hdr->flag_state >> 4)&1)%2;
		int syncBit = ((tcp_hdr->flag_state >> 1)&1)%2;
		if(ackBit && syncBit){
			conn->state = tcp_state_syn_recv;
		}
	}else if(conn->state == tcp_state_syn_recv){
		int ackBit = ((tcp_hdr->flag_state >> 4)&1)%2;
		if(ackBit){
			conn->state = tcp_state_established;
		}
	}else if(conn->state == tcp_state_established){
		int finBit = ((tcp_hdr->flag_state)&1)%2;
		if(finBit){
			conn->state = tcp_state_closed;
		}
	}
}/* end sr_nat_connection_state */

/*---------------------------------------------------------------------
 * Method: sr_nat_translate(struct sr_instance* ,
							uint8_t* , int ,
							struct sr_nat_mapping* ,
							sr_nat_trans_type )
 * Scope:  Global
 *
 *---------------------------------------------------------------------*/
void sr_nat_translate(struct sr_instance* sr,
		uint8_t* packet, int len,
		struct sr_nat_mapping* mapping,
        sr_nat_trans_type trans_type){
    assert(sr);
    assert(packet);
    assert(mapping);

    /* Thread_safety */
    pthread_mutex_lock(&(sr->nat.lock));

    sr_ip_hdr_t *ip_hdr = (sr_ip_hdr_t*) (packet + sizeof(sr_ethernet_hdr_t));
    sr_icmp_t3_hdr_t *icmp_hdr  = (sr_icmp_t3_hdr_t*) (packet + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t));
    sr_tcp_hdr_t *tcp_hdr  = (sr_tcp_hdr_t*) (packet + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t));

    struct sr_if *interface = NULL;

    if(trans_type == nat_trans_int_to_ext){
        /* Internal to External */
    	ip_hdr->ip_src = mapping->ip_ext;

    	if(mapping->type == nat_mapping_icmp){
        	icmp_hdr->unused = mapping->aux_ext;
        	icmp_hdr->icmp_sum  = 0;
        	icmp_hdr->icmp_sum  = cksum(icmp_hdr, ntohs(ip_hdr->ip_len) - sizeof(sr_ip_hdr_t));
        }else if(mapping->type == nat_mapping_tcp){
        	uint32_t src_seq = tcp_hdr->ack_num - 1;
            struct sr_nat_connection* conn = sr_nat_lookup_connection(&(sr->nat), mapping, mapping->ip_int, ip_hdr->ip_dst, src_seq, tcp_hdr->dest_port);

            if(conn){
            	sr_nat_connection_state(conn, tcp_hdr);
				conn->src_seq = tcp_hdr->sequence_num;
				conn->last_updated = time(NULL);
			}

            tcp_hdr->src_port = mapping->aux_ext;
            tcp_hdr->checksum = 0;
            tcp_hdr->checksum = tcp_cksum(packet,len);
		}

        interface = sr_get_interface(sr, OUTBOUND);

    }else if(trans_type == nat_trans_ext_to_int){
    	/* External to Internal */
    	ip_hdr->ip_dst = mapping->ip_int;

    	if(mapping->type == nat_mapping_icmp){
        	icmp_hdr->unused = mapping->aux_int;
        	icmp_hdr->icmp_sum  = 0;
        	icmp_hdr->icmp_sum  = cksum(icmp_hdr, ntohs(ip_hdr->ip_len) - sizeof(sr_ip_hdr_t));
        }
        else if(mapping->type == nat_mapping_tcp){
            uint32_t src_seq = tcp_hdr->ack_num - 1;
            struct sr_nat_connection* conn = sr_nat_lookup_connection(&(sr->nat), mapping, mapping->ip_int, ip_hdr->ip_src, src_seq, tcp_hdr->src_port);
            if(conn){
            	sr_nat_connection_state(conn, tcp_hdr);
				conn->src_seq = tcp_hdr->sequence_num;
				conn->last_updated = time(NULL);
			}

            tcp_hdr->dest_port = mapping->aux_int;
            tcp_hdr->checksum = 0;
            tcp_hdr->checksum  = tcp_cksum(packet,len);
        }

        interface = sr_get_interface(sr, INBOUND);

    }
    memcpy(((sr_ethernet_hdr_t *)packet)->ether_dhost, interface->addr, ETHER_ADDR_LEN);
    memcpy(((sr_ethernet_hdr_t *)packet)->ether_shost, interface->addr, ETHER_ADDR_LEN);

    ip_hdr->ip_sum = 0;
    ip_hdr->ip_sum = cksum((packet + sizeof(sr_ethernet_hdr_t)), sizeof(sr_ip_hdr_t));

    mapping->last_updated = time(NULL);

    pthread_mutex_unlock(&(sr->nat.lock));
}

/*---------------------------------------------------------------------
 * Method: sr_send_icmp(struct sr_instance *, uint8_t *,
        				unsigned int , uint8_t , uint8_t ,
        				char* );
 * Scope:  Global
 *
 * Fill the Ethernet, IP and ICMP header and send the packet. The
 * information can vary regarding to the type of ICMP
 *---------------------------------------------------------------------*/
void sr_send_icmp(struct sr_instance *sr, uint8_t *packet,
        unsigned int len, uint8_t type, uint8_t code,
        char* interface){

	assert(sr);
	assert(packet);
	assert(interface);

    int length = type == icmp_type0 ? len : sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t) + sizeof(sr_icmp_t3_hdr_t);

    uint8_t *_packet = (uint8_t*) malloc(length);

    sr_ethernet_hdr_t *eth_hdr_2send = (sr_ethernet_hdr_t *) _packet;
    sr_ip_hdr_t *ip_hdr_2send      = (sr_ip_hdr_t*) (_packet + sizeof(sr_ethernet_hdr_t));
    sr_icmp_t3_hdr_t *icmp_hdr_2send  = (sr_icmp_t3_hdr_t*) (_packet + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t));

    sr_ethernet_hdr_t *eth_hdr = (sr_ethernet_hdr_t *) packet;
    sr_ip_hdr_t *ip_hdr = (sr_ip_hdr_t*) (packet + sizeof(sr_ethernet_hdr_t));
    sr_icmp_t3_hdr_t *icmp_hdr = (sr_icmp_t3_hdr_t*) (packet + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t));

    struct sr_if *src_if = sr_get_interface(sr,interface);

    /* build Ethernet header */
	memcpy(eth_hdr_2send->ether_dhost, eth_hdr->ether_shost, ETHER_ADDR_LEN);
	memcpy(eth_hdr_2send->ether_shost, eth_hdr->ether_dhost, ETHER_ADDR_LEN);
	eth_hdr_2send->ether_type = htons(ethertype_ip);

	/* build IP header */
	ip_hdr_2send->ip_tos = 0;
	ip_hdr_2send->ip_hl  = 5;
	ip_hdr_2send->ip_v   = 4;
	ip_hdr_2send->ip_len = htons(length - sizeof(sr_ethernet_hdr_t));
	ip_hdr_2send->ip_id  = htons(ip_hdr->ip_id);
	ip_hdr_2send->ip_off = htons(IP_DF);
	ip_hdr_2send->ip_ttl = 64;
	ip_hdr_2send->ip_p   = ip_protocol_icmp;
	ip_hdr_2send->ip_dst = ip_hdr->ip_src;
	ip_hdr_2send->ip_src = src_if->ip;

    /* build ICMP header */
    if(type == icmp_type0){
        memcpy(_packet, packet, length);
        icmp_hdr_2send->unused    = icmp_hdr->unused;
        icmp_hdr_2send->next_mtu  = icmp_hdr->next_mtu;
        icmp_hdr_2send->icmp_type = type;
        icmp_hdr_2send->icmp_code = code;
    }else if(type == icmp_type3 || type == icmp_type11){
        memcpy(icmp_hdr_2send->data, ip_hdr, ICMP_DATA_SIZE);
        icmp_hdr_2send->icmp_type = type;
        icmp_hdr_2send->icmp_code = code;
    }else{
        return;
    }

    ip_hdr_2send->ip_sum = 0;
    icmp_hdr_2send->icmp_sum  = 0;

    icmp_hdr_2send->icmp_sum  = cksum(icmp_hdr_2send,ntohs(ip_hdr_2send->ip_len) - sizeof(sr_ip_hdr_t));
    ip_hdr_2send->ip_sum      = cksum((_packet + sizeof(sr_ethernet_hdr_t)), sizeof(sr_ip_hdr_t));

    sr_send_packet(sr,_packet, length,interface);

    free(_packet);
}

/*---------------------------------------------------------------------
 * Method: sr_longest_prefix_match(struct sr_instance *, uint32_t)
 * Scope:  Global
 *
 * Find the longest prefix match from the routing table
 *---------------------------------------------------------------------*/
char* sr_longest_prefix_match(struct sr_instance *sr, uint32_t dest_ip){
    struct sr_rt* cur = sr->routing_table;
    char* iface = NULL;
    uint32_t mask = 0;
    while(cur){
        if(cur->mask.s_addr > mask || mask == 0){
            if((dest_ip & cur->mask.s_addr) == cur->dest.s_addr){
            	mask = cur->mask.s_addr;
                iface = cur->interface;
            }
        }
        cur = cur->next;
    }
    return iface;
}/* end sr_longest_prefix_match */
