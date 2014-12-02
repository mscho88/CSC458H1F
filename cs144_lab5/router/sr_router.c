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
#include "sr_nat.h"
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
 * Method: sr_handlepacketsr_print_routing_table(sr);(uint8_t* p,char* interface)
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
        /*struct sr_if* out_iface = sr_get_interface(sr, OUTBOUND);*/
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

char* sr_rtable_lookup(struct sr_instance *sr, uint32_t destIP){
    struct sr_rt* rTable = sr->routing_table;
    char* rInterface = NULL;
    uint32_t rMask = 0;
    while(rTable)
    {
        uint32_t curMask = rTable->mask.s_addr;
        uint32_t curDest = rTable->dest.s_addr;
        if(rMask == 0 || curMask > rMask)
        {
            /*Check with Longest Prefix Match Algorithm*/
            uint32_t newDestIP = (destIP & curMask);
            if(newDestIP == curDest)
            {
                rMask = curMask;
                rInterface = rTable->interface;
            }
        }
        rTable = rTable->next;
    }
    return rInterface;
}

void sr_send_icmp(struct sr_instance *sr, uint8_t *oldpacket,
        unsigned int len, uint8_t type, uint8_t code,
        char* interface){

    /* Sanity check on params */
    if(!sr || !oldpacket || !interface || !len){
        fprintf(stderr,"sr_send_icmp: bad parameters");
        return;
    }

    /* Create new buff */
    size_t buff_size = sizeof(sr_ethernet_hdr_t) +
        sizeof(sr_ip_hdr_t) +
        sizeof(sr_icmp_t3_hdr_t);

    /* if echo reply, sizes should match */
    if(type == 0)
        buff_size = len;

    uint8_t *buff = (uint8_t*) malloc(buff_size);

    memset(buff,0,buff_size);

    /* init protocol data structures for buff and oldpacket */
    sr_ethernet_hdr_t *ehdr = (sr_ethernet_hdr_t *) buff;
    sr_ip_hdr_t *iphdr      = (sr_ip_hdr_t*) (buff + sizeof(sr_ethernet_hdr_t));
    sr_icmp_t3_hdr_t *icmphdr  = (sr_icmp_t3_hdr_t*) (buff + sizeof(sr_ethernet_hdr_t) +
            sizeof(sr_ip_hdr_t));

    sr_ethernet_hdr_t *old_ehdr = (sr_ethernet_hdr_t *) oldpacket;
    sr_ip_hdr_t *old_iphdr      = (sr_ip_hdr_t*) (oldpacket + sizeof(sr_ethernet_hdr_t));
    sr_icmp_t3_hdr_t *old_icmphdr  = (sr_icmp_t3_hdr_t*) (oldpacket + sizeof(sr_ethernet_hdr_t) +
            sizeof(sr_ip_hdr_t));

    struct sr_if *src_if = sr_get_interface(sr,interface);

    /* fill in ICMP */
    if(type == 0){
        /* echo back the originial data from echo request */
        memcpy(buff,oldpacket,buff_size);
        /* Same ID and Seq fields are required in reply packet */
        icmphdr->unused    = old_icmphdr->unused;   /* ID Section */
        icmphdr->next_mtu  = old_icmphdr->next_mtu; /* Sequence Section */
    }
    else if(type == 3 || type== 11){
        /* Set data to old ip header + 8 bytes of its data */
        memcpy(icmphdr->data,old_iphdr,ICMP_DATA_SIZE);
    }
    else{
        fprintf(stderr,"sr_send_icmp: Unknown ICMP type %d",type);
        return;
    }

    icmphdr->icmp_type = type;
    icmphdr->icmp_code = code;
    icmphdr->icmp_sum  = 0;


    /* fill in IP */
    iphdr->ip_tos = 0;
    iphdr->ip_hl  = 5;
    iphdr->ip_v   = 4;
    iphdr->ip_len = htons(buff_size - sizeof(sr_ethernet_hdr_t));
    iphdr->ip_id  = htons(old_iphdr->ip_id);
    iphdr->ip_off = htons(IP_DF);
    iphdr->ip_ttl = 64;
    iphdr->ip_p   = ip_protocol_icmp;
    iphdr->ip_dst = old_iphdr->ip_src;
    iphdr->ip_src = src_if->ip;
    iphdr->ip_sum = 0;

    /* Calculate the checksums */
    icmphdr->icmp_sum  = cksum(icmphdr,ntohs(iphdr->ip_len) - sizeof(sr_ip_hdr_t));
    iphdr->ip_sum      = cksum((buff + sizeof(sr_ethernet_hdr_t)),(iphdr->ip_hl * 4));


    /* fill in ethernet */
    memcpy(ehdr->ether_dhost,old_ehdr->ether_shost,ETHER_ADDR_LEN);
    memcpy(ehdr->ether_shost,old_ehdr->ether_dhost,ETHER_ADDR_LEN);
    ehdr->ether_type = htons(ethertype_ip);

    /* DEBUG */
    /* print_hdrs(buff,buff_size); */

    /* Send it out */
    sr_send_packet(sr,buff,buff_size,interface);

    free(buff);
}

void sr_nat_translate(struct sr_instance* sr, uint8_t* packet, int len, struct sr_nat_mapping* mapping,
        sr_nat_trans_type trans_type){

    assert(sr);

    /* Thread_safety */
    pthread_mutex_lock(&(sr->nat.lock));

    assert(packet);
    assert(mapping);

    /* Sanity check on params */


    printf("*********************************Begin SR_NAT_TRANSLATE*********************************\n");

    /* init protocol data structures for packet */
    sr_ethernet_hdr_t *ehdr = (sr_ethernet_hdr_t *) packet;
    sr_ip_hdr_t *iphdr      = (sr_ip_hdr_t*) (packet + sizeof(sr_ethernet_hdr_t));
    sr_icmp_t3_hdr_t *icmphdr  = (sr_icmp_t3_hdr_t*) (packet + sizeof(sr_ethernet_hdr_t) +
            sizeof(sr_ip_hdr_t));
    sr_tcp_hdr_t *tcphdr  = (sr_tcp_hdr_t*) (packet + sizeof(sr_ethernet_hdr_t) +
            sizeof(sr_ip_hdr_t));

    struct sr_if *interface = NULL;

    /* Internal to External */
    if(trans_type == nat_trans_int_to_ext){

        /* Set new source IP */
        iphdr->ip_src = mapping->ip_ext;

        /* ICMP: Set new icmp ID and redo Checksum */
        if(mapping->type == nat_mapping_icmp){
            printf("ICMP Translation...\n");
            icmphdr->unused = mapping->aux_ext;
            icmphdr->icmp_sum  = 0; /* Clear first */
            icmphdr->icmp_sum  = cksum(icmphdr,ntohs(iphdr->ip_len) - sizeof(sr_ip_hdr_t));
        }
        /* TCP: Set new source port and redo Checksum */
        else if(mapping->type == nat_mapping_tcp){
            printf("TCP Translation...\n");

            uint32_t src_seq = tcphdr->ack_num-1;
            /* Update Connection State */
            struct sr_nat_connection* conn =
            sr_nat_lookup_connection(&(sr->nat), mapping, mapping->ip_int, iphdr->ip_dst, src_seq, tcphdr->dest_port);
            if(conn){
                printf("Ext to Int: found a connection.\n");
                /* Determine the packet type (syn,ack,etc...) */
                /* Change the connection state accordingly */

                /*
                tcp_state_listen,
                tcp_state_syn_sent,
                tcp_state_syn_recv,
                tcp_state_established,
                tcp_state_fin_wait1,
                tcp_state_fin_wait2,
                tcp_state_close_wait,
                tcp_state_time_wait,
                tcp_state_last_ack,
                tcp_state_closed
                */

		if(conn->state == tcp_state_syn_sent)
                {
                        int ackBit = ((tcphdr->flag_state >> 4)&1)%2;
                        int syncBit = ((tcphdr->flag_state >> 1)&1)%2;
                        if(ackBit && syncBit)
                        {
                                conn->state = tcp_state_syn_recv;
                        }
                }
                else if(conn->state == tcp_state_syn_recv)
                {
			int ackBit = ((tcphdr->flag_state >> 4)&1)%2;
			if(ackBit)
			{
				conn->state = tcp_state_established;
			}
                }
                else if(conn->state == tcp_state_established)
                {
                	int finBit = ((tcphdr->flag_state)&1)%2;
			if(finBit)
			{
				conn->state = tcp_state_closed;
			}
      		}

                /*update the sequence number*/
                conn->src_seq = tcphdr->sequence_num;
                /* Update the timer */
                conn->last_updated = time(NULL);

            }else{
                printf("Ext to In: no connection found.\n");
                /*wait 6 seconds and if link exist then drop it. If not, then sent icmp unreachable.*/
            }
            tcphdr->src_port = mapping->aux_ext;
            tcphdr->checksum = 0; /* Clear first */
            tcphdr->checksum  = tcp_cksum(packet,len);
            printf("The returned Checksum is: %i\n", tcphdr->checksum);
        }

        /* Change Ethernet Source and Destination ADDR */
        interface = sr_get_interface(sr, OUTBOUND);

    }
    /* External to Internal */
    else if(trans_type == nat_trans_ext_to_int){

        /* Set new destination IP */
        iphdr->ip_dst = mapping->ip_int;

        /* ICMP: Set new icmp ID and redo Checksum */
        if(mapping->type == nat_mapping_icmp){
            printf("ICMP Translation...\n");
            icmphdr->unused = mapping->aux_int;
            icmphdr->icmp_sum  = 0; /* Clear first */
            icmphdr->icmp_sum  = cksum(icmphdr,ntohs(iphdr->ip_len) - sizeof(sr_ip_hdr_t));
        }
        /* TCP: Set new source port and redo Checksum */
        else if(mapping->type == nat_mapping_tcp){
            printf("TCP Translation...\n");
            uint32_t src_seq = tcphdr->ack_num-1;
            /* Update Connection State */
            struct sr_nat_connection* conn =
              sr_nat_lookup_connection(&(sr->nat), mapping, mapping->ip_int,
                iphdr->ip_src, src_seq, tcphdr->src_port);
            if(conn){
                printf("Ext to Int: found a connection.\n");
                /* Determine the packet type (syn,ack,etc...) */
                /* Change the connection state accordingly */

           	if(conn->state == tcp_state_syn_sent)
                {
                        int ackBit = ((tcphdr->flag_state >> 4)&1)%2;
			int syncBit = ((tcphdr->flag_state >> 1)&1)%2;
                        if(ackBit && syncBit)
                        {
                                conn->state = tcp_state_syn_recv;
                        }
                }
		else if(conn->state == tcp_state_syn_recv)
                {
                        int ackBit = ((tcphdr->flag_state >> 4)&1)%2;
                        if(ackBit)
                        {
                                conn->state = tcp_state_established;
                        }
                }
                else if(conn->state == tcp_state_established)
                {
                        int finBit = ((tcphdr->flag_state)&1)%2;
                        if(finBit)
                        {
                                conn->state = tcp_state_closed;
                        }
                }

                /*update the sequence number*/
                conn->src_seq = tcphdr->sequence_num;
                /* Update the timer */
                conn->last_updated = time(NULL);
            }else{
                printf("Ext to In: no connection found.\n");
                /*wait 6 seconds and if link exist then drop it. If not, then sent icmp unreachable.*/
            }

            tcphdr->dest_port = mapping->aux_int;
            tcphdr->checksum = 0; /* Clear first */
            tcphdr->checksum  = tcp_cksum(packet,len);
        }

        /* Change Ethernet Source and Destination ADDR */
        interface = sr_get_interface(sr, INBOUND);

    }

    /* Change Ethernet Source and Destination ADDR */
    assert(interface);
    memcpy(ehdr->ether_dhost,interface->addr,ETHER_ADDR_LEN);
    memcpy(ehdr->ether_shost,interface->addr,ETHER_ADDR_LEN);

    /* Calculate IP checksum */
    iphdr->ip_sum = 0;
    iphdr->ip_sum = cksum((packet + sizeof(sr_ethernet_hdr_t)),(iphdr->ip_hl * 4));
    printf("IP checksum: %i\n", iphdr->ip_sum);
    printf("*********************************END SR_NAT_TRANSLATE*********************************\n");

    /* Update mappings' last_update */
    mapping->last_updated = time(NULL);

    /* release mutex */
    pthread_mutex_unlock(&(sr->nat.lock));

}

/*
* calculate and return the TCP checksum for a packet that has the
* format: Etherneti_hdr(IP_hdr(TCP_hdr(...)))
*
*/
uint16_t tcp_cksum(const void *packet, int len){

    assert(packet);

    printf("HEX: %x\n",cksum(packet,len));

    sr_tcp_pseudo_hdr_t *pseudo_hdr;
    unsigned char*  buf;
    unsigned int total_len = 0;
    uint16_t checksum   = 0;

    sr_ip_hdr_t *iphdr   = (sr_ip_hdr_t*) (packet + sizeof(sr_ethernet_hdr_t));
    sr_tcp_hdr_t *tcphdr = (sr_tcp_hdr_t*) (packet + sizeof(sr_ethernet_hdr_t) +
                                                      sizeof(sr_ip_hdr_t));

    /* Fill in pseudo header */
    pseudo_hdr = (sr_tcp_pseudo_hdr_t *)malloc(sizeof(sr_tcp_pseudo_hdr_t));
    pseudo_hdr->ip_src = iphdr->ip_src;
    pseudo_hdr->ip_dst = iphdr->ip_dst;
    pseudo_hdr->reserved = 0;
    pseudo_hdr->protocol = (iphdr->ip_p);
    pseudo_hdr->len = htons(ntohs(iphdr->ip_len) - sizeof(sr_ip_hdr_t));

    uint16_t originalChecksum = tcphdr->checksum;
    printf("Original Checksum: %i\n", originalChecksum);
    tcphdr->checksum = 0;

    total_len = ntohs(iphdr->ip_len) - sizeof(sr_ip_hdr_t) + sizeof(sr_tcp_pseudo_hdr_t);

    buf = malloc(total_len);
    memcpy(buf, pseudo_hdr, sizeof(sr_tcp_pseudo_hdr_t));
    memcpy(buf+ sizeof(sr_tcp_pseudo_hdr_t), tcphdr, ntohs(iphdr->ip_len) - sizeof(sr_ip_hdr_t));

    printf("pseudo length: %lu\n",sizeof(sr_tcp_pseudo_hdr_t));
    printf("tcp total: %lu\n", ntohs(iphdr->ip_len) - sizeof(sr_ip_hdr_t));
    printf("tcp total+pseudo length: %d\n",total_len);


    checksum = cksum(buf,total_len);
    printf("checksum is : %i\n",checksum);
    tcphdr->checksum = originalChecksum;
    free(pseudo_hdr);
    free(buf);

    return checksum;
}

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
}

void sr_handlepacket_ip(struct sr_instance* sr,
        uint8_t * packet/* lent */,
        unsigned int len,
        char* interface/* lent */){
	/*int matchingHeaderAddr 	= 1;
	int broadcastAddr 		= 1;
	sr_ethernet_hdr_t *ehdr 	= (sr_ethernet_hdr_t *)packet;
	uint8_t *addr = ehdr->ether_dhost;
	struct sr_if* srcInterface = sr_get_interface(sr, interface);
	if(srcInterface == NULL)
	{
		fprintf(stderr,"sr_handlepacket: Failed to pass ETHERNET header sanity check due to bad interface name\n");
		return;
	}
	uint8_t *interfaceAddr = srcInterface->addr;
	int pos = 0;
	uint8_t cur;
	for (; pos < ETHER_ADDR_LEN; pos++) {
		cur = addr[pos];
		if(cur != 255)
		{
			broadcastAddr = 0;
		}
		if(cur != interfaceAddr[pos])
		{
			matchingHeaderAddr = 0;
		}
	}
	if(!matchingHeaderAddr && !broadcastAddr)
	{
		fprintf(stderr,"sr_handlepacket: Failed to pass ETHERNET header sanity check due to bad destination header address\n");
		return;
	}*/

	sr_ip_hdr_t *ip_hdr = (sr_ip_hdr_t *)(packet + sizeof(sr_ethernet_hdr_t));

	/* Sanity Check */
	if (len < sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t)) {
		return;
	}
	/* end Sanity Check */

	/* Checksum */
	int orig_sum = ip_hdr->ip_sum;
	ip_hdr->ip_sum = 0;
	if(orig_sum != cksum(ip_hdr, (ip_hdr->ip_hl * 4))){
		return;
	}
	ip_hdr->ip_sum = orig_sum;
	/* end Checksum */

	struct sr_if* dest_if = sr_find_interface(sr, ip_hdr->ip_dst);
	char* destInterface = dest_if->name;

	if(destInterface){
		if(sr->nat_active){
			/* External to External */
			if(!strcmp(interface,OUTBOUND) && !strcmp(destInterface,OUTBOUND)){
				sr_nat_mapping_type mapping_type;
				uint16_t aux_ext;
				if(ip_hdr->ip_p == ip_protocol_icmp){
					if (len < sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t) + sizeof(sr_icmp_hdr_t)){
						return;
					}

					sr_icmp_t3_hdr_t *icmp_t3_hdr = (sr_icmp_t3_hdr_t*) (packet + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t));

					orig_sum = icmp_t3_hdr->icmp_sum;
					icmp_t3_hdr->icmp_sum = 0;
					if(orig_sum != cksum(icmp_t3_hdr, ntohs(ip_hdr->ip_len) - sizeof(sr_ip_hdr_t))){
						return;
					}
					icmp_t3_hdr->icmp_sum = orig_sum;

					mapping_type = nat_mapping_icmp;
					aux_ext = icmp_t3_hdr->unused;
				}
				else if(ip_hdr->ip_p == ip_protocol_tcp){
					if (len < sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t) + sizeof(sr_tcp_hdr_t)){
						return;
					}
					sr_tcp_hdr_t *tcp_hdr = (sr_tcp_hdr_t*) (packet + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t));

					if(tcp_cksum(packet,len) != tcp_hdr->checksum){
						return;
					}

					aux_ext = tcp_hdr->dest_port;
					mapping_type = nat_mapping_tcp;
				}
				struct sr_nat_mapping *mapping = sr_nat_lookup_external(&(sr->nat),aux_ext, mapping_type);

				if(mapping != NULL){
					sr_nat_translate(sr,packet,len, mapping, nat_trans_ext_to_int);
					sr_handlepacket(sr,packet,len, INBOUND);
					free(mapping);
					return;
				}else{
					printf("Problem wit external looking for mapping\n");
				}
			}else if(!strcmp(interface,INBOUND) && !strcmp(destInterface,INBOUND)){
				/* Internal to Internal */
				printf("Int:%s -> Int:%s\n",interface,destInterface);
			}else{
				/* Internal to External / External to Internal */
				printf("Int/Ext:%s -> Ext/Int:%s\n",interface,destInterface);
				sr_send_icmp(sr,packet,len,3,0,interface);
			}
		}

		if(ip_hdr->ip_p == ip_protocol_icmp){
			if (len < sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t) + sizeof(sr_icmp_hdr_t)){
				return;
			}

			sr_icmp_hdr_t *icmp_hdr = (sr_icmp_hdr_t*) (packet + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t));
			orig_sum = icmp_hdr->icmp_sum;
			icmp_hdr->icmp_sum = 0;
			if(orig_sum != cksum(icmp_hdr,ntohs(ip_hdr->ip_len) - sizeof(sr_ip_hdr_t))){
				return;
			}
			icmp_hdr = orig_sum;

			if(icmp_hdr->icmp_type == 8){
				if(icmp_hdr->icmp_code != 0){
					return;
				}
				sr_send_icmp(sr,packet,len,0,0,interface);
			}else{
				return;
			}
		}else if(ip_hdr->ip_p == ip_protocol_tcp || ip_hdr->ip_p == ip_protocol_udp){
			sr_send_icmp(sr,packet,len,3,3,interface);
		}else{
			return;
		}
	}else{
		/*PACKET FORWARDING, DESTINATION IS NOT ROUTER*/
		/*Sanity Check 1: see if we have the destination address in router, if not then sent ICMP*/
		if(sr->routing_table == 0){
			sr_send_icmp(sr,packet,len,3,0,interface);
			return;
		}

		char* rInterface = sr_rtable_lookup(sr, ip_hdr->ip_dst);
		if(rInterface == NULL){
			sr_send_icmp(sr,packet,len,3,0,interface);
			return;
		}

		if(ip_hdr->ip_ttl <= 1){
			sr_send_icmp(sr,packet,len,11,0,interface);
			return;
		}

		if(sr->nat_active){
			if (strcmp(interface, INBOUND) == 0 && strcmp(rInterface, OUTBOUND) == 0){
				sr_nat_mapping_type proto_type;
				uint16_t sourcePort = 0;
				struct sr_nat_connection* initialConnection = NULL;
				if(ip_hdr->ip_p == ip_protocol_icmp){
					/*handle forward icmp while getting icmp id*/
					/* Check length */
					if (len < sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t) + sizeof(sr_icmp_t3_hdr_t)){
						fprintf(stderr, "sr_handlepacket: insufficient length\n");
						return;
					}

					sr_icmp_t3_hdr_t *icmp_t3_hdr = (sr_icmp_t3_hdr_t*) (packet + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t));
					orig_sum = icmp_t3_hdr->icmp_sum;
					icmp_t3_hdr->icmp_sum = 0;
					if(orig_sum != cksum(icmp_t3_hdr,ntohs(ip_hdr->ip_len) - sizeof(sr_ip_hdr_t))){
						return;
					}
					icmp_t3_hdr->icmp_sum = orig_sum;

					sourcePort = icmp_t3_hdr->unused;
					proto_type = nat_mapping_icmp;
				}else if(ip_hdr->ip_p == ip_protocol_tcp){
					if (len < sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t) + sizeof(sr_tcp_hdr_t)){
						return;
					}

					sr_tcp_hdr_t *tcphdr = (sr_tcp_hdr_t*) (packet +
							sizeof(sr_ethernet_hdr_t) +
							sizeof(sr_ip_hdr_t));
					if(tcp_cksum(packet,len) != tcphdr->checksum){
						return;
					}
					sourcePort = tcphdr->src_port;
					proto_type = nat_mapping_tcp;
					printf("TCP checksum works, new sourcePort %i\n", sourcePort);
					struct sr_nat_connection* initialConnection = (struct sr_nat_connection *)malloc(sizeof(struct sr_nat_connection));
					printf("****************************INSERT NEW CONNECTION IN HANDLE PACKET*****************\n");
					initialConnection->ip_src = ip_hdr->ip_src;
					initialConnection->src_seq = tcphdr->sequence_num;
					initialConnection->ip_dest = ip_hdr->ip_dst;
					initialConnection->port_dest = tcphdr->dest_port;
					initialConnection->last_updated = time(NULL);
					initialConnection->state = tcp_state_syn_sent;
					printf("IP SRC: %i\n Port SRC %i\n IP DEST %i\n PORT DEST %i\n DATE %i\n STATE %i", initialConnection->ip_src, initialConnection->src_seq, initialConnection->ip_dest, initialConnection->port_dest, initialConnection->last_updated, initialConnection->state);
					printf("*********************************FINISH INSERTING CONNECTION IN HANDLE PACKET*************\n");
				}

				struct sr_nat_mapping *internal_mapping = sr_nat_lookup_internal(&sr->nat, ip_hdr->ip_src, sourcePort, proto_type);
				if(internal_mapping == NULL){
					internal_mapping = sr_nat_insert_mapping(&sr->nat, ip_hdr->ip_src, sourcePort, proto_type);
					if(proto_type == nat_mapping_tcp){
						internal_mapping->conns = initialConnection;
					}
		/*In case of free the instance*/
		internal_mapping = sr_nat_lookup_internal(&sr->nat, ip_hdr->ip_src, sourcePort, proto_type);
		printf("source port after insert %i\n", internal_mapping->aux_int);
				}
				fprintf(stderr, "\n************ TRANSLATE INTERNAL MESSAGE TO EXTERNAL *************\n");
				sr_nat_translate(sr,packet,len, internal_mapping, nat_trans_int_to_ext);
				printf("SR_NAT_TRANS CALLED - INT TO EXT \n");
				sr_handlepacket(sr,packet,len, OUTBOUND);

				if(internal_mapping)
				{
					free(internal_mapping);
				}
				return;
			}
			else if (strcmp(interface, OUTBOUND) == 0 && strcmp(rInterface, INBOUND) == 0)
			{
				fprintf(stderr,"Cannot ping internal nat from external");
				/* Send ICMP Net Unreachable */
				sr_send_icmp(sr,packet,len,3,0,interface);
				return;
			}
		}

		sr_ethernet_hdr_t *eth_hdr = (sr_ethernet_hdr_t *)packet;
		/*Find MAC address by look up requested destination IP in cache*/
		struct sr_arpentry* cacheEntry = sr_arpcache_lookup(&sr->cache, ip_hdr->ip_dst);
		if(cacheEntry != NULL)
		{
			/* this might crush free(lookupResult);*/
			/*Now pack everything with new checksum and TTL and send */
			struct sr_if* curInterface = sr_get_interface(sr, rInterface);
			ip_hdr->ip_ttl -= 1;
			/*Calculate new checksum*/
			ip_hdr->ip_sum = 0;
			ip_hdr->ip_sum = cksum((packet + sizeof(sr_ethernet_hdr_t)),(ip_hdr->ip_hl*4));
			memcpy(eth_hdr->ether_shost, curInterface->addr, ETHER_ADDR_LEN);
			memcpy(eth_hdr->ether_dhost, cacheEntry->mac, ETHER_ADDR_LEN);
			/*dump it out and see*/
			sr_send_packet(sr, packet, len, rInterface);
			free(cacheEntry);
		}
		else
		{
			struct sr_arpreq* currentRequest = sr_arpcache_queuereq(&sr->cache, ip_hdr->ip_dst, packet, len, interface);
			/*TODO Need to free sr_arpreq*/
		}
	}
}
