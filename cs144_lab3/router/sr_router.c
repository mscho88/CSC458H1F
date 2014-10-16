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
}/* end sr_ForwardPacket */

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
	sr_arp_hdr_t* arp_header = ((sr_arp_hdr_t*)(packet + sizeof(sr_ethernet_hdr_t)));

    if(htons(arp_header->ar_op) == arp_op_request){
    	struct sr_arpentry *arp_entry;
    	if((arp_entry = sr_arpcache_lookup(&(sr->cache), arp_header->ar_sip)) == NULL){
    		/* If no ARP cache is saved, the router caches the sender. */
    		struct sr_arpreq *arp_cache;
    		if((arp_cache = sr_arpcache_insert(&(sr->cache), arp_header->ar_sha, arp_header->ar_sip)) == NULL){
    		    uint8_t* tx_packet = ((uint8_t*)(malloc(sizeof(sr_ethernet_hdr_t) + sizeof(sr_arp_hdr_t))));
    		    struct sr_if* rx_if = sr_get_interface(sr, interface);
    		    print_hdr_eth(packet);
    		    memcpy(tx_packet, packet, sizeof(sr_arp_hdr_t));
    		    print_hdr_eth(tx_packet);
    			sr_arp_hdr_t* tx_arp = ((sr_arp_hdr_t*)(tx_packet + sizeof(sr_ethernet_hdr_t)));
    			print_hdr_arp((uint8_t*)tx_arp);
    			tx_arp->ar_hln = arp_header->ar_hln;
				tx_arp->ar_hrd = arp_header->ar_hrd;
				tx_arp->ar_op = arp_header->ar_op;
				tx_arp->ar_pln = arp_header->ar_pln;
				tx_arp->ar_pro = arp_header->ar_pro;
				memcpy(tx_arp->ar_sha, arp_header->ar_sha, ETHER_ADDR_LEN);
				tx_arp->ar_sip = arp_header->ar_sip;
				memcpy(tx_arp->ar_tha, arp_header->ar_tha, ETHER_ADDR_LEN);
				tx_arp->ar_tip = arp_header->ar_tip;
				/*print_hdr_arp((uint8_t*)tx_arp);*/
				print_hdr_eth(tx_packet);
				sr_send_packet(sr, ((uint8_t*)(tx_packet)), sizeof(sr_ethernet_hdr_t) + sizeof(sr_arp_hdr_t), rx_if->name);

				free(tx_packet);

    		}else{
    			Debug("Error on caching the sender information. \n");
    		}
    	}else{
    		/*send back the arp_reply*/
    	}
    }else if(htons(arp_header->ar_op) == arp_op_reply){
    	Debug("*** -> Address Resolution Protocol reply \n");

    }
}/* end sr_handlepacket_arp */

/*
void populate_ethernet_header(uint8_t *buf, uint8_t *eth_shost, uint8_t *eth_dhost, uint16_t ether_type)
{
    struct sr_ethernet_hdr *rep_eth_hdr = (struct sr_ethernet_hdr *) buf;
    memcpy(rep_eth_hdr->ether_shost, eth_shost, sizeof(uint8_t) * ETHER_ADDR_LEN);
    memcpy(rep_eth_hdr->ether_dhost, eth_dhost, sizeof(uint8_t) * ETHER_ADDR_LEN);
    rep_eth_hdr->ether_type = htons(ether_type);
}
void populate_arp_header(uint8_t *buf, uint16_t hrd, uint16_t op, uint8_t *sha, uint32_t sip, uint8_t *dha, uint32_t dip)
{
    struct sr_arphdr *arp_hdr = (struct sr_arphdr *)buf;

    arp_hdr->ar_hrd = htons(hrd);
    arp_hdr->ar_pro = htons(ETHERTYPE_IP);
    arp_hdr->ar_hln = ETHER_ADDR_LEN;
    arp_hdr->ar_pln = IPv4_ADDR_LEN;
    arp_hdr->ar_op = htons(op);
    memcpy(arp_hdr->ar_sha, sha, ETHER_ADDR_LEN);
    arp_hdr->ar_sip = sip;
    memcpy(arp_hdr->ar_tha, dha, ETHER_ADDR_LEN);
    arp_hdr->ar_tip = dip;
}*/


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

	Debug("*** -> IP \n");
}/* end sr_handlepacket_ip */
