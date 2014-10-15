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

  sr_ethernet_hdr_t *packet_header = (sr_ethernet_hdr_t *) packet;

  /* When the router receives any packet, it should be determined what
   * type of the protocol is. After that, it is required to figure out
   * where to send the packet by comparing the address in the routing
   * table. It may drop the packet if there exists no address to send.
   */
  uint16_t ethernet_protocol_type = htons(packet_header->ether_type);

  if(ethernet_protocol_type == ethertype_arp){
  	  Debug("*** -> Received Address Resolution Protocol \n");
  	  sr_handlepacket_arp(sr, packet, len, interface);
  }else if(ethernet_protocol_type == ethertype_ip){
	  Debug("*** -> Received Internet Protocol \n");
	  /*sr_handlepacket_ip(sr, packet, len, packet_header);*/
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


    /*sr_ethernet_hdr_t *header = (sr_ethernet_hdr_t *) packet;*/

	/* Set the packet to the ARP header
	struct sr_arp_hdr* arp_header = ((struct sr_arp_hdr*)(packet + sizeof(sr_ethernet_hdr_t)));
	print_addr_ip_int(arp_header->ar_tip);
	sr_print_routing_table(sr);*/
    sr_ethernet_hdr_t* rx_e_hdr = (sr_ethernet_hdr_t *) packet;
	sr_ethernet_hdr_t* tx_e_hdr = ((sr_ethernet_hdr_t *)(malloc(sizeof(sr_ethernet_hdr_t))));
	uint8_t* tx_packet;
	int queue_index;
    struct sr_if* rx_if = sr_get_interface(sr, interface);

    /***** Getting the ARP header *****/
    sr_arp_hdr_t *rx_arp_hdr = ((sr_arp_hdr_t *)(packet + sizeof(sr_ethernet_hdr_t)));
    sr_arp_hdr_t *tx_arp_hdr = ((sr_arp_hdr_t *)(malloc(sizeof(sr_arp_hdr_t))));

    if(htons(rx_arp_hdr->ar_op) == arp_op_request){
    	int i;
    	/* Since the packet is ARP request, it is required to broadcast
    	 * to the devices where the router knows. */
    	Debug("*** -> Address Resolution Protocol Request \n");

    	/* When the router receives ARP packet, then the router firstly
    	 * checks whether the router has any interface with the given ip
    	 * address. */
    	struct sr_if *interfaces = sr_get_interface(sr, interface);

    	for (i = 0; i < ETHER_ADDR_LEN; i++){
    		tx_e_hdr->ether_dhost[i] = rx_e_hdr->ether_shost[i];
    	}

    	for (i = 0; i < ETHER_ADDR_LEN; i++){
    		tx_e_hdr->ether_shost[i] = ((uint8_t)(rx_if->addr[i]));
    	}

    	tx_e_hdr->ether_type = rx_e_hdr->ether_type;
    	tx_arp_hdr->ar_hrd = rx_arp_hdr->ar_hrd;
    	tx_arp_hdr->ar_pro = rx_arp_hdr->ar_pro;

    	tx_arp_hdr->ar_hln = rx_arp_hdr->ar_hln;
    	tx_arp_hdr->ar_pln = rx_arp_hdr->ar_pln;
    	tx_arp_hdr->ar_op = htons(rx_arp_hdr->ar_op);

    	for (i = 0; i < ETHER_ADDR_LEN; i++){
    		tx_arp_hdr->ar_sha[i] = ((uint8_t)(rx_if->addr[i]));
    	}

    	tx_arp_hdr->ar_sip = rx_arp_hdr->ar_tip;

    	for (i = 0; i < ETHER_ADDR_LEN; i++){
    		tx_arp_hdr->ar_tha[i] = rx_arp_hdr->ar_sha[i];
    	}
    	tx_arp_hdr->ar_tip = rx_arp_hdr->ar_sip;

    	tx_packet = ((uint8_t*)(malloc(sizeof(sr_ethernet_hdr_t) + sizeof( sr_arp_hdr_t))));
    	memcpy(tx_packet, tx_e_hdr, sizeof(sr_ethernet_hdr_t));
    	memcpy(tx_packet + sizeof(sr_ethernet_hdr_t), tx_arp_hdr, sizeof( sr_arp_hdr_t));

    	print_hdr_arp((uint8_t*)(tx_packet));
    	sr_send_packet(sr, ((uint8_t*)(tx_packet)), sizeof(sr_ethernet_hdr_t) + sizeof(sr_arp_hdr_t), rx_if->name);

    	free(tx_packet);
    	free(tx_arp_hdr);
    	free(tx_e_hdr);
    	/*while(cur != NULL){
    		if(cur->ip == arp_header->ar_tip){
    	        /*uint8_t *new_pkt = malloc(sizeof(struct sr_ether_header_t) + sizeof(struct sr_header_t));
    	        sr_ethernet_hdr_t *packet_header = (sr_ethernet_hdr_t *) packet;
    	        memcpy(packet_header->ether_dhost, arp_header->
    			sr_send_packet(sr, packet, len, interface);
    			free(new_pkt);
    			return;
    		}
    		cur = cur->next;
    	}*/
    	printf("reached here");
    	return;
    }else if(htons(rx_arp_hdr->ar_op) == arp_op_reply){
    	/* Since the packet is ARP reply, it is required to send
    	 * back the the sender to let it know the MAC address of the
    	 * destination where the sender wants to know. */
    	Debug("*** -> Address Resolution Protocol reply \n");

    }
}/* end sr_handlepacket_arp */

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
        sr_ethernet_hdr_t *header){

}/* end sr_handlepacket_ip */
