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
  struct sr_if *interfaces = sr_get_interface(sr, interface);

  /*sr_print_if_list(sr);
  printf("hahaha\n");
  sr_print_if(interfaces->next);*/
  /*
  struct sr_if *cur = interfaces;
  while(cur != NULL){
	  for(int i = 0; i < ETHER_ADDR_LEN; i++){
		  if(packet_header->ether_dhost[i] == ){

		  }
	  }
	  cur = cur->next;
  }*/

  /* When the router receives any packet, it should be determined what
   * type of the protocol is. After that, it is required to figure out
   * where to send the packet by comparing the address in the routing
   * table. It may drop the packet if there exists no address to send.
   */

/*
  printf(" Packet detail ... \n");
  printf(" Source : ");
  print_addr_eth(packet_header->ether_shost);
  printf(" Destination : ");
  print_addr_eth(packet_header->ether_dhost);
  printf(" *****************\n;");
*/
  uint16_t ethernet_protocol_type = htons(packet_header->ether_type);

  if(ethernet_protocol_type == ethertype_arp){
  	  Debug("*** -> Received Address Resolution Protocol \n");
  	  sr_handlepacket_arp(sr, packet, len, interface, packet_header);
  }else if(ethernet_protocol_type == ethertype_ip){
	  Debug("*** -> Received Internet Protocol \n");
	  sr_handlepacket_ip(sr, packet, len, packet_header);
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
        uint8_t * packet,
        unsigned int len,
		char* interface,
        struct sr_ethernet_hdr_t *header){

	/* Set the packet to the ARP header */
    struct sr_arp_hdr* arp_header = ((struct sr_arp_hdr*)(packet + sizeof(struct sr_ethernet_hdr)));

    if(htons(arp_header->ar_op) == arp_op_request){
    	/* Since the packet is ARP request, it is required to broadcast
    	 * to the devices where the router knows. */
    	Debug("*** -> Address Resolution Protocol Request \n");
    	sr_send_packet(sr, packet, len, interface);
    	/* To transmit the packet, the router needs to copy the packet
		 * locally to protect the loss of the data in the packet.*/
    }else if(htons(arp_header->ar_op) == arp_op_reply){
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
        struct sr_ethernet_hdr_t *header){

}/* end sr_handlepacket_ip */
