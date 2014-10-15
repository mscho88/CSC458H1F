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
 * Protocol. The router is required to send the reply packet to the
 * sender back (this is what the sender wants). Hence, the router
 * firstly look up the ARP cache and the interfaces what the router
 * knows. Otherwise, the router broadcast to the adjacent routers.
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

	/* Set the packet to the ARP header */
	sr_arp_hdr_t* arp_header = ((sr_arp_hdr_t*)(packet + sizeof(sr_ethernet_hdr_t)));

    if(htons(arp_header->ar_op) == arp_op_request){
    	Debug("*** -> Address Resolution Protocol Request \n");

    	/* When the router receives ARP request, it is required to
    	 * check the ARP cache first whether the router already knows
		 * the request for the sender. Also, the router keeps track of
		 * ARP cache of the sender on ARP request. */
    	printf(" sender information : %s \n", arp_header->ar_sha);
    	print_addr_ip_int(arp_header->ar_sip);
    	if(sr_arpcache_insert(&(sr->cache), arp_header->ar_sha, arp_header->ar_sip) == NULL){
    	    fprintf(stderr, "Failed on inserting the sender information : \n");
    	}

    	struct sr_arpentry *is_have = sr_arpcache_lookup(&(sr->cache), arp_header->ar_tip);
    	if(is_have->valid){
    		/* If the router finds the valid ARP cache which is the
    		 * MAC address of the sender wants, then sends back to
    		 * the packet to the sender.*/
    		/*********send the packet back to the sender*********/
    		printf("The router needs to send back the packet with ARP reply. \n");
    		return;
    	}

    	/* If the router does not have any valid MAC address to respond
    	 * to the sender, ..*/

    	/* Firstly, the router tries to look up the router among the
		 * interfaces.*/
    	struct sr_if *interfaces = sr_get_interface(sr, interface);
    	struct sr_if *cur = interfaces;
    	printf("before the while loop\n");
    	while(cur != NULL){
        	printf("in the while loop\n");
    		if(cur->ip == arp_header->ar_tip){
    			/* Since there does not exist the destination ARP cache,
    			 * above ARP cache looking up failed. Hence, the router
    			 * is required to learn the destination and store the
    			 * information in the ARP cache. */
    			if(sr_arpcache_insert(&(sr->cache), cur->addr, cur->ip) == NULL){
    				printf("hello world11\n");
    				fprintf(stderr, "Failed on inserting the sender information : \n");
    			}
        		/*********send the packet back to the sender*********/

        		printf("The router needs to send back the packet with ARP reply. \n");
    			return;
    		}
    		cur = cur->next;
    	}

    	printf("after the while loop\n");

    	/* Since the router could not find the valid interface, the
		 * router needs to broadcast the packet to adjacent routers.
		 * Sending the packet to the sender is unnecessary as if
		 * statement refers.*/
    	cur = interfaces;
    	while(cur != 0){
    		if(cur->ip != arp_header->ar_sip){
        		/*********send the packet back to the sender*********/

        		printf("The router needs to send the packet with ARP request to adjacent routers. \n");
    		}
    		cur = cur->next;
    	}
    	printf("Reached the End of ARP request. \n");
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
        char* interface){

}/* end sr_handlepacket_ip */
