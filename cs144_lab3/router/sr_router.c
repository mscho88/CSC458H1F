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

  /*printf("packet is %u\n", packet);*/
  /*printf("interface is %s\n", interface);*/
  print_addr_eth(packet);
  ethertype(packet);
  /* When the router receives any packet, it should be determined what type of the protocol is. Hence, */
  /*sr_ethernet_hdr_t *header = (sr_ethernet_hdr_t *) packet;
  uint16_t ethernet_protocol_type = ntohs(header->ether_type);

  if(ethernet_protocol_type == ip_protocol_icmp){

  }else if(ethernet_protocol_type == ethertype_arp){

  }else if(ethernet_protocol_type == ethertype_ip){

  }*/
      /*switch (ethernet_protocol_type)
      {
          case sr_ip_protocol:
          {
              Check whether IP or ICMP
              break;
          }
          case ETHERTYPE_ARP:
          {
              sr_arp_hdr_t *arp_header = (sr_arp_hdr_t *)(packet + sizeof(sr_ethernet_hdr_t));
              unsigned short opcode = arp_header->ar_op;
              if (opcode == ARP_REQUEST)
              {
                  // Unicast ARP reply back to requester if Target Protocol Address == any of
                  // the ip's in if_list
                  sr_handle_received_arpreq(sr, arp_header);
              }
              else if (opcode == ARP_REPLY)
              {
                  sr_handle_arpreply(sr, arp_header);
              }
              break;
          }
          default:
              break;
      }*/
  /* fill in code here */

}/* end sr_ForwardPacket */

