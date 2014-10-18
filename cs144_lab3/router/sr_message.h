
#ifndef SR_MESSAGE_H
#define SR_MESSAGE_H

#include <stdio.h>
#include <assert.h>

#include "sr_if.h"
#include "sr_rt.h"
#include "sr_router.h"
#include "sr_protocol.h"
#include "sr_arpcache.h"
#include "sr_utils.h"

void send_arp_packet(struct sr_instance*, uint8_t*, unsigned int, char*);
void send_ip_packet(struct sr_instance*, uint8_t*, char*, uint16_t, uint16_t);

void build_ether_header(uint8_t *_packet, uint8_t *addr, struct sr_if* interfaces, uint16_t protocol);
void build_arp_header(uint8_t *, sr_arp_hdr_t* , struct sr_if* );
void build_ip_header(uint8_t *, sr_ip_hdr_t* , struct sr_if* );
void build_icmp_header(uint8_t *, uint8_t *, sr_ip_hdr_t *, sr_icmp_hdr_t* , struct sr_if* , uint16_t , uint16_t );

#endif /* SR_MESSAGE_H */
