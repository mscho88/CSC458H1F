#include "sr_if.h"
#include "sr_rt.h"
#include "sr_router.h"
#include "sr_protocol.h"
#include "sr_arpcache.h"
#include "sr_utils.h"

void send_arp_packet(struct sr_instance* , uint8_t* , unsigned int , char* );

void build_ether_header(uint8_t *_packet, uint8_t *destination, struct sr_if* interfaces){

void build_arp_header(uint8_t *, sr_arp_hdr_t* , struct sr_if* );
