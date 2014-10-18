#include "sr_packet.h"

#include <stdio.h>
#include <assert.h>

#include "sr_if.h"
#include "sr_rt.h"
#include "sr_router.h"
#include "sr_protocol.h"
#include "sr_arpcache.h"
#include "sr_utils.h"

/*---------------------------------------------------------------------
 * Method: send_arp_packet(struct sr_instance* sr, uint8_t* packet,
 * 							unsigned int len, char* interface)
 * Scope:  Local
 *
 * Send an ARP reply packet to the sender
 *
 *---------------------------------------------------------------------*/
void send_arp_packet(struct sr_instance* sr, uint8_t* packet, unsigned int len, char* interface){
	unsigned int length = sizeof(sr_ethernet_hdr_t) + sizeof(sr_arp_hdr_t);
	struct sr_if *interfaces = sr_get_interface(sr, interface);
	uint8_t* _packet = (uint8_t*)malloc(length);
	sr_ethernet_hdr_t* eth_header = (sr_ethernet_hdr_t *)packet;
	sr_arp_hdr_t* arp_header = (sr_arp_hdr_t*)(packet + sizeof(sr_ethernet_hdr_t));

	/* Build ARP Packet */
	build_ether_header(_packet, eth_header->ether_shost, interfaces, ethertype_arp);
	build_arp_header(_packet + sizeof(sr_ethernet_hdr_t), arp_header, interfaces);

	sr_send_packet(sr, (uint8_t*)_packet, length, interfaces->name);
	free(_packet);
}/* end send_arp_packet */

void send_ip_error_packet(struct sr_instance* sr, uint8_t* packet, char* interface, uint16_t type, uint16_t code){
	unsigned int length = sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t) + sizeof(sr_icmp_t3_hdr_t);
	struct sr_if *interfaces = sr_get_interface(sr, interface);

	uint8_t *_packet = (uint8_t *)malloc(length);

	sr_ethernet_hdr_t *eth_header = (sr_ethernet_hdr_t *)packet;
	sr_ip_hdr_t* ip_header = (sr_ip_hdr_t*)(packet + sizeof(sr_ethernet_hdr_t));
	sr_icmp_t3_hdr_t *icmp_header = (sr_icmp_t3_hdr_t *)(packet + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t));

	build_ether_header(_packet, eth_header->ether_shost, interfaces, ethertype_ip);
	build_ip_header(_packet + sizeof(sr_ethernet_hdr_t), ip_header, interfaces);
	build_icmp_t3_header(_packet + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t), packet, ip_header, icmp_header, interfaces, type, code);

	sr_send_packet(sr, (uint8_t *)_packet, length, interfaces->name);
	free(_packet);
}

/*---------------------------------------------------------------------
 * Method: build_ether_header(uint8_t *_packet,
 *							sr_ethernet_hdr_t* eth_orig_header,
 *							struct sr_if* interfaces)
 * Scope:  Local
 *
 * Build the ethernet header
 *
 *---------------------------------------------------------------------*/
void build_ether_header(uint8_t *_packet, uint8_t *addr, struct sr_if* interfaces, uint16_t protocol){
	sr_ethernet_hdr_t *eth_tmp_header = (sr_ethernet_hdr_t *)_packet;
	memcpy(eth_tmp_header->ether_dhost, addr, ETHER_ADDR_LEN);
	memcpy(eth_tmp_header->ether_shost, interfaces->addr, ETHER_ADDR_LEN);
	if(protocol == ethertype_arp){
		eth_tmp_header->ether_type = htons(ethertype_arp);
	}else if(protocol == ethertype_ip){
		eth_tmp_header->ether_type = htons(ethertype_ip);
	}
}/* end build_ether_header */

/*---------------------------------------------------------------------
 * Method: build_arp_header(uint8_t *_packet,
 * 							sr_arp_hdr_t* arp_orig_header,
 * 							struct sr_if* if_walker)
 * Scope:  Local
 *
 * Build the ARP header
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
}/* end build_arp_header */

/*---------------------------------------------------------------------
 * Method: sr_handlepacket_arp(struct sr_instance* sr,
 *      						uint8_t*  packet,
 *      						unsigned int len,
 *								char* interface)
 * Scope:  Local
 *
 * When the ethernet type is Address Resolution Protocol
 *
 *---------------------------------------------------------------------*/
void build_ip_header(uint8_t *_packet, sr_ip_hdr_t* ip_header, struct sr_if* interfaces){
	sr_ip_hdr_t* ip_tmp_header = (sr_ip_hdr_t *)_packet;
	ip_tmp_header->ip_v = ip_header->ip_v;
	ip_tmp_header->ip_hl = 5;/*ip_header->ip_hl;*/
	ip_tmp_header->ip_tos = 0;/*ip_header->ip_tos;*/
	ip_tmp_header->ip_len = htons(sizeof(sr_ip_hdr_t) + sizeof(sr_icmp_t3_hdr_t));

	ip_tmp_header->ip_src = interfaces->ip;
	ip_tmp_header->ip_dst = ip_header->ip_src;
	ip_tmp_header->ip_id = 0;
	ip_tmp_header->ip_off = 0;/*htons(ip_header->ip_off);*/
	ip_tmp_header->ip_ttl = ip_header->ip_ttl;
	ip_tmp_header->ip_p = ip_protocol_icmp;
	ip_tmp_header->ip_sum = 0;
	ip_tmp_header->ip_sum = cksum(ip_tmp_header, sizeof(sr_ip_hdr_t));
}

void build_icmp_header(uint8_t *_packet, uint8_t type, uint8_t code){
	sr_icmp_t3_hdr_t *icmp_tmp_hdr = (sr_icmp_t3_hdr_t *)_packet;
	icmp_tmp_hdr->icmp_type = type;
	icmp_tmp_hdr->icmp_code = code;
	icmp_tmp_hdr->icmp_sum = 0;
	icmp_tmp_hdr->icmp_sum = cksum(icmp_tmp_hdr, sizeof(sr_icmp_hdr_t));
}

void build_icmp_t3_header(uint8_t *_packet, uint8_t *packet, sr_ip_hdr_t *ip_header, sr_icmp_hdr_t* icmp_orig_header, struct sr_if* interfaces, uint8_t type, uint8_t code){
	sr_icmp_t3_hdr_t *icmp_tmp_hdr = (sr_icmp_t3_hdr_t *)_packet;
	icmp_tmp_hdr->icmp_type = type;
	icmp_tmp_hdr->icmp_code = code;
	memcpy(icmp_tmp_hdr->data, ip_header, 20);
	memcpy(icmp_tmp_hdr->data + 20, icmp_orig_header, 8);
	icmp_tmp_hdr->icmp_sum = 0;
	icmp_tmp_hdr->icmp_sum = cksum(icmp_tmp_hdr, sizeof(sr_icmp_t3_hdr_t));
}

void send_icmp_echo_packet(struct sr_instance* sr, uint8_t* packet, unsigned int len, char* interface) {
	uint8_t *_packet = (uint8_t *) malloc(len);
	memcpy(_packet, packet, len);
	struct sr_if *interfaces = (struct sr_if *)sr_get_interface(sr, interface);

	sr_ethernet_hdr_t *eth_header = (sr_ethernet_hdr_t *)_packet;
	sr_ip_hdr_t *ip_header = (sr_ip_hdr_t *)(_packet + sizeof(sr_ethernet_hdr_t));

	eth_header->ether_type = htons(ethertype_ip);
	uint8_t shost[ETHER_ADDR_LEN];
	memcpy(shost, interfaces->addr, ETHER_ADDR_LEN);
	uint8_t dhost[ETHER_ADDR_LEN];
	memcpy(dhost, eth_header->ether_shost, ETHER_ADDR_LEN);

	memcpy(eth_header->ether_shost, shost, ETHER_ADDR_LEN);
	memcpy(eth_header->ether_dhost, dhost, ETHER_ADDR_LEN);

	build_ip_header(_packet + sizeof(sr_ethernet_hdr_t), ip_header, interfaces);
	build_icmp_header((_packet + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t)), icmp_type0, icmp_code);

	sr_send_packet(sr, _packet, len, interface);
	free(_packet);
}

void send_arp_request(struct sr_instance *sr, uint32_t dst_ip, char *interface) {
	unsigned int len = sizeof(sr_ethernet_hdr_t) + sizeof(sr_arp_hdr_t);
	uint8_t *_packet = (uint8_t *)malloc(len);
	struct sr_if *interfaces = (struct sr_if *)sr_get_interface(sr, interface);

	sr_ethernet_hdr_t *ether_hdr = (sr_ethernet_hdr_t *)(_packet);
	ether_hdr->ether_type = htons(ethertype_arp);
	memcpy(ether_hdr->ether_shost, interfaces->addr, ETHER_ADDR_LEN);
	memcpy(ether_hdr->ether_dhost, Broadcast, ETHER_ADDR_LEN);

	sr_arp_hdr_t *arp_hdr = (sr_arp_hdr_t *)(_packet + sizeof(sr_ethernet_hdr_t));
	arp_hdr->ar_hrd = htons(arp_hrd_ethernet);
	arp_hdr->ar_pro = htons(ethertype_ip);
	arp_hdr->ar_pln = 4;
	arp_hdr->ar_hln = ETHER_ADDR_LEN;
	arp_hdr->ar_op = htons(arp_op_request);
	arp_hdr->ar_sip = interfaces->ip;
	memcpy(arp_hdr->ar_sha, interfaces->addr, ETHER_ADDR_LEN);
	memcpy(arp_hdr->ar_tha, Broadcast, ETHER_ADDR_LEN);
	arp_hdr->ar_tip = dst_ip;

	sr_send_packet(sr, _packet, len, interface);
	free(_packet);
}
