#ifndef SR_NAT_TABLE_H
#define SR_NAT_TABLE_H

#include <inttypes.h>
#include <time.h>
#include <pthread.h>
#include <string.h>
#include "sr_if.h"
#include "sr_utils.h"

typedef enum {
  nat_mapping_icmp,
  nat_mapping_tcp,
  nat_mapping_udp,
} sr_nat_mapping_type;

typedef enum {
    in2ex,
    ex2in,
} sr_nat_trans_type;

typedef enum {
    syn_sent,
    syn_recv,
    established,
    fin_wait1,
    fin_wait2,
    close_wait,
    time_wait,
    last_ack,
    closed,
} sr_tcp_state;


struct sr_nat_connection {
  /* add TCP connection state data members here */
  uint32_t ip_src;
  uint16_t src_seq;
  uint32_t ip_dest;
  uint16_t port_dest;
  time_t last_updated;
  sr_tcp_state state;

  struct sr_nat_connection *next;
};

struct sr_nat_mapping {
  sr_nat_mapping_type type;
  uint32_t ip_int; /* internal ip addr */
  uint32_t ip_ext; /* external ip addr */
  uint16_t aux_int; /* internal port or icmp id */
  uint16_t aux_ext; /* external port or icmp id */
  time_t last_updated; /* use to timeout mappings */
  struct sr_nat_connection *conns; /* list of connections. null for ICMP */
  struct sr_nat_mapping *next;
};

struct sr_nat {
  /* add any fields here */
  struct sr_nat_mapping *mappings;

  int icmp_query;
  int tcp_establish;
  int tcp_transitory;

  uint32_t port_id;
  uint32_t nat_external_ip;

  /* threading */
  pthread_mutex_t lock;
  pthread_mutexattr_t attr;
  pthread_attr_t thread_attr;
  pthread_t thread;
};


int   sr_nat_init(struct sr_nat *nat);     /* Initializes the nat */
int   sr_nat_destroy(struct sr_nat *nat);  /* Destroys the nat (free memory) */
void *sr_nat_timeout(void *nat_ptr);  /* Periodic Timout */

/* Get the mapping associated with given external port.
   You must free the returned structure if it is not NULL. */
struct sr_nat_mapping *sr_nat_lookup_external(struct sr_nat *nat,
    uint16_t aux_ext, sr_nat_mapping_type type );

/* Get the mapping associated with given internal (ip, port) pair.
   You must free the returned structure if it is not NULL. */
struct sr_nat_mapping *sr_nat_lookup_internal(struct sr_nat *nat,
  uint32_t ip_int, uint16_t aux_int, sr_nat_mapping_type type );

/* Insert a new mapping into the nat's mapping table.
   You must free the returned structure if it is not NULL. */
struct sr_nat_mapping *sr_nat_insert_mapping(struct sr_nat *nat,
  uint32_t ip_int, uint16_t aux_int, sr_nat_mapping_type type );

struct sr_nat_connection*
sr_nat_lookup_connection(struct sr_nat* nat, struct sr_nat_mapping* mapping,
  uint32_t ip_src, uint32_t ip_dest, uint32_t src_seq, uint16_t port_dest);


struct sr_nat_connection *build_connections(sr_ip_hdr_t *, sr_tcp_hdr_t *);
void sr_dismiss_mapping(struct sr_nat *, struct sr_nat_mapping *,struct sr_nat_mapping *);


#endif
