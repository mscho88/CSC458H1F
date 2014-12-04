#include <signal.h>
#include <assert.h>
#include "sr_nat.h"
#include "sr_protocol.h"
#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>


int sr_nat_init(struct sr_nat *nat) { /* Initializes the nat */

    assert(nat);

    /* Acquire mutex lock */
    pthread_mutexattr_init(&(nat->attr));
    pthread_mutexattr_settype(&(nat->attr), PTHREAD_MUTEX_RECURSIVE);
    int success = pthread_mutex_init(&(nat->lock), &(nat->attr));

    /* Initialize timeout thread */

    pthread_attr_init(&(nat->thread_attr));
    pthread_attr_setdetachstate(&(nat->thread_attr), PTHREAD_CREATE_JOINABLE);
    pthread_attr_setscope(&(nat->thread_attr), PTHREAD_SCOPE_SYSTEM);
    pthread_attr_setscope(&(nat->thread_attr), PTHREAD_SCOPE_SYSTEM);
    pthread_create(&(nat->thread), &(nat->thread_attr), sr_nat_timeout, nat);

    /* CAREFUL MODIFYING CODE ABOVE THIS LINE! */

    nat->mappings = NULL;
    nat->icmp_query = 60;
    nat->tcp_establish = 7440;
    nat->tcp_transitory = 300;
    nat->auxCounter = 0;
    nat->nat_external_ip = 0;

    /* Initialize any variables here */

    return success;
}


int sr_nat_destroy(struct sr_nat *nat){
    /* Destroys the nat (free memory) */
    pthread_mutex_lock(&(nat->lock));

    /* free nat memory here */

    /* declare mapping variable */
    struct sr_nat_connection *currentConns;
    struct sr_nat_connection *wasteConns;
    struct sr_nat_mapping *wasteMapping;
    struct sr_nat_mapping *current = nat->mappings;


    while(current)
    {
        currentConns = current->conns;
        while(currentConns)
        {
            wasteConns = currentConns;
            currentConns = currentConns->next;
            free(wasteConns);
        }
        wasteMapping = current;
        current = current->next;
        free(wasteMapping);
    }


    pthread_kill(nat->thread, SIGKILL);
    return pthread_mutex_destroy(&(nat->lock)) &&
        pthread_mutexattr_destroy(&(nat->attr));
}
/*---------------------------------------------------------------------
 * Method: sr_dismiss_mapping(struct sr_nat *, struct sr_nat_mapping *,
 * 								struct sr_nat_mapping *);
 * Scope:  Local
 *
 * If cur is the first mapping, then prev must be NULL. Hence,
 * nat_mappings should be the next element of the cureent one.
 * Otherwise, the next of prev should point the next mapping of
 * the current one.
 *
 *---------------------------------------------------------------------*/
void sr_dismiss_mapping(struct sr_nat *nat, struct sr_nat_mapping *prev_map,struct sr_nat_mapping *cur_map){
	if (prev_map == NULL){
		nat->mappings = cur_map->next;
	}else{
		prev_map->next = cur_map->next;
	}
}

void *sr_nat_timeout(void *nat_ptr) {  /* Periodic Timeout handling */

    struct sr_nat *nat = (struct sr_nat *)nat_ptr;
    while (1) {
        sleep(1.0);
        pthread_mutex_lock(&(nat->lock));

        time_t curtime = time(NULL);

        struct sr_nat_mapping *prev_map     = NULL;
        struct sr_nat_mapping *cur_map = nat->mappings;

        struct sr_nat_connection *cur_conn  = NULL;
        struct sr_nat_connection *prev_conn    = NULL;

        while(cur_map){
        	if(cur_map->type == nat_mapping_icmp && nat->icmp_query < (curtime - cur_map->last_updated)){
        		sr_dismiss_mapping(nat, prev_map, cur_map);

				/* Destroy the current mapping. */
		        struct sr_nat_mapping *exp_entry = cur_map;
				cur_map = cur_map->next;
				free(exp_entry);
				continue;

            }else if(cur_map->type == nat_mapping_tcp){
                cur_conn = cur_map->conns;
                while(cur_conn){
					if(nat->tcp_establish < curtime - cur_conn->last_updated && cur_conn->state == tcp_state_established){
						if(prev_conn){
							prev_conn->next = cur_conn->next;
						}else{
							cur_map->conns = cur_conn->next;
							if(cur_map->conns == NULL){
								sr_dismiss_mapping(nat, prev_map, cur_map);
							}
						}
					}else if (nat->tcp_transitory < curtime - cur_conn->last_updated){
						if(prev_conn){
							prev_conn->next = cur_conn->next;
						}else{
							cur_map->conns = cur_conn->next;
							if(cur_map->conns == NULL){
								sr_dismiss_mapping(nat, prev_map, cur_map);
							}
						}
					}

					prev_conn = cur_conn;
					cur_conn = cur_conn->next;
                }
            }else{
            	prev_map = cur_map;
            	cur_map = cur_map->next;
            }
        }
        pthread_mutex_unlock(&(nat->lock));
    }
    return NULL;
}

/* Get the mapping associated with given external port.
   You must free the returned structure if it is not NULL. */
struct sr_nat_mapping *sr_nat_lookup_external(struct sr_nat *nat,
        uint16_t aux_ext, sr_nat_mapping_type type ) {

    pthread_mutex_lock(&(nat->lock));

    /* handle lookup here, malloc and assign to copy */
    struct sr_nat_mapping *copy = NULL;

    struct sr_nat_mapping *current = nat->mappings;
    while(current){
        if(current->type == type && current->aux_ext == aux_ext){
            copy = malloc(sizeof(struct sr_nat_mapping));
            copy->type = current->type;
            copy->ip_int = current->ip_int;
            copy->ip_ext = current->ip_ext;
            copy->aux_int = current->aux_int;
            copy->aux_ext = current->aux_ext;
            copy->last_updated = current->last_updated;
            copy->conns = current->conns;
            copy->next = current->next;
            pthread_mutex_unlock(&(nat->lock));

            return copy;
        }
        current = current->next;
    }

    pthread_mutex_unlock(&(nat->lock));
    printf("Nothing matches aux %i\n", aux_ext);
    return copy;
}

/* Get the mapping associated with given internal (ip, port) pair.
   You must free the returned structure if it is not NULL. */
struct sr_nat_mapping *sr_nat_lookup_internal(struct sr_nat *nat,
        uint32_t ip_int, uint16_t aux_int, sr_nat_mapping_type type ) {

    pthread_mutex_lock(&(nat->lock));

    /* handle lookup here, malloc and assign to copy. */
    struct sr_nat_mapping *copy = NULL;

    struct sr_nat_mapping *current = nat->mappings;
    while(current){
        if(current->type == type && current->ip_int == ip_int && current->aux_int == aux_int){
            copy = malloc(sizeof(struct sr_nat_mapping));
            copy->type = current->type;
            copy->ip_int = current->ip_int;
            copy->ip_ext = current->ip_ext;
            copy->aux_int = current->aux_int;
            copy->aux_ext = current->aux_ext;
            copy->last_updated = current->last_updated;
            copy->conns = current->conns;
            copy->next = current->next;
            pthread_mutex_unlock(&(nat->lock));

            return copy;
        }
        current = current->next;
    }

    pthread_mutex_unlock(&(nat->lock));
    return copy;
}

/* Insert a new mapping into the nat's mapping table.
   Actually returns a copy to the new mapping, for thread safety.
 */
struct sr_nat_mapping *sr_nat_insert_mapping(struct sr_nat *nat,
        uint32_t ip_int, uint16_t aux_int, sr_nat_mapping_type type ) {

    /* Check Params */
    assert(nat);
    assert(ip_int);
    assert(aux_int);

    pthread_mutex_lock(&(nat->lock));

    /* handle insert here, create a mapping, and then return a copy of it */
    struct sr_nat_mapping *mapping = malloc(sizeof(struct sr_nat_mapping));

    mapping->ip_int = ip_int;
    mapping->aux_int = aux_int;
    mapping->ip_ext = nat->nat_external_ip;
    mapping->aux_ext = sr_nat_genAux(nat);
    mapping->last_updated = time(NULL);
    mapping->conns = NULL;
    mapping->type = type;
    mapping->next = nat->mappings;
    nat->mappings = mapping;


    pthread_mutex_unlock(&(nat->lock));
    return mapping;
}

uint32_t sr_nat_genAux(struct sr_nat *nat){

    assert(nat);

    uint32_t retn;
    retn = nat->auxCounter + 1024;
    nat->auxCounter = ((nat->auxCounter+1)%64500);
    return retn;
}


void print_nat_mappings(struct sr_nat *nat){

    assert(nat);

    struct sr_nat_mapping *mapping = nat->mappings;
    while(mapping){
        printf("************************\n");
        printf("\nip_int: ");
        print_addr_ip_int(htonl(mapping->ip_int));
        printf("\naux_int: %d\n", mapping->aux_int);
        printf("\nip_ext: ");
        print_addr_ip_int(htonl(mapping->ip_ext));
        printf("\naux_ext: %d\n", mapping->aux_ext);
        printf("\n type: %i",mapping->type);

        mapping = mapping->next;
    }

    return;
}

struct sr_nat_connection* sr_nat_lookup_connection(
  struct sr_nat* nat,
  struct sr_nat_mapping* mapping,
  uint32_t ip_src, uint32_t ip_dest,
  uint32_t src_seq,uint16_t port_dest){

    pthread_mutex_lock(&(nat->lock));

    assert(mapping);
    struct sr_nat_connection* walker = mapping->conns;
    while(walker !=  NULL){
        if((ip_src == walker->ip_src) &&
         (ip_dest == walker->ip_dest) &&
         (port_dest == walker->port_dest) &&
         (src_seq == walker->src_seq)){
            pthread_mutex_unlock(&(nat->lock));

            return walker;
        }
        walker = walker->next;
    }

    pthread_mutex_unlock(&(nat->lock));

    return NULL;
}




/*---------------------------------------------------------------------
 * Method: build_connections(sr_ip_hdr_t *, sr_tcp_hdr_t *)
 * Scope:  Local
 *
 * This method build connections in case of TCP protocol. In case of
 * ICMP protocol, building connections is not required. Connections
 * are set to be NULL.
 *
 * NOTE : ICMP protocl will not call this function.
 *
 *---------------------------------------------------------------------*/
struct sr_nat_connection *build_connections(sr_ip_hdr_t *ip_hdr, sr_tcp_hdr_t *tcp_hdr){
	struct sr_nat_connection *conn = (struct sr_nat_connection *)malloc(sizeof(struct sr_nat_connection));
	conn->ip_src = ip_hdr->ip_src;
	conn->src_seq = tcp_hdr->sequence_num;
	conn->ip_dest = ip_hdr->ip_dst;
	conn->port_dest = tcp_hdr->dest_port;
	conn->last_updated = time(NULL);
	conn->state = tcp_state_syn_sent;
	return conn;
}
