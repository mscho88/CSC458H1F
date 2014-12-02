
#include <signal.h>
#include <assert.h>
#include "sr_nat.h"
#include <unistd.h>
#include <stdlib.h>
#include <string.h>


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
  nat->id = 0;
  /* Initialize any variables here */

  return success;
}


int sr_nat_destroy(struct sr_nat *nat) {  /* Destroys the nat (free memory) */

  pthread_mutex_lock(&(nat->lock));

  /* free nat memory here */

  pthread_kill(nat->thread, SIGKILL);
  return pthread_mutex_destroy(&(nat->lock)) &&
    pthread_mutexattr_destroy(&(nat->attr));

}

void *sr_nat_timeout(void *nat_ptr) {  /* Periodic Timout handling */
  struct sr_nat *nat = (struct sr_nat *)nat_ptr;
  while (1) {
    sleep(1.0);
    pthread_mutex_lock(&(nat->lock));

    time_t curtime = time(NULL);

    /* handle periodic tasks here */

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
  struct sr_nat_mapping *cur = nat->mappings;
  while(cur != NULL){
	  if(cur->aux_ext == aux_ext && cur->type == type){
		  cur->last_updated = time(NULL);
		  copy = malloc(sizeof(struct sr_nat_mapping));
		  memcpy(copy, cur, sizeof(struct sr_nat_mapping));
		  pthread_mutex_unlock(&(nat->lock));
		  return copy;
	  }
	  cur = cur->next;
  }

  pthread_mutex_unlock(&(nat->lock));
  return copy;
}

/* Get the mapping associated with given internal (ip, port) pair.
   You must free the returned structure if it is not NULL. */
struct sr_nat_mapping *sr_nat_lookup_internal(struct sr_nat *nat,
  uint32_t ip_int, uint16_t aux_int, sr_nat_mapping_type type ) {

  pthread_mutex_lock(&(nat->lock));

  /* handle lookup here, malloc and assign to copy. */
  struct sr_nat_mapping *copy = NULL;
  struct sr_nat_mapping *cur = nat->mappings;
  while(cur != NULL){
	  if(cur->ip_int == ip_int && cur->aux_int == aux_int && cur->type == type){
		  /* Copy the current mapping and return */
          cur->last_updated = time(NULL);
		  copy = malloc(sizeof(struct sr_nat_mapping));
          memcpy(copy, cur, sizeof(struct sr_nat_mapping));
          pthread_mutex_unlock(&(nat->lock));
          return copy;
	  }
	  cur = cur->next;
  }
  pthread_mutex_unlock(&(nat->lock));
  return copy;
}

/* Insert a new mapping into the nat's mapping table.
   Actually returns a copy to the new mapping, for thread safety.
 */
struct sr_nat_mapping *sr_nat_insert_mapping(struct sr_nat *nat,
  uint32_t ip_int, uint16_t aux_int, sr_nat_mapping_type type ) {

  pthread_mutex_lock(&(nat->lock));

  /* handle insert here, create a mapping, and then return a copy of it */
  struct sr_nat_mapping *mapping = NULL;

  mapping = malloc(sizeof(struct sr_nat_mapping));
  mapping->aux_int = aux_int;
  if (type == nat_mapping_icmp){
	  /* ICMP id */
	  mapping->aux_ext = 0;
	  mapping->conns = NULL;
  }else if(type == nat_mapping_tcp){
	  /* Internal port and external port */
	  /* TODO */
	  mapping->aux_ext = nat->external_port;
	  mapping->conns = NULL;
  }
  mapping->ip_ext = nat->external_ip;
  mapping->ip_int = ip_int;
  mapping->last_updated = time(NULL);
  mapping->type = type;

  /* Insert newly built mapping to the mappings */
  /*struct sr_nat_mapping temp = nat->mappings;*/
  mapping->next = nat->mappings;
  nat->mappings = mapping;

  pthread_mutex_unlock(&(nat->lock));
  return mapping;
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
