#ifndef P2POOL_LOCAL_STATS_H
#define P2POOL_LOCAL_STATS_H

#include <stdint.h>
#include <stdbool.h>
#include "elist.h"
#include <pthread.h>


#define MAX_URL_SIZE 512 
struct p2pool_stats_t
{
	double score;
	double last_ping_time;
	bool knocked_out;
	char  name[MAX_URL_SIZE];
	char  port[MAX_URL_SIZE];
	char  short_url[MAX_URL_SIZE];
	char  url[MAX_URL_SIZE];
	double block_value;
	double fee;
	double donation_proportion;
};

struct p2pool_list {
	struct list_head head;
	bool frozen;
	uint64_t num_entries;
	pthread_mutex_t mutex;
};

int get_p2pool_local_stats(struct p2pool_stats_t * stats, char * pool_short_url);
int  get_p2pool_info_from_scanner(struct p2pool_list *l);
int update_all_p2p_info(struct p2pool_list *l);
struct p2pool_list * new_p2pool_list(void);
void p2pool_list_free(struct p2pool_list *l);
struct p2pool_stats_t * p2pool_list_get_valid_pool(struct p2pool_list *l);
void p2pool_list_free(struct p2pool_list *l);
bool p2pool_list_push(struct p2pool_list * l, struct p2pool_stats_t *stats);

#endif //P2POOL_LOCAL_STATS_H
