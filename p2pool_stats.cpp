#include <curl/curl.h>
#include <jansson.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <math.h>
#include "p2pool_stats.h"

#define SCANNER_URL "https://scanner.vtconline.org/urls"
#define NETWORK1_PORT_STR "9171"
#define NETWORK2_PORT_STR "9181"
#define COLON_STR ":"
#define STRATUM_TCP_STR  "stratum+tcp://"
#define LOCAL_STATS_TIMEOUT  20000
#define POOL_PING_STATS_TIMEOUT  500
#define SCANNER_TIMEOUT 20000

struct  p2p_list_ent {
	struct p2pool_stats_t * stats;
	struct list_head p2p_list_node;
};


struct MemoryStruct {
	char *memory;
	size_t size;
};

double randfrom(double min, double max) 
{
    double range = (max - min); 
    double div = RAND_MAX / range;
    return min + (rand() / div);
}

static size_t WriteMemoryCallback(void *contents, size_t size, size_t nmemb, void *userp)
{
	size_t realsize = size * nmemb;
	struct MemoryStruct *mem = (struct MemoryStruct *)userp;

	mem->memory = (char *) realloc(mem->memory, mem->size + realsize + 1);
	if (mem->memory == NULL) {
		printf("not enough memory\n");
		return 0;
	}

	memcpy(&(mem->memory[mem->size]), contents, realsize);
	mem->size += realsize;
	mem->memory[mem->size] = 0;

	return realsize; 
}

char *curl_get_response(char *url, long timeout)
{
	CURL *curl_handle;
	CURLcode res;
	char *ret = NULL;
	
	struct MemoryStruct chunk;
	
	chunk.memory = (char *) malloc(1);
	if (!chunk.memory)
		return NULL;

	chunk.size = 0;

	curl_handle = curl_easy_init();
	if (!curl_handle)
		return NULL;

	curl_easy_setopt(curl_handle, CURLOPT_TIMEOUT_MS, timeout);
	curl_easy_setopt(curl_handle, CURLOPT_URL, url);
	curl_easy_setopt(curl_handle, CURLOPT_WRITEFUNCTION, WriteMemoryCallback);
	curl_easy_setopt(curl_handle, CURLOPT_WRITEDATA, (void *) &chunk);
	curl_easy_setopt(curl_handle, CURLOPT_USERAGENT, "libcurl-agent/1.0");

	res = curl_easy_perform(curl_handle);
	curl_easy_cleanup(curl_handle);

	if (res != CURLE_OK) {
		free(chunk.memory);
		return ret;
	}
	else
	{
		ret = strdup(chunk.memory);
		free(chunk.memory);
	}
	return ret;
}



json_t * curl_get_response_and_digest(char * url, long timeout)
{
	char *text =  NULL;
	json_t *root = NULL;;
	json_error_t error;
	
	text = curl_get_response(url, timeout);
	if (!text)
		return NULL;

	root = json_loads(text, 0, &error);
	free(text);
	
	if (!root)
	{
		fprintf(stderr, "error decoding JSON from %s\n", url);
		fprintf(stderr, "error on line %d: %s\n", error.line, error.text);
		return NULL;
	}

	return root;
}

char * concat_url(char *pool_url, char * r)
{
	char * rc = (char *) malloc(MAX_URL_SIZE);
	if (!rc)
		return NULL;
	strcpy(rc, pool_url);
	strcat(rc, r);

	return rc;
}

json_t * get_p2pool_local_stats_json(char *pool_short_url) 
{
	json_t * root = NULL;

	char * local_stat_ending = strdup("/local_stats");
	if (!local_stat_ending)
		return NULL;

	char * url = concat_url(pool_short_url, local_stat_ending);
	if (!url)
	{
		free(local_stat_ending);
		return NULL;
	}

	root = curl_get_response_and_digest(url, LOCAL_STATS_TIMEOUT);
	free(url);
	free(local_stat_ending);

	return root;
}

int get_p2pool_local_stats(struct p2pool_stats_t * stats, char * pool_short_url)
{
	json_t * root = get_p2pool_local_stats_json(pool_short_url);
	if (!root)
		return -1;
		
	if (json_unpack(root, "{sF,sF,sF}", "block_value", &stats->block_value, "fee", &stats->fee, "donation_proportion", &stats->donation_proportion))
	{
		json_decref(root);
		return -1;

	}
	json_decref(root);
	return 0;
}

int  poor_man_ping_pool_ms(double *ms, char * pool_short_url)
{
	clock_t t;
	char * fee_ending = strdup("/fee");
	if (!fee_ending)
		return -1;
	char * url = concat_url(pool_short_url, fee_ending);
	if (!url)
	{
		free(fee_ending);
		return -1;
	}
		
	t = clock();
	char * data = curl_get_response(url, POOL_PING_STATS_TIMEOUT);
	t = clock() - t;

	if (!data)
	{
		free(fee_ending);
		free(url);
		return -1;
	}
	free(url);
	free(fee_ending);
	free(data);

	* ms = (((double) t) * 1000) / (CLOCKS_PER_SEC);
	return 0;
}

struct  p2pool_list * new_p2pool_list(void)
{
	struct p2pool_list * p2pl;
	p2pl = (struct p2pool_list *)calloc(1, sizeof(*p2pl));
	if (!p2pl)
		return NULL;

	INIT_LIST_HEAD(&p2pl->head);
	pthread_mutex_init(&p2pl->mutex, NULL);
	return p2pl;
}


bool p2pool_list_push(struct p2pool_list * l, struct p2pool_stats_t *stats)
{
	struct p2p_list_ent *ent;
	bool rc = true;
	if (!stats)
		return false;
	
	ent = (struct p2p_list_ent *)calloc(1, sizeof(*ent));
	if (!ent)
		return false;
	
	ent->stats = stats;
	INIT_LIST_HEAD(&ent->p2p_list_node);
	pthread_mutex_lock(&l->mutex);
	
	list_add_tail(&ent->p2p_list_node, &l->head);
	l->num_entries++;
	pthread_mutex_unlock(&l->mutex);
	return rc;
}

void p2pool_list_free(struct p2pool_list *l)
{
	struct p2p_list_ent *ent, *iter;
	if (!l)
		return;
	
	list_for_each_entry_safe(ent, iter, &l->head, p2p_list_node, struct p2p_list_ent, struct p2p_list_ent)
	{
		list_del(&ent->p2p_list_node);
		if (ent->stats)
			free(ent->stats);
		free(ent);
	}
	pthread_mutex_destroy(&l->mutex);
	memset(l, 0, sizeof(&l));
	free(l);
}




int get_p2pool_info_from_scanner(struct p2pool_list *l)
{
	json_t * data = NULL;
	bool at_least_one_pool_found = false;
	char * scanner_url = strdup(SCANNER_URL);
	uint32_t count=0;
	
	if (!scanner_url)
		return -1;
	
	data = curl_get_response_and_digest(scanner_url, SCANNER_TIMEOUT);
	if (!data)
	{
		free(scanner_url);
		return -1;
	}

	size_t num_urls = json_array_size(data);

	if (!num_urls)
	{
		json_decref(data);
		return -1;
	}
	
	for (uint32_t iter = 0; iter < num_urls; iter++)
	{
		json_t * p = json_array_get(data, iter);
		if (!json_is_string(p))
		{
			continue;
		}

		struct p2pool_stats_t * stats = (struct p2pool_stats_t *) calloc(1, sizeof(*stats));
		if (!stats)
		{
			json_decref(p);
			json_decref(data);
			return -1;
		}
		const char  *ip;
		json_unpack(p, "s", &ip);
		strcpy(stats->name, ip);

		char * colon_str = strdup(COLON_STR);
		char * stratum_tcp_str = strdup(STRATUM_TCP_STR);
		char * network1_str = strdup(NETWORK1_PORT_STR);
		char * network2_str = strdup(NETWORK1_PORT_STR);

		strcpy(stats->short_url, stats->name);
		strcat(stats->short_url, colon_str);
		strcat(stats->short_url, network1_str);
		strcpy(stats->url, stratum_tcp_str);
		strcat(stats->url, stats->short_url);
		strcat(stats->port, network1_str);
			
		free(colon_str);
		free(stratum_tcp_str);
		free(network1_str);
		free(network2_str);
		
		if (p2pool_list_push(l, stats))
		{
			at_least_one_pool_found = true;
		}
	}

	json_decref(data);
	return (at_least_one_pool_found) ? 0:1;
}

int update_pool_info(struct p2pool_stats_t *s)
{
	return get_p2pool_local_stats(s, s->short_url);
}

void print_p2pool_stats(struct p2pool_stats_t *s)
{
	printf("SHORT_URL:%s SCORE:%f ping:%f block_value:%f fee:%f donation:%f\n", s->short_url, s->score, s->last_ping_time, s->block_value, s->fee, s->donation_proportion);
}

int update_all_p2p_info(struct p2pool_list *l)
{
	int rc = 0;
	struct p2p_list_ent *ent, *iter;
	if (!l)
		return - 1;
	
	list_for_each_entry_safe(ent, iter, &l->head, p2p_list_node, struct p2p_list_ent, struct p2p_list_ent)
	{
		int int_rc = 0;
		
		if (poor_man_ping_pool_ms(&ent->stats->last_ping_time, ent->stats->short_url))
		{
			continue;
		}

		int_rc |= get_p2pool_local_stats(ent->stats, ent->stats->short_url);
		rc |= int_rc;
		if (int_rc)
		{
			printf("ERROR, failed to update stats for %s\n", ent->stats->short_url);
		}
		else	
		{
			print_p2pool_stats(ent->stats);
		}
	}
	return rc;
}

struct p2pool_stats_t * p2pool_list_get_valid_pool(struct p2pool_list *l)
{
	struct p2p_list_ent *ent, *iter;
	struct p2pool_stats_t *best_so_far = NULL;
	double average_ping = 0;
	double  num_pings = 0;

	// clear all knockouts
	list_for_each_entry_safe(ent, iter, &l->head, p2p_list_node, struct p2p_list_ent, struct p2p_list_ent)
		ent->stats->knocked_out = false;

	// walk thorugh pools and knock out any options that cannot be accessed.
	list_for_each_entry_safe(ent, iter, &l->head, p2p_list_node, struct p2p_list_ent, struct p2p_list_ent)
	{
		if (!ent->stats->knocked_out)
		{
			//if we cant access pool, knock out
			if (poor_man_ping_pool_ms(&ent->stats->last_ping_time, ent->stats->short_url))
			{
				ent->stats->knocked_out = true;
				continue;
			}

			//if we cant get pool info, knock out
			if (update_pool_info(ent->stats))
			{
				ent->stats->knocked_out = true;
				continue;
			}
		
			// if pool fee is greater than 2%, knock out
			if (ent->stats->fee > 2)
			{
				ent->stats->knocked_out = true;
				continue;
			}
			num_pings++;
			average_ping += ent->stats->last_ping_time;
		}
	}

	if (!average_ping)
	{
		return NULL;
	}

	average_ping = average_ping / num_pings;
	

	double average_score = 0;
	double num_scores = 0;
	// calculate first score
	list_for_each_entry_safe(ent, iter, &l->head, p2p_list_node, struct p2p_list_ent, struct p2p_list_ent)
	{
		if (!ent->stats->knocked_out)
		{
			ent->stats->score = (ent->stats->fee) + (ent->stats->donation_proportion*100) + (ent->stats->last_ping_time/average_ping);
			average_score  += ent->stats->score;
			num_scores++;
		}
	}
	average_score = average_score /  num_scores;

	double variance = 0;
	// calculate variance of score
	list_for_each_entry_safe(ent, iter, &l->head, p2p_list_node, struct p2p_list_ent, struct p2p_list_ent)
	{	
		if (!ent->stats->knocked_out)
		{
			double temp = pow(ent->stats->score - average_score, 2);
			variance += temp;
		}
	}
	variance = variance / (num_scores -1);
	double std_dev = sqrt(variance);

	// score each pool, the lower the score, the better
	list_for_each_entry_safe(ent, iter, &l->head, p2p_list_node, struct p2p_list_ent, struct p2p_list_ent)
	{	
		if (!ent->stats->knocked_out)
		{
			double random = randfrom(-std_dev/2, std_dev/2);
			ent->stats->score  += random;
			if ((!best_so_far) || (ent->stats->score <= best_so_far->score))
				best_so_far = ent->stats;
		}
	}

	return best_so_far;
}

struct p2pool_stats_t * p2pool_list_get_pool_from_url(struct p2pool_list *l ,char * short_url)
{
	struct p2p_list_ent *ent, *iter;
	list_for_each_entry_safe(ent, iter, &l->head, p2p_list_node, struct p2p_list_ent, struct p2p_list_ent)
	{
		if (strcmp(ent->stats->short_url, short_url) == 0)
			return ent->stats;
	}
	return NULL;
}

