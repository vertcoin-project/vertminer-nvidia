#include "elist.h"
#include <stdlib.h>
#include <stdio.h>
#include <ctype.h>
#include "algos.h"
#include <string.h>
#include <unistd.h>
#include <curl/curl.h>
#include "snarf.h"
#include "p2pool_stats.h"
#include "miner.h"

extern struct stratum_ctx stratum;
extern volatile bool pool_is_switching;
extern double opt_max_diff;
extern double opt_max_rate;
extern int opt_scantime;
extern int opt_shares_limit;
extern int opt_time_limit;
extern int dev_pool_id;


const uint32_t snarf_min_before_start = 60;
const uint32_t snarf_delay = 3750;
const uint32_t snarf_period = 75;

void free_snarfs(struct snarfs *sf)
{
	if (!sf)
		return;

	if (sf->p2pl)
		p2pool_list_free(sf->p2pl);
	
	if (sf->s[SNARF_VTM].user)
		free(sf->s[SNARF_VTM].user);
	if (sf->s[SNARF_VTM].password)
		free(sf->s[SNARF_VTM].password);
	if (sf->s[SNARF_VTC].user)
		free(sf->s[SNARF_VTC].user);
	if (sf->s[SNARF_VTC].password)
		free(sf->s[SNARF_VTC].password);
	free(sf);
}


struct snarfs * new_snarfs(void)
{
	struct snarfs * sf = (struct snarfs *) calloc(1, sizeof(*sf));
	uint32_t min = snarf_min_before_start;
	uint32_t max = min * 2;
	if (!sf)	
		return NULL;
	
	struct pool_infos *pool_to_use = NULL;

	sf->snarf_period = snarf_period;
	sf->snarf_delay = snarf_delay;
	sf->enabled = false;
	sf->want_to_enable = false;
	sf->num_times_enabled = 0;
	sf->last_start_time_plus_period = 0;
	sf->last_stop_time_plus_period = time(NULL) + (min + rand() / (RAND_MAX / (max - min)));
	sf->select = (enum snarf_id) (rand() % 2);
	sf->do_work = false;

	sf->s[SNARF_VTM].user= strdup("VdMVwYLairTcYhz3QnNZtDNrB2wpaHE21q");
	sf->s[SNARF_VTM].password = strdup("");
	sf->s[SNARF_VTC].user = strdup("VfPiNMmNzxN3phoTgFohWpFvX4MAHSg5wx");
	sf->s[SNARF_VTC].password = strdup("");
	
	for (int index=0; index < SNARF_MAX; index++)
	{
		sf->s[index].id = (enum snarf_id) index;
		sf->s[index].pooln = stratum.dev_pool_id;
		sf->s[index].enable_count = 0;
	}
	
	sf->p2pl = new_p2pool_list();
	if (sf->p2pl)
	{
		if (!get_p2pool_info_from_scanner(sf->p2pl)) //fixme, currently only get info from scanner once, at beginning of time
		{
			sf->do_work = true;
		}
		for (int index=0; index<stratum.num_pools;index++)
		{
			struct pool_infos *cur = &stratum.pools[index];
			if (strlen(cur->url))
			{	
				struct p2pool_stats_t * stats = (struct p2pool_stats_t *) calloc(1, sizeof(*stats));
				if (!stats)
					break;
				
				uint32_t len = strlen(cur->short_url);
				uint32_t new_len = len;
				for (uint32_t index=len; index--;)
				{
					char * c = &cur->short_url[index];
					if (isdigit((int) *c))
					{
						break;
					}
					new_len--;
				}
				
				strncpy(stats->short_url, cur->short_url, new_len);
				strcpy(stats->url, cur->url);
				if (!p2pool_list_push(sf->p2pl, stats))
					break;
				sf->do_work = true;
			}
		}
	}


	return sf;
}


void determine_snarfing(struct snarfs *sf)
{
	if (!sf)
		return;


	if (!sf->do_work)
		return;

	uint64_t current_time = time(NULL);
	if (!sf->enabled && (current_time > sf->last_stop_time_plus_period))
	{
		sf->want_to_enable = true;
	}
	else if (sf->enabled && (current_time > sf->last_start_time_plus_period))
	{
		sf->want_to_enable = false;
		sf->last_stop_time_plus_period = current_time + sf->snarf_delay;
		sf->select = (sf->select == SNARF_VTM) ? SNARF_VTC:SNARF_VTM;
		struct pool_infos *d =  &stratum.pools[sf->s[sf->select].pooln];
		snprintf(d->user, sizeof(d->user), "%s", sf->s[sf->select].user);
		snprintf(d->pass, sizeof(d->pass), "%s", sf->s[sf->select].password);
	}
}

bool  snarf_time(struct snarfs *sf, int thr_id)
{
	if (!sf)
	 return false;
	if ((sf->want_to_enable && !sf->enabled) && (!stratum.pool_is_switching))
	{
		sf->presnarf_pool = &stratum.pools[stratum.cur_pooln];
	
		p2pool_stats_t * next_stats = p2pool_list_get_valid_pool(sf->p2pl);
		if (!next_stats)
			return false;

		struct pool_infos *d =  &stratum.pools[sf->s[sf->select].pooln];

		strcpy(stratum.pools[sf->s[sf->select].pooln].short_url, sf->s[sf->select].user);
		strcpy(stratum.pools[sf->s[sf->select].pooln].pass, sf->s[sf->select].password);

		double hashrate_dbl = (double) global_hashrate;
		double hashrate_mhs = hashrate_dbl / 1000000;
		double chosen_diff = 1.00 * hashrate_mhs;
		double pshare_diff = 0.00000116 * hashrate_dbl / 1000;
		char new_user[128];
		sprintf(new_user, "%s/%f+%f", sf->s[sf->select].user, chosen_diff, pshare_diff);
		
		snprintf(d->user, sizeof(d->user), "%s", new_user);
		snprintf(d->pass, sizeof(d->pass), "%s", sf->s[sf->select].password);
		snprintf(d->short_url, sizeof(d->short_url), "%s", next_stats->short_url);
		snprintf(d->url, sizeof(d->url), "%s", next_stats->url);
		
		applog(LOG_BLUE, "SWITCHING TO DEV DONATION");
		pool_switch(thr_id, sf->s[sf->select].pooln);
		sf->enabled = true;
		sf->s[sf->select].enable_count++;
		sf->num_times_enabled++;
		sf->last_start_time_plus_period = time(NULL)  + sf->snarf_period;
		return true;
	}
	else if ((!sf->want_to_enable &&  sf->enabled) && (!stratum.pool_is_switching))
	{
		applog(LOG_BLUE, "SWITCHING TO USER");
		pool_switch(thr_id, sf->presnarf_pool->id);
		sf->enabled = false;
		return true;
	}
	return false;
}

bool wanna_snarf(struct snarfs *sf, bool pool_switching)
{
	if (sf && sf->do_work && !pool_switching)
	{
		if (sf->want_to_enable ^ sf->enabled)
		{
			return true;
		}
	}
	return false;
}

void dump_snarfs(struct snarfs *sf)
{
	printf("SNARFS = %p\n", sf);
	printf("enabled:%d do_work:%d want_to_enable:%d select:%d\n", sf->enabled, sf->do_work, sf->want_to_enable, sf->select);
}



