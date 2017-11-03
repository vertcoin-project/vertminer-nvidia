/**
 * Functions which handle multiple pools data
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "miner.h"
#include "compat.h"
#include "algos.h"

// to move in miner.h
extern bool check_dups;

extern double opt_max_diff;
extern double opt_max_rate;
extern int opt_scantime;
extern int opt_shares_limit;
extern int opt_time_limit;

extern char* rpc_url;
extern char* rpc_user;
extern char* rpc_pass;
extern char* short_url;

extern struct stratum_ctx * volatile stratum;
extern pthread_mutex_t stats_lock;
extern time_t firstwork_time;

extern struct work _ALIGN(64) g_work[MAX_STRATUM_THREADS];
extern volatile time_t g_work_time[MAX_STRATUM_THREADS];
extern uint8_t conditional_state[MAX_GPUS];

extern double thr_hashrates[MAX_GPUS];
extern int dev_pool_id;

extern struct option options[];

#define CFG_NULL 0
#define CFG_POOL 1
struct opt_config_array {
	int cat;
	const char *name;     // json key
	const char *longname; // global opt name if different
} cfg_array_keys[] = {
	{ CFG_POOL, "url", NULL }, /* let this key first, increment pools */
	{ CFG_POOL, "user", NULL },
	{ CFG_POOL, "pass", NULL },
	{ CFG_POOL, "userpass", NULL },
	{ CFG_POOL, "name", "pool-name" },
	{ CFG_POOL, "algo", "pool-algo" },
	{ CFG_POOL, "scantime", "pool-scantime" },
	{ CFG_POOL, "max-diff", "pool-max-diff" },
	{ CFG_POOL, "max-rate", "pool-max-rate" },
	{ CFG_POOL, "disabled", "pool-disabled" },
	{ CFG_POOL, "time-limit", "pool-time-limit" },
	{ CFG_NULL, NULL, NULL }
};

// store current credentials in pools container, operates on a single pool instance
void pool_set_creds(struct pool_infos *p, char *full_rpc_url, char *short_rpc_url, char *rpc_username, char *rpc_password)
{
	snprintf(p->url, sizeof(p->url), "%s", full_rpc_url);
	snprintf(p->short_url, sizeof(p->short_url), "%s", short_rpc_url);
	snprintf(p->user, sizeof(p->user), "%s", rpc_username);
	snprintf(p->pass, sizeof(p->pass), "%s", rpc_password);

	if (!(p->status & POOL_ST_DEFINED)) {
		p->status |= POOL_ST_DEFINED;
		// init pool options as "unset"
		// until cmdline is fully parsed...
		p->algo = -1;
		p->max_diff = -1.;
		p->max_rate = -1.;
		p->scantime = -1;
		p->shares_limit = -1;
		p->time_limit = -1;

		p->check_dups = check_dups;

		p->status |= POOL_ST_DEFINED;
	}

	if (strlen(rpc_url)) {
		p->type = POOL_STRATUM;
		p->status |= POOL_ST_VALID;
	}
}

// fill the unset pools options with cmdline ones 
void pool_init_defaults(struct stratum_ctx * ctx, struct pool_infos *poolinfos, int number_of_pools)
{
	
	for (int i=0; i<number_of_pools; i++) {
		poolinfos[i].id = i;
		if (poolinfos[i].algo == -1) poolinfos[i].algo = (int) opt_algo;
		if (poolinfos[i].max_diff == -1.) poolinfos[i].max_diff = opt_max_diff;
		if (poolinfos[i].max_rate == -1.) poolinfos[i].max_rate = opt_max_rate;
		if (poolinfos[i].scantime == -1) poolinfos[i].scantime = opt_scantime;
		if (poolinfos[i].shares_limit == -1) poolinfos[i].shares_limit = opt_shares_limit;
		if (poolinfos[i].time_limit == -1) poolinfos[i].time_limit = opt_time_limit;
		poolinfos[i].stratum = ctx;
	}
}

// attributes only set by a json pools config
void pool_set_attr(struct pool_infos *p, const char* key, char* arg)
{
	if (!strcasecmp(key, "name")) {
		snprintf(p->name, sizeof(p->name), "%s", arg);
		return;
	}
	if (!strcasecmp(key, "algo")) {
		p->algo = algo_to_int(arg);
		return;
	}
	if (!strcasecmp(key, "scantime")) {
		p->scantime = atoi(arg);
		return;
	}
	if (!strcasecmp(key, "max-diff")) {
		p->max_diff = atof(arg);
		return;
	}
	if (!strcasecmp(key, "max-rate")) {
		p->max_rate = atof(arg);
		return;
	}
	if (!strcasecmp(key, "shares-limit")) {
		p->shares_limit = atoi(arg);
		return;
	}
	if (!strcasecmp(key, "time-limit")) {
		p->time_limit = atoi(arg);
		printf("p->time_limit = %d\n", p->time_limit);
		return;
	}
	if (!strcasecmp(key, "disabled")) {
		int removed = atoi(arg);
		if (removed) {
			p->status |= POOL_ST_REMOVED;
		}
		return;
	}
}

// pool switching code
bool pool_switch(struct stratum_ctx *ctx, int pooln)
{
	int prevn = ctx->cur_pooln;
	bool algo_switch = false;
	struct pool_infos *prev = &ctx->pools[stratum->cur_pooln];
	struct pool_infos* p = NULL;

	stratum_free_job(ctx);

	if (pooln < (ctx->num_pools+1)) {
		ctx->cur_pooln = pooln;
		p = &ctx->pools[stratum->cur_pooln];
	} else {
		applog(LOG_ERR, "Switch to inexistant pool %d!", pooln);
		return false;
	}

	// save global attributes
	prev->check_dups = check_dups;

	pthread_mutex_lock(&ctx->work_lock);

	free(rpc_user); rpc_user = strdup(p->user);
	free(rpc_pass); rpc_pass = strdup(p->pass);
	free(rpc_url);  rpc_url = strdup(p->url);

	short_url = p->short_url; // just a pointer, no alloc

	opt_scantime = p->scantime;
	opt_max_diff = p->max_diff;
	opt_max_rate = p->max_rate;
	opt_shares_limit = p->shares_limit;
	opt_time_limit = p->time_limit;

	// yiimp stats reporting
	opt_stratum_stats = (strstr(p->pass, "stats") != NULL) || (strcmp(p->user, "benchmark") == 0);

	pthread_mutex_unlock(&ctx->work_lock);

	if (prevn != ctx->cur_pooln) {

		ctx->pool_switch_count++;
		net_diff = 0;
		g_work_time[ctx->id] = 0;
		g_work[ctx->id].data[0] = 0;
		ctx->pool_is_switching = true;
		ctx->need_reset = true;
		// used to get the pool uptime
		firstwork_time = time(NULL);
		restart_threads();
		// reset wait states
		for (int n=0; n<opt_n_threads; n++)
			conditional_state[n] = false;

		// restore flags
		check_dups = p->check_dups;

		ctx->pooln = ctx->cur_pooln;

		// unlock the stratum thread
		printf("pushing %s stratum\n", rpc_url);
		tq_push(ctx->thread->q, strdup(rpc_url));
		applog(LOG_BLUE, "Switch to stratum pool %d: %s", ctx->cur_pooln,
			strlen(p->name) ? p->name : p->short_url);
	}
	return true;
}

// search available pool
int pool_get_first_valid(struct stratum_ctx * ctx, int startfrom)
{
	int next = 0;
	for (int i=0; i<ctx->num_pools; i++) {
		int pooln = (startfrom + i) % ctx->num_pools;
		
		if (!(ctx->pools[pooln].status & POOL_ST_VALID))
			continue;
		if (ctx->pools[pooln].status & (POOL_ST_DISABLED | POOL_ST_REMOVED))
			continue;
		next = pooln;
		break;
	}
	return next;
}

// switch to next available pool
bool pool_switch_next(struct stratum_ctx * ctx, int thr_id)
{
	if (ctx->num_pools > 1) {
		int pooln = pool_get_first_valid(ctx, ctx->cur_pooln+1);
		return pool_switch(ctx, pooln);
	} else {
		// no switch possible
		if (!opt_quiet)
			applog(LOG_DEBUG, "No other pools to try...");
		return false;
	}
}


// Parse pools array in json config
bool parse_pool_array(json_t *obj)
{
	size_t idx;
	json_t *p, *val;

	if (!json_is_array(obj))
		return false;

	// array of objects [ {}, {} ]
	json_array_foreach(obj, idx, p)
	{
		if (!json_is_object(p))
			continue;

		for (int i = 0; i < ARRAY_SIZE(cfg_array_keys); i++)
		{
			int opt = -1;
			char *s = NULL;
			if (cfg_array_keys[i].cat != CFG_POOL)
				continue;

			val = json_object_get(p, cfg_array_keys[i].name);
			if (!val)
				continue;

			for (int k = 0; k < options_count(); k++)
			{
				const char *alias = cfg_array_keys[i].longname;
				if (alias && !strcasecmp(options[k].name, alias)) {
					opt = k;
					break;
				}
				if (!alias && !strcasecmp(options[k].name, cfg_array_keys[i].name)) {
					opt = k;
					break;
				}
			}
			if (opt == -1)
				continue;

			if (json_is_string(val)) {
				s = strdup(json_string_value(val));
				if (!s)
					continue;

				// applog(LOG_DEBUG, "pool key %s '%s'", options[opt].name, s);
				parse_arg(options[opt].val, s);
				free(s);
			} else {
				// numeric or bool
				char buf[32] = { 0 };
				double d = 0.;
				if (json_is_true(val)) d = 1.;
				else if (json_is_integer(val))
					d = 1.0 * json_integer_value(val);
				else if (json_is_real(val))
					d = json_real_value(val);
				snprintf(buf, sizeof(buf)-1, "%f", d);
				// applog(LOG_DEBUG, "pool key %s '%f'", options[opt].name, d);
				parse_arg(options[opt].val, buf);
			}
		}
	}
	return true;
}

// debug stuff
void pool_dump_infos(struct pool_infos *p, int num_pools)
{
	struct pool_infos *start = POOL_INFOS_HEAD(p);
	if (opt_benchmark) return;
	for (int i=0; i<num_pools; i++) {
		applog(LOG_DEBUG, "POOL %01d: %s USER %s -s %d", i,
			start[i].short_url, start[i].user, start[i].scantime);
	}
}

void pool_dump_info(struct pool_infos *p)
{
	if (opt_benchmark) return;
	applog(LOG_BLUE, "POOL %01d: %s USER %s -s %d", p->id, p->short_url, p->user, p->scantime);
}
