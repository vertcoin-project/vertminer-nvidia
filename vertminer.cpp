/*
 * Copyright 2010 Jeff Garzik
 * Copyright 2012-2014 pooler
 * Copyright 2014-2015 tpruvot
 * Copyright 2017-2018 aturek
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the Free
 * Software Foundation; either version 2 of the License, or (at your option)
 * any later version.  See COPYING for more details.
 */

#include <vertminer-config.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <inttypes.h>
#include <unistd.h>
#include <math.h>
#include <sys/time.h>
#include <time.h>
#include <signal.h>

#include <curl/curl.h>
#include <openssl/sha.h>

#ifdef WIN32
#include <windows.h>
#include <stdint.h>
#else
#include <errno.h>
#include <sys/resource.h>
#if HAVE_SYS_SYSCTL_H
#include <sys/types.h>
#if HAVE_SYS_PARAM_H
#include <sys/param.h>
#endif
#include <sys/sysctl.h>
#endif
#endif

#include "miner.h"
#include "algos.h"
#include <cuda_runtime.h>

#ifdef WIN32
#include <Mmsystem.h>
#pragma comment(lib, "winmm.lib")
#include "compat/winansi.h"
BOOL WINAPI ConsoleHandler(DWORD);
#endif

#define PROGRAM_NAME		"vertminer"
#define LP_SCANTIME		60

#include "nvml.h"
#include "snarf.h"
#ifdef USE_WRAPNVML
nvml_handle *hnvml = NULL;
#endif

enum workio_commands {
	WC_SUBMIT_WORK,
	WC_ABORT,
};

struct workio_cmd {
	enum workio_commands	cmd;
	struct thr_info		*thr;
	union {
		struct work	*work;
	} u;
	int pooln;
};

bool opt_debug = false;
bool opt_debug_diff = false;
bool opt_debug_threads = false;
bool opt_protocol = false;
bool opt_benchmark = false;
bool opt_showdiff = true;
bool opt_eco_mode = false;

// todo: limit use of these flags,
// prefer the pools[] attributes
bool check_dups = false;
bool check_stratum_jobs = false;

static bool submit_old = false;
bool use_syslog = false;
bool use_colors = true;
int use_pok = 0;
static bool opt_background = false;
bool opt_quiet = false;
static int opt_retries = -1;
static int opt_fail_pause = 30;
int opt_time_limit = -1;
int opt_shares_limit = -1;
time_t firstwork_time = 0;
int opt_timeout = 300; // curl
int opt_scantime = 10;
static json_t *opt_config;
static const bool opt_time = true;
const enum sha_algos opt_algo = ALGO_LYRA2v2;
int opt_n_threads = 0;
int gpu_threads = 1;
int64_t opt_affinity = -1L;
int opt_priority = 0;
static double opt_difficulty = 1.;
bool opt_extranonce = true;
bool opt_trust_pool = false;
uint16_t opt_vote = 9999;
int num_cpus;
int active_gpus;
char * device_name[MAX_GPUS];
short device_map[MAX_GPUS] = { 0 };
long  device_sm[MAX_GPUS] = { 0 };
uint32_t gpus_intensity[MAX_GPUS] = { 0 };
uint32_t device_gpu_clocks[MAX_GPUS] = { 0 };
uint32_t device_mem_clocks[MAX_GPUS] = { 0 };
uint32_t device_plimit[MAX_GPUS] = { 0 };
uint8_t device_tlimit[MAX_GPUS] = { 0 };
int8_t device_pstate[MAX_GPUS] = { -1, -1 };
int32_t device_led[MAX_GPUS] = { -1, -1 };
int opt_led_mode = 0;
int opt_cudaschedule = -1;
static bool opt_keep_clocks = false;

// un-linked to cmdline scrypt options (useless)
int device_batchsize[MAX_GPUS] = { 0 };
int device_texturecache[MAX_GPUS] = { 0 };
int device_singlememory[MAX_GPUS] = { 0 };
// implemented scrypt options
int parallel = 2; // All should be made on GPU
char *device_config[MAX_GPUS] = { 0 };
int device_backoff[MAX_GPUS] = { 0 };
int device_lookup_gap[MAX_GPUS] = { 0 };
int device_interactive[MAX_GPUS] = { 0 };
int opt_nfactor = 0;
bool opt_autotune = true;

// pools (failover/getwork infos)
bool opt_pool_failover = true;

// current connection
char *rpc_user = NULL;
char *rpc_pass;
char *rpc_url;
char *short_url = NULL;

struct stratum_ctx stratums[MAX_STRATUM_THREADS]= { 0 };
struct stratum_ctx * volatile stratum;
int stratum_thr_id = -1;

//struct snarfs * sf = NULL;

static unsigned char pk_script[25] = { 0 };
static size_t pk_script_size = 0;

char *opt_cert;
char *opt_proxy;
long opt_proxy_type;
struct thr_info *thr_info = NULL;
static int work_thr_id;
struct thr_api *thr_api;
int api_thr_id = -1;
volatile bool abort_flag = false;
struct work_restart *work_restart = NULL;
static int app_exit_code = EXIT_CODE_OK;

pthread_mutex_t applog_lock;
pthread_mutex_t stats_lock;
double thr_hashrates[MAX_GPUS] = { 0 };
uint64_t global_hashrate = 0;
static char *lp_id;
double   net_diff = 0;
uint64_t net_hashrate = 0;
uint64_t net_blocks = 0;
// conditional mining
uint8_t conditional_state[MAX_GPUS] = { 0 };
double opt_max_temp = 0.0;
double opt_max_diff = -1.;
double opt_max_rate = -1.;
double opt_resume_temp = 0.;
double opt_resume_diff = 0.;
double opt_resume_rate = -1.;

int opt_statsavg = 30;

// strdup on char* to allow a common free() if used
static char* opt_syslog_pfx = strdup(PROGRAM_NAME);
char *opt_api_allow = strdup("127.0.0.1"); /* 0.0.0.0 for all ips */
int opt_api_remote = 0;
int opt_api_listen = 4068; /* 0 to disable */

bool opt_stratum_stats = false;

static char const usage[] = "\
Usage: " PROGRAM_NAME " [OPTIONS]\n\
Options:\n\
  -a, --algo=ALGO       specify the hash algorithm to use(NOT NECESSARY FOR VERTMINER)\n\
			lyra2v2     Lyra2REv2(VertCoin)\n\
  -d, --devices         Comma separated list of CUDA devices to use.\n\
                        Device IDs start counting from 0! Alternatively takes\n\
                        string names of your cards like gtx780ti or gt640#2\n\
                        (matching 2nd gt640 in the PC)\n\
  -i  --intensity=N[,N] GPU intensity 8.0-25.0 (default: auto) \n\
                        Decimals are allowed for fine tuning \n\
      --eco             Use Eco mode\n\
	                    Auto tuning for low energy (Lyra2REv2 only)\n\
      --cuda-schedule   Set device threads scheduling mode (default: auto)\n\
  -f, --diff-factor     Divide difficulty by this factor (default 1.0) \n\
  -m, --diff-multiplier Multiply difficulty by this value (default 1.0) \n\
      --vote=VOTE       vote (for decred and HeavyCoin)\n\
      --trust-pool      trust the max block reward vote (maxvote) sent by the pool\n\
  -o, --url=URL         URL of mining server\n\
  -O, --userpass=U:P    username:password pair for mining server\n\
  -u, --user=USERNAME   username for mining server\n\
  -p, --pass=PASSWORD   password for mining server\n\
      --cert=FILE       certificate for mining server using SSL\n\
  -x, --proxy=[PROTOCOL://]HOST[:PORT]  connect through a proxy\n\
  -t, --threads=N       number of miner threads (default: number of nVidia GPUs)\n\
  -r, --retries=N       number of times to retry if a network call fails\n\
                          (default: retry indefinitely)\n\
  -R, --retry-pause=N   time to pause between retries, in seconds (default: 30)\n\
      --shares-limit    maximum shares [s] to mine before exiting the program.\n\
      --time-limit      maximum time [s] to mine before exiting the program.\n\
  -T, --timeout=N       network timeout, in seconds (default: 300)\n\
  -s, --scantime=N      upper bound on time spent scanning current work when\n\
                          long polling is unavailable, in seconds (default: 10)\n\
  -n, --ndevs           list cuda devices\n\
  -N, --statsavg        number of samples used to compute hashrate (default: 30)\n\
      --coinbase-addr=ADDR  payout address for solo mining\n\
      --no-getwork      disable getwork support\n\
      --no-gbt          disable getblocktemplate support (height check in solo)\n\
      --no-stratum      disable X-Stratum support\n\
      --no-extranonce   disable extranonce subscribe on stratum\n\
  -q, --quiet           disable per-thread hashmeter output\n\
      --no-color        disable colored output\n\
  -D, --debug           enable debug output\n\
  -P, --protocol-dump   verbose dump of protocol-level activities\n\
      --cpu-affinity    set process affinity to cpu core(s), mask 0x3 for cores 0 and 1\n\
      --cpu-priority    set process priority (default: 3) 0 idle, 2 normal to 5 highest\n\
  -b, --api-bind=port   IP:port for the miner API (default: 127.0.0.1:4068), 0 disabled\n\
      --api-remote      Allow remote control, like pool switching\n\
      --max-temp=N      Only mine if gpu temp is less than specified value\n\
      --max-rate=N[KMG] Only mine if net hashrate is less than specified value\n\
      --max-diff=N      Only mine if net difficulty is less than specified value\n\
                        Can be tuned with --resume-diff=N to set a resume value\n"
#if defined(__linux) || defined(_WIN64) /* via nvml */
"\
      --mem-clock=3505  Set the gpu memory max clock (346.72+ driver)\n\
      --gpu-clock=1150  Set the gpu engine max clock (346.72+ driver)\n\
      --pstate=0[,2]    Set the gpu power state (352.21+ driver)\n\
      --plimit=100W     Set the gpu power limit (352.21+ driver)\n"
#else /* via nvapi.dll */
"\
      --mem-clock=3505  Set the gpu memory boost clock\n\
      --gpu-clock=1150  Set the gpu engine boost clock\n\
      --plimit=100      Set the gpu power limit in percentage\n\
      --tlimit=80       Set the gpu thermal limit in degrees\n\
      --led=100         Set the logo led level (0=disable, 0xFF00FF for RVB)\n"
#endif
#ifdef HAVE_SYSLOG_H
"\
  -S, --syslog          use system log for output messages\n\
      --syslog-prefix=... allow to change syslog tool name\n"
#endif
"\
      --hide-diff       hide submitted block and net difficulty (old mode)\n\
  -B, --background      run the miner in the background\n\
      --benchmark       run in offline benchmark mode\n\
      --cputest         debug hashes from cpu algorithms\n\
  -c, --config=FILE     load a JSON-format configuration file\n\
  -V, --version         display version information and exit\n\
  -h, --help            display this help text and exit\n\
";

static char const short_options[] =
#ifdef HAVE_SYSLOG_H
	"S"
#endif
	"a:Bc:i:Dhp:Px:f:m:nqr:R:s:t:T:o:u:O:Vd:N:b:l:L:";

struct option options[] = {
	{ "algo", 1, NULL, 'a' },
	{ "api-bind", 1, NULL, 'b' },
	{ "api-remote", 0, NULL, 1030 },
	{ "background", 0, NULL, 'B' },
	{ "benchmark", 0, NULL, 1005 },
	{ "cert", 1, NULL, 1001 },
	{ "coinbase-addr", 1, NULL, 1016 },
	{ "config", 1, NULL, 'c' },
	{ "cputest", 0, NULL, 1006 },
	{ "cpu-affinity", 1, NULL, 1020 },
	{ "cpu-priority", 1, NULL, 1021 },
	{ "cuda-schedule", 1, NULL, 1025 },
	{ "debug", 0, NULL, 'D' },
	{ "help", 0, NULL, 'h' },
	{ "intensity", 1, NULL, 'i' },
	{ "ndevs", 0, NULL, 'n' },
	{ "no-color", 0, NULL, 1002 },
	{ "no-extranonce", 0, NULL, 1012 },
	{ "no-gbt", 0, NULL, 1011 },
	{ "no-getwork", 0, NULL, 1010 },
	{ "no-longpoll", 0, NULL, 1003 },
	{ "no-stratum", 0, NULL, 1007 },
	{ "no-autotune", 0, NULL, 1004 },  // scrypt
	{ "interactive", 1, NULL, 1050 },  // scrypt
	{ "launch-config", 1, NULL, 'l' }, // scrypt
	{ "lookup-gap", 1, NULL, 'L' },    // scrypt
	{ "texture-cache", 1, NULL, 1051 },// scrypt
	{ "max-temp", 1, NULL, 1060 },
	{ "max-diff", 1, NULL, 1061 },
	{ "max-rate", 1, NULL, 1062 },
	{ "resume-diff", 1, NULL, 1063 },
	{ "resume-rate", 1, NULL, 1064 },
	{ "resume-temp", 1, NULL, 1065 },
	{ "pass", 1, NULL, 'p' },
	{ "pool-name", 1, NULL, 1100 },     // pool
	{ "pool-algo", 1, NULL, 1101 },     // pool
	{ "pool-scantime", 1, NULL, 1102 }, // pool
	{ "pool-shares-limit", 1, NULL, 1109 },
	{ "pool-time-limit", 1, NULL, 1108 },
	{ "pool-max-diff", 1, NULL, 1161 }, // pool
	{ "pool-max-rate", 1, NULL, 1162 }, // pool
	{ "pool-disabled", 1, NULL, 1199 }, // pool
	{ "protocol-dump", 0, NULL, 'P' },
	{ "proxy", 1, NULL, 'x' },
	{ "quiet", 0, NULL, 'q' },
	{ "retries", 1, NULL, 'r' },
	{ "retry-pause", 1, NULL, 'R' },
	{ "scantime", 1, NULL, 's' },
	{ "show-diff", 0, NULL, 1013 },
	{ "hide-diff", 0, NULL, 1014 },
	{ "statsavg", 1, NULL, 'N' },
	{ "gpu-clock", 1, NULL, 1070 },
	{ "mem-clock", 1, NULL, 1071 },
	{ "pstate", 1, NULL, 1072 },
	{ "plimit", 1, NULL, 1073 },
	{ "keep-clocks", 0, NULL, 1074 },
	{ "tlimit", 1, NULL, 1075 },
	{ "led", 1, NULL, 1080 },
#ifdef HAVE_SYSLOG_H
	{ "syslog", 0, NULL, 'S' },
	{ "syslog-prefix", 1, NULL, 1018 },
#endif
	{ "shares-limit", 1, NULL, 1009 },
	{ "time-limit", 1, NULL, 1008 },
	{ "threads", 1, NULL, 't' },
	{ "vote", 1, NULL, 1022 },
	{ "trust-pool", 0, NULL, 1023 },
	{ "timeout", 1, NULL, 'T' },
	{ "url", 1, NULL, 'o' },
	{ "user", 1, NULL, 'u' },
	{ "userpass", 1, NULL, 'O' },
	{ "version", 0, NULL, 'V' },
	{ "devices", 1, NULL, 'd' },
	{ "diff-multiplier", 1, NULL, 'm' },
	{ "diff-factor", 1, NULL, 'f' },
	{ "diff", 1, NULL, 'f' }, // compat
	{ "eco", 0, NULL, 1081 },
	{ 0, 0, 0, 0 }
};

static char const scrypt_usage[] = "\n\
Scrypt specific options:\n\
  -l, --launch-config   gives the launch configuration for each kernel\n\
                        in a comma separated list, one per device.\n\
  -L, --lookup-gap      Divides the per-hash memory requirement by this factor\n\
                        by storing only every N'th value in the scratchpad.\n\
                        Default is 1.\n\
      --interactive     comma separated list of flags (0/1) specifying\n\
                        which of the CUDA device you need to run at inter-\n\
                        active frame rates (because it drives a display).\n\
      --texture-cache   comma separated list of flags (0/1/2) specifying\n\
                        which of the CUDA devices shall use the texture\n\
                        cache for mining. Kepler devices may profit.\n\
      --no-autotune     disable auto-tuning of kernel launch parameters\n\
";

struct work _ALIGN(64) g_work[MAX_STRATUM_THREADS];
volatile time_t g_work_time[MAX_STRATUM_THREADS];
pthread_mutex_t g_work_lock[MAX_STRATUM_THREADS];

// get const array size (defined in vertminer.cpp)
int options_count()
{
	int n = 0;
	while (options[n].name != NULL)
		n++;
	return n;
}

#ifdef __linux /* Linux specific policy and affinity management */
#include <sched.h>
static inline void drop_policy(void) {
	struct sched_param param;
	param.sched_priority = 0;
#ifdef SCHED_IDLE
	if (unlikely(sched_setscheduler(0, SCHED_IDLE, &param) == -1))
#endif
#ifdef SCHED_BATCH
		sched_setscheduler(0, SCHED_BATCH, &param);
#endif
}

static void affine_to_cpu_mask(int id, unsigned long mask) {
	cpu_set_t set;
	CPU_ZERO(&set);
	for (uint8_t i = 0; i < num_cpus; i++) {
		// cpu mask
		if (mask & (1UL<<i)) { CPU_SET(i, &set); }
	}
	if (id == -1) {
		// process affinity
		sched_setaffinity(0, sizeof(&set), &set);
	} else {
		// thread only
		pthread_setaffinity_np(thr_info[id].pth, sizeof(&set), &set);
	}
}
#elif defined(__FreeBSD__) /* FreeBSD specific policy and affinity management */
#include <sys/cpuset.h>
static inline void drop_policy(void) { }
static void affine_to_cpu_mask(int id, unsigned long mask) {
	cpuset_t set;
	CPU_ZERO(&set);
	for (uint8_t i = 0; i < num_cpus; i++) {
		if (mask & (1UL<<i)) CPU_SET(i, &set);
	}
	cpuset_setaffinity(CPU_LEVEL_WHICH, CPU_WHICH_TID, -1, sizeof(cpuset_t), &set);
}
#elif defined(WIN32) /* Windows */
static inline void drop_policy(void) { }
static void affine_to_cpu_mask(int id, unsigned long mask) {
	if (id == -1)
		SetProcessAffinityMask(GetCurrentProcess(), mask);
	else
		SetThreadAffinityMask(GetCurrentThread(), mask);
}
#else /* Martians */
static inline void drop_policy(void) { }
static void affine_to_cpu_mask(int id, uint8_t mask) { }
#endif


void get_currentalgo(char* buf, int sz)
{
	snprintf(buf, sz, "%s", algo_names[opt_algo]);
}

/**
 * Exit app
 */
void proper_exit(int reason)
{
//	free_snarfs(sf);
	restart_threads();
	if (abort_flag) /* already called */
		return;

	abort_flag = true;
	usleep(200 * 1000);
	cuda_shutdown();

	if (reason == EXIT_CODE_OK && app_exit_code != EXIT_CODE_OK) {
		reason = app_exit_code;
	}

	pthread_mutex_lock(&stats_lock);
	if (check_dups)
		hashlog_purge_all();
	stats_purge_all();
	pthread_mutex_unlock(&stats_lock);

#ifdef WIN32
	timeEndPeriod(1); // else never executed
#endif
#ifdef USE_WRAPNVML
	if (hnvml) {
		for (int n=0; n < opt_n_threads && !opt_keep_clocks; n++) {
			nvml_reset_clocks(hnvml, device_map[n]);
		}
		nvml_destroy(hnvml);
	}
#endif
	free(opt_syslog_pfx);
	free(opt_api_allow);
	//free(work_restart);
	//free(thr_info);
	exit(reason);
}

static bool jobj_binary(const json_t *obj, const char *key,
			void *buf, size_t buflen)
{
	const char *hexstr;
	json_t *tmp;

	tmp = json_object_get(obj, key);
	if (unlikely(!tmp)) {
		applog(LOG_ERR, "JSON key '%s' not found", key);
		return false;
	}
	hexstr = json_string_value(tmp);
	if (unlikely(!hexstr)) {
		applog(LOG_ERR, "JSON key '%s' is not a string", key);
		return false;
	}
	if (!hex2bin((uchar*)buf, hexstr, buflen))
		return false;

	return true;
}

/* compute nbits to get the network diff */
static void calc_network_diff(struct work *work)
{
	// sample for diff 43.281 : 1c05ea29
	uint32_t nbits = swab32(work->data[18]);

	uint32_t bits = (nbits & 0xffffff);
	int16_t shift = (swab32(nbits) & 0xff); // 0x1c = 28

	uint64_t diffone = 0x0000FFFF00000000ull;
	double d = (double)0x0000ffff / (double)bits;

	for (int m=shift; m < 29; m++) d *= 256.0;
	for (int m=29; m < shift; m++) d /= 256.0;
	if (opt_debug_diff)
		applog(LOG_DEBUG, "net diff: %f -> shift %u, bits %08x", d, shift, bits);

	net_diff = d;
}


#define YES "yes!"
#define YAY "yay!!!"
#define BOO "booooo"

int share_result(struct stratum_ctx * ctx, int result, int pooln, double sharediff, const char *reason)
{
	const char *flag;
	char suppl[32] = { 0 };
	char s[32] = { 0 };
	double hashrate = 0.;
	struct pool_infos *p = &ctx->pools[pooln];

	pthread_mutex_lock(&stats_lock);
	for (int i = 0; i < opt_n_threads; i++) {
		hashrate += stats_get_speed(i, thr_hashrates[i]);
	}
	pthread_mutex_unlock(&stats_lock);

	result ? p->accepted_count++ : p->rejected_count++;

	p->last_share_time = time(NULL);
	if (sharediff > p->best_share)
		p->best_share = sharediff;

	global_hashrate = llround(hashrate);

	format_hashrate(hashrate, s);
	if (opt_showdiff)
		sprintf(suppl, "diff %.3f", sharediff);
	else // accepted percent
		sprintf(suppl, "%.2f%%", 100. * p->accepted_count / (p->accepted_count + p->rejected_count));

	if (!net_diff || sharediff < net_diff) {
		flag = use_colors ?
			(result ? CL_GRN YES : CL_RED BOO)
		:	(result ? "(" YES ")" : "(" BOO ")");
	} else {
		p->solved_count++;
		flag = use_colors ?
			(result ? CL_GRN YAY : CL_RED BOO)
		:	(result ? "(" YAY ")" : "(" BOO ")");
	}

	applog(LOG_NOTICE, "accepted: %lu/%lu (%s), %s %s",
			p->accepted_count,
			p->accepted_count + p->rejected_count,
			suppl, s, flag);
	if (reason) {
		applog(LOG_WARNING, "reject reason: %s", reason);
		if (!check_dups && strncasecmp(reason, "duplicate", 9) == 0) {
			applog(LOG_WARNING, "enabling duplicates check feature");
			check_dups = true;
			g_work_time[ctx->id] = 0;
		}
	}
	return 1;
}

static bool submit_upstream_work(CURL *curl, struct work *work)
{
	char s[512];
	struct pool_infos *pool = &work->ctx->pools[work->pooln];
	json_t *val, *res, *reason;
	bool stale_work = false;
	int idnonce = 0;

	/* discard if a newer block was received */
	stale_work = work->height && work->height < g_work[work->ctx->id].height;
	if (!stale_work) {
		pthread_mutex_lock(&g_work_lock[work->ctx->id]);
		if (strlen(work->job_id + 8))
			stale_work = strncmp(work->job_id + 8, g_work[work->ctx->id].job_id + 8, sizeof(g_work[work->ctx->id].job_id) - 8);
		if (stale_work) {
			pool->stales_count++;
			if (opt_debug) applog(LOG_DEBUG, "outdated job %s, new %s stales=%d",
				work->job_id + 8 , g_work[work->ctx->id].job_id + 8, pool->stales_count);
			if (!check_stratum_jobs && pool->stales_count > 5) {
				if (!opt_quiet) applog(LOG_WARNING, "Enabled stratum stale jobs workaround");
				check_stratum_jobs = true;
			}
		}
		pthread_mutex_unlock(&g_work_lock[work->ctx->id]);
	}

	if (!submit_old && stale_work) {
		if (opt_debug)
			applog(LOG_WARNING, "stale work detected, discarding");
		return true;
	}

	uint32_t sent = 0;
	uint32_t ntime, nonce;
	char *ntimestr, *noncestr, *xnonce2str, *nvotestr;
	uint16_t nvote = 0;
	
	le32enc(&ntime, work->data[17]);
	le32enc(&nonce, work->data[19]);
	
	noncestr = bin2hex((const uchar*)(&nonce), 4);
	
	if (check_dups)
		sent = hashlog_already_submittted(work->job_id, nonce);
	if (sent > 0) {
		sent = (uint32_t) time(NULL) - sent;
		if (!opt_quiet) {
			applog(LOG_WARNING, "nonce %s was already sent %u seconds ago", noncestr, sent);
			hashlog_dump_job(work->job_id);
		}
		free(noncestr);
		// prevent useless computing on some pools
		g_work_time[work->ctx->id] = 0;
		restart_threads();
		return true;
	}
	
	ntimestr = bin2hex((const uchar*)(&ntime), 4);
	
	xnonce2str = bin2hex(work->xnonce2, work->xnonce2_len);
	
	// store to keep/display the solved ratio/diff
	work->ctx->sharediff = work->sharediff[idnonce];
	
	if (net_diff && work->ctx->sharediff > net_diff && (opt_debug || opt_debug_diff))
		applog(LOG_INFO, "share diff: %.5f, possible block found!!!",
			work->ctx->sharediff);
	else if (opt_debug_diff)
		applog(LOG_DEBUG, "share diff: %.5f (x %.1f)", work->ctx->sharediff, work->shareratio);
	
		sprintf(s, "{\"method\": \"mining.submit\", \"params\": ["
			"\"%s\", \"%s\", \"%s\", \"%s\", \"%s\"], \"id\":%d}",
			pool->user, work->job_id + 8, xnonce2str, ntimestr, noncestr, 10+idnonce);
//			printf("{\"method\": \"mining.submit\", \"params\": ["
//				"\"%s\", \"%s\", \"%s\", \"%s\", \"%s\"], \"id\":%d}",
//					pool->user, work->job_id + 8, xnonce2str, ntimestr, noncestr, 10+idnonce);
	free(xnonce2str);
	free(ntimestr);
	free(noncestr);

	gettimeofday(&work->ctx->tv_submit, NULL);
	if (unlikely(!stratum_send_line(work->ctx, s))) {
		applog(LOG_ERR, "submit_upstream_work stratum_send_line failed");
		return false;
	}

	if (check_dups)
		hashlog_remember_submit(work, nonce);

	return true;
}




static void workio_cmd_free(struct workio_cmd *wc)
{
	if (!wc)
		return;

	switch (wc->cmd) {
	case WC_SUBMIT_WORK:
		aligned_free(wc->u.work);
		break;
	default: /* do nothing */
		break;
	}

	memset(wc, 0, sizeof(*wc));	/* poison */
	free(wc);
}

static void workio_abort()
{
	struct workio_cmd *wc;

	/* fill out work request message */
	wc = (struct workio_cmd *)calloc(1, sizeof(*wc));
	if (!wc)
		return;

	wc->cmd = WC_ABORT;

	/* send work request to workio thread */
	if (!tq_push(thr_info[work_thr_id].q, wc)) {
		workio_cmd_free(wc);
	}
}


static bool workio_submit_work(struct workio_cmd *wc, CURL *curl)
{
	int failures = 0;
	uint32_t pooln = wc->pooln;
	// applog(LOG_DEBUG, "%s: pool %d", __func__, wc->pooln);

	/* submit solution to bitcoin via JSON-RPC */
	while (!submit_upstream_work(curl, wc->u.work)) {
		if (unlikely((opt_retries >= 0) && (++failures > opt_retries))) {
			applog(LOG_ERR, "...terminating workio thread");
			return false;
		}
		/* pause, then restart work-request loop */
		if (!opt_benchmark)
			applog(LOG_ERR, "...retry after %d seconds", opt_fail_pause);

		sleep(opt_fail_pause);
	}

	return true;
}

static void *workio_thread(void *userdata)
{
	struct thr_info *mythr = (struct thr_info*)userdata;
	CURL *curl;
	bool ok = true;

	curl = curl_easy_init();
	if (unlikely(!curl)) {
		applog(LOG_ERR, "CURL initialization failed");
		return NULL;
	}

	while (ok && !abort_flag) {
		struct workio_cmd *wc;

		/* wait for workio_cmd sent to us, on our queue */
		wc = (struct workio_cmd *)tq_pop(mythr->q, NULL);
		if (!wc) {
			ok = false;
			break;
		}

		/* process workio_cmd */
		switch (wc->cmd) {
			break;
		case WC_SUBMIT_WORK:
			if (opt_led_mode == LED_MODE_SHARES)
				gpu_led_on(device_map[wc->thr->id]);
			ok = workio_submit_work(wc, curl);
			if (opt_led_mode == LED_MODE_SHARES)
				gpu_led_off(device_map[wc->thr->id]);
			break;
		case WC_ABORT:
		default:		/* should never happen */
			ok = false;
			break;
		}

		if (!ok && stratum->num_pools > 1 && opt_pool_failover) {
			if (opt_debug_threads)
				applog(LOG_DEBUG, "%s died, failover", __func__);
			ok = pool_switch_next(stratum, -1);
			tq_push(wc->thr->q, NULL); // get_work() will return false
		}

		workio_cmd_free(wc);
	}

	if (opt_debug_threads)
		applog(LOG_DEBUG, "%s() died", __func__);
	curl_easy_cleanup(curl);
	tq_freeze(mythr->q);
	return NULL;
}


static bool submit_work(struct thr_info *thr, const struct work *work_in)
{
	struct workio_cmd *wc;
	/* fill out work request message */
	wc = (struct workio_cmd *)calloc(1, sizeof(*wc));
	if (!wc)
		return false;

	wc->u.work = (struct work *)aligned_calloc(sizeof(*work_in));
	if (!wc->u.work)
		goto err_out;

	wc->cmd = WC_SUBMIT_WORK;
	wc->thr = thr;
	memcpy(wc->u.work, work_in, sizeof(struct work));
	wc->pooln = work_in->pooln;

	/* send solution to workio thread */
	if (!tq_push(thr_info[work_thr_id].q, wc))
		goto err_out;

	return true;

err_out:
	workio_cmd_free(wc);
	return false;
}

static bool stratum_gen_work(struct stratum_ctx *sctx, struct work *work)
{
	uchar merkle_root[64] = { 0 };
	int i;

	if (!sctx->job.job_id) {
		// applog(LOG_WARNING, "stratum_gen_work: job not yet retrieved");
		return false;
	}

	pthread_mutex_lock(&stratum->work_lock);

	// store the job ntime as high part of jobid
	snprintf(work->job_id, sizeof(work->job_id), "%07x %s",
		be32dec(sctx->job.ntime) & 0xfffffff, sctx->job.job_id);
	work->xnonce2_len = sctx->xnonce2_size;
	memcpy(work->xnonce2, sctx->job.xnonce2, sctx->xnonce2_size);

	// also store the block number
	work->height = sctx->job.height;
	// and the pool of the current stratum
	work->pooln = sctx->pooln;
	work->ctx = sctx;
	/* Generate merkle root */
	sha256d(merkle_root, sctx->job.coinbase, (int)sctx->job.coinbase_size);

	for (i = 0; i < sctx->job.merkle_count; i++) {
		memcpy(merkle_root + 32, sctx->job.merkle[i], 32);
		sha256d(merkle_root, merkle_root, 64);
	}
	
	/* Increment extranonce2 */
	for (i = 0; i < (int)sctx->xnonce2_size && !++sctx->job.xnonce2[i]; i++);
	
	/* Assemble block header */
	memset(work->data, 0, sizeof(work->data));
	work->data[0] = le32dec(sctx->job.version);
	
	for (i = 0; i < 8; i++)
	{
	    work->data[1 + i] = le32dec((uint32_t *)sctx->job.prevhash + i);
	}

	for (i = 0; i < 8; i++)
	{
		work->data[9 + i] = be32dec((uint32_t *)merkle_root + i);
	}
	work->data[17] = le32dec(sctx->job.ntime);
	work->data[18] = le32dec(sctx->job.nbits);
	work->data[20] = 0x80000000;
	work->data[31] = 0x00000280;

	if (opt_showdiff || opt_max_diff > 0.)
		calc_network_diff(work);

	pthread_mutex_unlock(&stratum->work_lock);

	if (opt_debug) {
		uint32_t utm = work->data[17];
		utm = swab32(utm);
		char *tm = atime2str(utm - sctx->srvtime_diff);
		char *xnonce2str = bin2hex(work->xnonce2, sctx->xnonce2_size);
		applog(LOG_DEBUG, "DEBUG: job_id=%s xnonce2=%s time=%s",
		       work->job_id, xnonce2str, tm);
		free(tm);
		free(xnonce2str);
	}

	if (opt_difficulty == 0.)
		opt_difficulty = 1.;

	work_set_target(work, sctx->job.diff / (256.0 * opt_difficulty));

	if (stratum->stratum_diff != sctx->job.diff) {
		char sdiff[32] = { 0 };
		// store for api stats
		stratum->stratum_diff = sctx->job.diff;
		if (opt_showdiff && work->targetdiff != stratum->stratum_diff)
			snprintf(sdiff, 32, " (%.5f)", work->targetdiff);
		applog(LOG_WARNING, "Stratum difficulty set to %g%s", stratum->stratum_diff, sdiff);
	}

	return true;
}

void restart_threads(void)
{
	if (opt_debug && !opt_quiet)
		applog(LOG_DEBUG,"%s", __FUNCTION__);

	for (int i = 0; i < opt_n_threads && work_restart; i++)
		work_restart[i].restart = 1;
}

//static bool wanna_mine(int thr_id, struct snarfs *sf)
static bool wanna_mine(struct stratum_ctx *ctx, int thr_id)
{
	bool state = true;
	bool allow_pool_rotate = (thr_id == 0 && ctx->num_pools > 1 && !ctx->pool_is_switching);

/*
	if ((thr_id == 0) && sf && sf->do_work && !stratum->pool_is_switching)
	{
		if (sf->want_to_enable ^ sf->enabled)
		{
			state = false;
			conditional_state[thr_id] = (uint8_t) !state; // only one wait message in logs
			return state;
		}
	}
*/	


	if (opt_max_temp > 0.0) {
#ifdef USE_WRAPNVML
		struct cgpu_info * cgpu = &thr_info[thr_id].gpu;
		float temp = gpu_temp(cgpu);
		if (temp > opt_max_temp) {
			if (!conditional_state[thr_id] && !opt_quiet)
				gpulog(LOG_INFO, thr_id, "temperature too high (%.0f°c), waiting...", temp);
			state = false;
		} else if (opt_max_temp > 0. && opt_resume_temp > 0. && conditional_state[thr_id] && temp > opt_resume_temp) {
			if (!thr_id && opt_debug)
				applog(LOG_DEBUG, "temperature did not reach resume value %.1f...", opt_resume_temp);
			state = false;
		}
#endif
	}
	// Network Difficulty
	if (opt_max_diff > 0.0 && net_diff > opt_max_diff) {
		int next = pool_get_first_valid(ctx, ctx->cur_pooln+1);
		if (ctx->num_pools > 1 && ctx->pools[next].max_diff != ctx->pools[ctx->cur_pooln].max_diff && opt_resume_diff <= 0.)
			ctx->conditional_pool_rotate = allow_pool_rotate;
		if (!thr_id && !conditional_state[thr_id] && !opt_quiet)
			applog(LOG_INFO, "network diff too high, waiting...");
		state = false;
	} else if (opt_max_diff > 0. && opt_resume_diff > 0. && conditional_state[thr_id] && net_diff > opt_resume_diff) {
		if (!thr_id && opt_debug)
			applog(LOG_DEBUG, "network diff did not reach resume value %.3f...", opt_resume_diff);
		state = false;
	}
	// Network hashrate
	if (opt_max_rate > 0.0 && net_hashrate > opt_max_rate) {
		int next = pool_get_first_valid(ctx, ctx->cur_pooln+1);
		if (ctx->pools[next].max_rate != ctx->pools[ctx->cur_pooln].max_rate && opt_resume_rate <= 0.)
			ctx->conditional_pool_rotate = allow_pool_rotate;
		if (!thr_id && !conditional_state[thr_id] && !opt_quiet) {
			char rate[32];
			format_hashrate(opt_max_rate, rate);
			applog(LOG_INFO, "network hashrate too high, waiting %s...", rate);
		}
		state = false;
	} else if (opt_max_rate > 0. && opt_resume_rate > 0. && conditional_state[thr_id] && net_hashrate > opt_resume_rate) {
		if (!thr_id && opt_debug)
			applog(LOG_DEBUG, "network rate did not reach resume value %.3f...", opt_resume_rate);
		state = false;
	}
	conditional_state[thr_id] = (uint8_t) !state; // only one wait message in logs
	return state;
}

static void *miner_thread(void *userdata)
{
	struct thr_info *mythr = (struct thr_info *)userdata;
	struct stratum_ctx * sctx = stratum;
	int thr_id = mythr->id;
	int dev_id = device_map[thr_id % MAX_GPUS];
	struct work work;
	uint64_t loopcnt = 0;
	uint32_t max_nonce;
	uint32_t end_nonce = UINT32_MAX / opt_n_threads * (thr_id + 1) - (thr_id + 1);
	bool work_done = false;
	bool extrajob = false;
	int thr_cur_pooln = 0;
	char s[16];
	int rc = 0;
	int work_count = 0;
	int remain; 

//	if ((thr_id == 0) && (!sf))
//	{
//		sf = new_snarfs();
//	}
	
	
	memset(&work, 0, sizeof(work)); // prevent work from being used uninitialized

	if (opt_priority > 0) {
		int prio = 2; // default to normal
#ifndef WIN32
		prio = 0;
		// note: different behavior on linux (-19 to 19)
		switch (opt_priority) {
			case 0:
				prio = 15;
				break;
			case 1:
				prio = 5;
				break;
			case 2:
				prio = 0; // normal process
				break;
			case 3:
				prio = -1; // above
				break;
			case 4:
				prio = -10;
				break;
			case 5:
				prio = -15;
		}
		if (opt_debug)
			applog(LOG_DEBUG, "Thread %d priority %d (nice %d)",
				thr_id,	opt_priority, prio);
#endif
		setpriority(PRIO_PROCESS, 0, prio);
		drop_policy();
	}

	/* Cpu thread affinity */
	if (num_cpus > 1) {
		if (opt_affinity == -1L && opt_n_threads > 1) {
			if (opt_debug)
				applog(LOG_DEBUG, "Binding thread %d to cpu %d (mask %x)", thr_id,
						thr_id % num_cpus, (1UL << (thr_id % num_cpus)));
			affine_to_cpu_mask(thr_id, 1 << (thr_id % num_cpus));
		} else if (opt_affinity != -1L) {
			if (opt_debug)
				applog(LOG_DEBUG, "Binding thread %d to cpu mask %lx", thr_id,
						(long) opt_affinity);
			affine_to_cpu_mask(thr_id, (unsigned long) opt_affinity);
		}
	}

	gpu_led_off(dev_id);

	while (!abort_flag) {
		struct timeval tv_start, tv_end, diff;
		unsigned long hashes_done;
		uint32_t start_nonce;
		uint32_t scan_time = opt_scantime;
		uint64_t max64, minmax = 0x100000;
		int nodata_check_oft = 0;
		bool regen = false;
		work_count++;
		remain = work_count % 100;
		
		if (remain == 50)
			sctx = &stratums[1];
		else if (remain == 51)
			sctx = &stratums[2];
		else
			sctx = &stratums[0];

		// &work.data[19]
		int wcmplen = 76;
		int wcmpoft = 0;

		uint32_t *nonceptr = (uint32_t*) (((char*)work.data) + wcmplen);

		uint32_t sleeptime = 0;

		while (!work_done && time(NULL) >= (g_work_time[sctx->id] + opt_scantime)) {
			usleep(100*1000);
			if (sleeptime > 4) {
				extrajob = true;
				break;
			}
			sleeptime++;
		}
		if (sleeptime && opt_debug && !opt_quiet)
			applog(LOG_DEBUG, "sleeptime: %u ms", sleeptime*100);
		nonceptr = (uint32_t*) (((char*)work.data) + wcmplen);
		pthread_mutex_lock(&g_work_lock[sctx->id]);
		extrajob |= work_done;

		regen = (nonceptr[0] >= end_nonce);
		regen = regen || extrajob;

		if (regen) {
			work_done = false;
			extrajob = false;
			if (stratum_gen_work(sctx, &g_work[sctx->id]))
			{
				g_work_time[sctx->id] = time(NULL);
				thr_cur_pooln = g_work[sctx->id].pooln;
			}
			
		}

		//if (thr_id == 0)
		//	determine_snarfing(sf);

		if (!opt_benchmark && (g_work[sctx->id].height != work.height || memcmp(work.target, g_work[sctx->id].target, sizeof(work.target))))
		{
			if (opt_debug) {
				uint64_t target64 = g_work[sctx->id].target[7] * 0x100000000ULL + g_work[sctx->id].target[6];
				applog(LOG_DEBUG, "job %s target change: %llx (%.1f)", g_work[sctx->id].job_id, target64, g_work[sctx->id].targetdiff);
			}
//			work.target = g_work.target;
			memcpy(work.target, g_work[sctx->id].target, sizeof(work.target));
			work.targetdiff = g_work[sctx->id].targetdiff;
			work.height = g_work[sctx->id].height;
			//nonceptr[0] = (UINT32_MAX / opt_n_threads) * thr_id; // 0 if single thr
		}


		if (memcmp(&work.data[wcmpoft], &g_work[sctx->id].data[wcmpoft], wcmplen)) {
			work = g_work[sctx->id];
			nonceptr[0] = (UINT32_MAX / opt_n_threads) * thr_id; // 0 if single thr
		} else
			nonceptr[0]++; //??

		if (opt_benchmark) {
			// randomize work
			nonceptr[-1] += 1;
		}

		pthread_mutex_unlock(&g_work_lock[sctx->id]);

		// --benchmark [-a all]
		if (opt_benchmark && bench_algo >= 0) {
			//gpulog(LOG_DEBUG, thr_id, "loop %d", loopcnt);
			if (loopcnt >= 3) {
				if (!bench_algo_switch_next(thr_id) && thr_id == 0)
				{
					bench_display_results();
					proper_exit(0);
					break;
				}
				loopcnt = 0;
			}
		}
		loopcnt++;

		// prevent gpu scans before a job is received
		nodata_check_oft = 0;
		if (work.data[nodata_check_oft] == 0 && !opt_benchmark) {
			sleep(1);
			if (!thr_id) stratum->pools[work.pooln].wait_time += 1;
			gpulog(LOG_DEBUG, thr_id, "no data");
			continue;
		}

		/* conditional mining */
		if (!wanna_mine(sctx, thr_id)) {

			// free gpu resources
			algo_free_all(thr_id);
			// clear any free error (algo switch)
			cuda_clear_lasterror();

			//if (snarf_time(sf, thr_id))
			//{
			//	continue;
			//}
			if (stratum->num_pools > 1 && stratum->conditional_pool_rotate) {
				if (!stratum->pool_is_switching)
					pool_switch_next(stratum, thr_id);
				else if (time(NULL) - firstwork_time > 35) {
					if (!opt_quiet)
						applog(LOG_WARNING, "Pool switching timed out...");
					if (!thr_id) stratum->pools[work.pooln].wait_time += 1;
					stratum->pool_is_switching = false;
				}
				sleep(1);
				continue;
			}

			stratum->pool_on_hold = true;
			global_hashrate = 0;
			sleep(5);
			if (!thr_id) stratum->pools[work.pooln].wait_time += 5;
			continue;
		}
		stratum->pool_on_hold = false;

		work_restart[thr_id].restart = 0;

		/* adjust max_nonce to meet target scan time */
		max64 = LP_SCANTIME;

		/* time limit */
		if (opt_time_limit > 0 && firstwork_time) {
			int passed = (int)(time(NULL) - firstwork_time);
			int remain = (int)(opt_time_limit - passed);
			if (remain < 0)  {
				if (thr_id != 0) {
					sleep(1); continue;
				}
				if (stratum->num_pools > 1 && stratum->pools[work.pooln].time_limit > 0) {
					if (!stratum->pool_is_switching) {
						if (!opt_quiet)
							applog(LOG_INFO, "Pool mining timeout of %ds reached, rotate...", opt_time_limit);
						pool_switch_next(stratum, thr_id);
					} else if (passed > 35) {
						// ensure we dont stay locked if pool_is_switching is not reset...
						applog(LOG_WARNING, "Pool switch to %d timed out...", work.pooln);
						if (!thr_id) stratum->pools[work.pooln].wait_time += 1;
						stratum->pool_is_switching = false;
					}
					sleep(1);
					continue;
				}
				app_exit_code = EXIT_CODE_TIME_LIMIT;
				abort_flag = true;
				if (opt_benchmark) {
					char rate[32];
					format_hashrate((double)global_hashrate, rate);
					applog(LOG_NOTICE, "Benchmark: %s", rate);
					usleep(200*1000);
					fprintf(stderr, "%llu\n", (long long unsigned int) global_hashrate);
				} else {
					applog(LOG_NOTICE, "Mining timeout of %ds reached, exiting...", opt_time_limit);
				}
				workio_abort();
				break;
			}
			if (remain < max64) max64 = remain;
		}

		/* shares limit */
		if (opt_shares_limit > 0 && firstwork_time) {
			int64_t shares = (stratum->pools[work.pooln].accepted_count + stratum->pools[work.pooln].rejected_count);
			if (shares >= opt_shares_limit) {
				int passed = (int)(time(NULL) - firstwork_time);
				if (thr_id != 0) {
					sleep(1); continue;
				}
				if (stratum->num_pools > 1 && stratum->pools[work.pooln].shares_limit > 0) {
					if (!stratum->pool_is_switching) {
						if (!opt_quiet)
							applog(LOG_INFO, "Pool shares limit of %d reached, rotate...", opt_shares_limit);
						pool_switch_next(stratum, thr_id);
					} else if (passed > 35) {
						// ensure we dont stay locked if pool_is_switching is not reset...
						applog(LOG_WARNING, "Pool switch to %d timed out...", work.pooln);
						if (!thr_id) stratum->pools[work.pooln].wait_time += 1;
						stratum->pool_is_switching = false;
					}
					sleep(1);
					continue;
				}
				abort_flag = true;
				app_exit_code = EXIT_CODE_OK;
				applog(LOG_NOTICE, "Mining limit of %d shares reached, exiting...", opt_shares_limit);
				workio_abort();
				break;
			}
		}

		max64 *= (uint32_t)thr_hashrates[thr_id];

		/* on start, max64 should not be 0,
		 *    before hashrate is computed */
		if (max64 < minmax) {
			minmax = 0x400000;
			max64 = max(minmax-1, max64);
		}

		// we can't scan more than uint32 capacity
		max64 = min(UINT32_MAX, max64);

		start_nonce = nonceptr[0];

		/* never let small ranges at end */
		if (end_nonce >= UINT32_MAX - 256)
			end_nonce = UINT32_MAX;

		if ((max64 + start_nonce) >= end_nonce)
			max_nonce = end_nonce;
		else
			max_nonce = (uint32_t) (max64 + start_nonce);

		// todo: keep it rounded to a multiple of 256 ?

		if (unlikely(start_nonce > max_nonce)) {
			// should not happen but seen in skein2 benchmark with 2 gpus
			max_nonce = end_nonce = UINT32_MAX;
		}

		work.scanned_from = start_nonce;

		gpulog(LOG_DEBUG, thr_id, "start=%08x end=%08x range=%08x",
			start_nonce, max_nonce, (max_nonce-start_nonce));

		if (opt_led_mode == LED_MODE_MINING)
			gpu_led_on(dev_id);

		hashes_done = 0;
		gettimeofday(&tv_start, NULL);

		// check (and reset) previous errors
		cudaError_t err = cudaGetLastError();
		if (err != cudaSuccess && !opt_quiet)
			gpulog(LOG_WARNING, thr_id, "%s", cudaGetErrorString(err));

		/* scan nonces for a proof-of-work hash */
		rc = scanhash_lyra2v2(thr_id, &work, max_nonce, &hashes_done);

		if (opt_led_mode == LED_MODE_MINING)
			gpu_led_off(dev_id);

		if (abort_flag)
			break; // time to leave the mining loop...

		if (work_restart[thr_id].restart)
			continue;

		/* record scanhash elapsed time */
		gettimeofday(&tv_end, NULL);

		// todo: update all algos to use work->nonces and pdata[19] as counter
		
		// algos with 2 results in pdata and work.nonces unset
		work.nonces[0] = nonceptr[0];
		work.nonces[1] = nonceptr[2];

		if (rc > 0 && opt_debug)
			applog(LOG_NOTICE, CL_CYN "found => %08x" CL_GRN " %08x", work.nonces[0], swab32(work.nonces[0]));
		if (rc > 1 && opt_debug)
			applog(LOG_NOTICE, CL_CYN "found => %08x" CL_GRN " %08x", work.nonces[1], swab32(work.nonces[1]));

		timeval_subtract(&diff, &tv_end, &tv_start);

		if (diff.tv_usec || diff.tv_sec) {
			double dtime = (double) diff.tv_sec + 1e-6 * diff.tv_usec;

			/* hashrate factors for some algos */
			double rate_factor = 1.0;

			/* store thread hashrate */
			if (dtime > 0.0) {
				pthread_mutex_lock(&stats_lock);
				thr_hashrates[thr_id] = hashes_done / dtime;
				thr_hashrates[thr_id] *= rate_factor;
				if (loopcnt > 2) // ignore first (init time)
					stats_remember_speed(thr_id, hashes_done, thr_hashrates[thr_id], (uint8_t) rc, work.height);
				pthread_mutex_unlock(&stats_lock);
			}
		}

		if (rc > 0)
			work.scanned_to = work.nonces[0];
		if (rc > 1)
			work.scanned_to = max(work.nonces[0], work.nonces[1]);
		else {
			work.scanned_to = max_nonce;
			if (opt_debug && opt_benchmark) {
				// to debug nonce ranges
				gpulog(LOG_DEBUG, thr_id, "ends=%08x range=%08x", nonceptr[0], (nonceptr[0] - start_nonce));
			}
			// prevent low scan ranges on next loop on fast algos (blake)
			if (nonceptr[0] > UINT32_MAX - 64)
				nonceptr[0] = UINT32_MAX;
		}

		if (check_dups)
			hashlog_remember_scan_range(&work);

		/* output */
		if (!opt_quiet && loopcnt > 1) {
			format_hashrate(thr_hashrates[thr_id], s);
			gpulog(LOG_INFO, thr_id, "%s, %s", device_name[dev_id], s);
		}

		/* ignore first loop hashrate */
		if (firstwork_time && thr_id == (opt_n_threads - 1)) {
			double hashrate = 0.;
			pthread_mutex_lock(&stats_lock);
			for (int i = 0; i < opt_n_threads && thr_hashrates[i]; i++)
				hashrate += stats_get_speed(i, thr_hashrates[i]);
			pthread_mutex_unlock(&stats_lock);
			if (opt_benchmark && bench_algo == -1 && loopcnt > 2) {
				format_hashrate(hashrate, s);
				applog(LOG_NOTICE, "Total: %s", s);
			}

			// since pool start
			stratum->pools[work.pooln].work_time = (uint32_t) (time(NULL) - firstwork_time);

			// X-Mining-Hashrate
			global_hashrate = llround(hashrate);
		}

		if (firstwork_time == 0)
			firstwork_time = time(NULL);

		/* if nonce found, submit work */
		if (rc > 0 && !opt_benchmark) {
			uint32_t curnonce = nonceptr[0]; // current scan position

			if (opt_led_mode == LED_MODE_SHARES)
				gpu_led_percent(dev_id, 50);

			nonceptr[0] = work.nonces[0];
			if (!submit_work(mythr, &work))
				break;
			nonceptr[0] = curnonce;

			// second nonce found, submit too (on pool only!)
			if (rc > 1 && work.nonces[1]) {
				nonceptr[0] = work.nonces[1];
				if (!submit_work(mythr, &work))
					break;
				nonceptr[0] = curnonce;
			}
		}
	}

out:
	if (opt_led_mode)
		gpu_led_off(dev_id);
	if (opt_debug_threads)
		applog(LOG_DEBUG, "%s() died", __func__);
	tq_freeze(mythr->q);
	return NULL;
}


static bool stratum_handle_response(struct stratum_ctx * ctx, char *buf)
{
	json_t *val, *err_val, *res_val, *id_val;
	json_error_t err;
	struct timeval tv_answer, diff;
	int num = 0;
	bool ret = false;

	val = JSON_LOADS(buf, &err);
	if (!val) {
		applog(LOG_INFO, "JSON decode failed(%d): %s", err.line, err.text);
		goto out;
	}

	res_val = json_object_get(val, "result");
	err_val = json_object_get(val, "error");
	id_val = json_object_get(val, "id");

	if (!id_val || json_is_null(id_val) || !res_val)
		goto out;

	// ignore late login answers
	num = (int) json_integer_value(id_val);
	if (num < 4)
		goto out;

	// todo: use request id to index nonce diff data
	// num = num % 10;

	gettimeofday(&tv_answer, NULL);
	timeval_subtract(&diff, &tv_answer, &ctx->tv_submit);
	// store time required to the pool to answer to a submit
	ctx->answer_msec = (1000 * diff.tv_sec) + (uint32_t) (0.001 * diff.tv_usec);

	share_result(ctx, json_is_true(res_val), ctx->pooln, ctx->sharediff,
		err_val ? json_string_value(json_array_get(err_val, 1)) : NULL);

	ret = true;
out:
	if (val)
		json_decref(val);

	return ret;
}

static void *stratum_thread(void *userdata)
{
	struct thr_info *mythr = (struct thr_info *)userdata;
	struct pool_infos *pool;
	struct stratum_ctx *sctx = NULL;
	int pooln, switchn;
	char *s;

	for (int i =0; i < MAX_STRATUM_THREADS; i++)
	{
		if (stratums[i].thread == mythr)
		{
			sctx = &stratums[i];
			break;
		}
	}
	if (!sctx)
	{
		goto out;
	}

wait_stratum_url:
	sctx->url = (char*)tq_pop(mythr->q, NULL);
			
	if (!sctx->url)
	{
		goto out;
	}

	if ((!sctx->pool_is_switching) && (sctx->id == 0))
		applog(LOG_BLUE, "Starting on %s", sctx->url);

	sctx->pooln = pooln = sctx->cur_pooln;
	switchn = sctx->pool_switch_count;
	pool = &sctx->pools[pooln];

	sctx->pool_is_switching = false;
	sctx->need_reset = false;

	while (!abort_flag) {
		int failures = 0;

		if (sctx->need_reset) {
			sctx->need_reset = false;
			if (sctx->url)
				stratum_disconnect(sctx);
		}

		while (!sctx->curl && !abort_flag) {
			pthread_mutex_lock(&g_work_lock[sctx->id]);
			g_work_time[sctx->id] = 0;
			g_work[sctx->id].data[0] = 0;
			pthread_mutex_unlock(&g_work_lock[sctx->id]);
			restart_threads();

			if (!stratum_connect(sctx, pool->url) ||
			    !stratum_subscribe(sctx) ||
			    !stratum_authorize(sctx, pool->user, pool->pass))
			{
				stratum_disconnect(sctx);
				if (opt_retries >= 0 && ++failures > opt_retries) {
					if (sctx->num_pools > 1 && opt_pool_failover) {
						applog(LOG_WARNING, "Stratum connect timeout, failover...");
						pool_switch_next(sctx, -1);
					} else {
						applog(LOG_ERR, "...terminating workio thread");
						//tq_push(thr_info[work_thr_id].q, NULL);
						workio_abort();
						proper_exit(EXIT_CODE_POOL_TIMEOUT);
						goto out;
					}
				}
				if (switchn != sctx->pool_switch_count)
					goto pool_switched;
				if (!opt_benchmark)
					applog(LOG_ERR, "...retry after %d seconds", opt_fail_pause);
				sleep(opt_fail_pause);
			}
		}

		if (switchn != sctx->pool_switch_count) goto pool_switched;

		if (sctx->job.job_id &&
		    (!g_work_time[sctx->id] || strncmp(sctx->job.job_id, g_work[sctx->id].job_id + 8, sizeof(g_work[sctx->id].job_id)-8))) {
			pthread_mutex_lock(&g_work_lock[sctx->id]);
			if (stratum_gen_work(sctx, &g_work[sctx->id]))
			{
				g_work_time[sctx->id] = time(NULL);
			}
			if (sctx->job.clean) {
				static uint32_t last_bloc_height;
				if (!opt_quiet && sctx->job.height != last_bloc_height) {
					last_bloc_height = sctx->job.height;
					if (net_diff > 0.)
						applog(LOG_BLUE, "%s block %d, diff %.3f", algo_names[opt_algo],
							sctx->job.height, net_diff);
					else
						applog(LOG_BLUE, "%s %s block %d", pool->short_url, algo_names[opt_algo],
							sctx->job.height);
				}
				restart_threads();
				if (check_dups)
					hashlog_purge_old();
				stats_purge_old();
			} else if (opt_debug && !opt_quiet) {
					applog(LOG_BLUE, "%s asks job %d for block %d", pool->short_url,
						strtoul(sctx->job.job_id, NULL, 16), sctx->job.height);
			}
			pthread_mutex_unlock(&g_work_lock[sctx->id]);
		}
		
		// check we are on the right pool
		if (switchn != sctx->pool_switch_count) goto pool_switched;

		if (!stratum_socket_full(sctx, opt_timeout)) {
			if (opt_debug)
				applog(LOG_WARNING, "Stratum connection timed out");
			s = NULL;
		} else
			s = stratum_recv_line(sctx);

		// double check we are on the right pool
		if (switchn != sctx->pool_switch_count) goto pool_switched;

		if (!s) {
			stratum_disconnect(sctx);
			if (!opt_quiet && !sctx->pool_on_hold)
				applog(LOG_WARNING, "Stratum connection interrupted");
			continue;
		}
		if (!stratum_handle_method(sctx, s))
			stratum_handle_response(sctx, s);
		free(s);
	}

out:
	if (opt_debug_threads)
		applog(LOG_DEBUG, "%s() died", __func__);

	return NULL;

pool_switched:
	/* this thread should not die on pool switch */
	stratum_disconnect(sctx);
	if (sctx->url) free(sctx->url); sctx->url = NULL;
	if (opt_debug_threads)
		applog(LOG_DEBUG, "%s() reinit...", __func__);
	goto wait_stratum_url;
}

static void show_version_and_exit(void)
{
	printf("%s v%s\n"
#ifdef WIN32
		"pthreads static %s\n"
#endif
		"%s\n",
		PACKAGE_NAME, PACKAGE_VERSION,
#ifdef WIN32
		PTW32_VERSION_STRING,
#endif
		curl_version());
	proper_exit(EXIT_CODE_OK);
}

static void show_usage_and_exit(int status)
{
	if (status)
		fprintf(stderr, "Try `" PROGRAM_NAME " --help' for more information.\n");
	else
		printf(usage);
	proper_exit(status);
}

static const char b58digits[] = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

static bool b58dec(unsigned char *bin, size_t binsz, const char *b58)
{
	size_t i, j;
	uint64_t t;
	uint32_t c;
	uint32_t *outi;
	size_t outisz = (binsz + 3) / 4;
	int rem = binsz % 4;
	uint32_t remmask = 0xffffffff << (8 * rem);
	size_t b58sz = strlen(b58);
	bool rc = false;

	outi = (uint32_t *)calloc(outisz, sizeof(*outi));

	for (i = 0; i < b58sz; ++i) {
		for (c = 0; b58digits[c] != b58[i]; c++)
			if (!b58digits[c])
				goto out;
		for (j = outisz; j--;) {
			t = (uint64_t)outi[j] * 58 + c;
			c = t >> 32;
			outi[j] = t & 0xffffffff;
		}
		if (c || outi[0] & remmask)
			goto out;
	}

	j = 0;
	switch (rem) {
	case 3:
		*(bin++) = (outi[0] >> 16) & 0xff;
	case 2:
		*(bin++) = (outi[0] >> 8) & 0xff;
	case 1:
		*(bin++) = outi[0] & 0xff;
		++j;
	default:
		break;
	}
	for (; j < outisz; ++j) {
		be32enc((uint32_t *)bin, outi[j]);
		bin += sizeof(uint32_t);
	}

	rc = true;
out:
	free(outi);
	return rc;
}

static int b58check(unsigned char *bin, size_t binsz, const char *b58)
{
	unsigned char buf[32];
	int i;

	sha256d(buf, bin, (int)(binsz - 4));
	if (memcmp(&bin[binsz - 4], buf, 4))
		return -1;

	/* Check number of zeros is correct AFTER verifying checksum
	* (to avoid possibility of accessing the string beyond the end) */
	for (i = 0; bin[i] == '\0' && b58[i] == '1'; ++i);
	if (bin[i] == '\0' || b58[i] == '1')
		return -3;

	return bin[0];
}

size_t address_to_script(unsigned char *out, size_t outsz, const char *addr)
{
	unsigned char addrbin[25];
	int addrver;
	size_t rv;

	if (!b58dec(addrbin, sizeof(addrbin), addr))
		return 0;
	addrver = b58check(addrbin, sizeof(addrbin), addr);
	if (addrver < 0)
		return 0;
	switch (addrver) {
	case 5:    /* Bitcoin script hash */
	case 196:  /* Testnet script hash */
		if (outsz < (rv = 23))
			return rv;
		out[0] = 0xa9;  /* OP_HASH160 */
		out[1] = 0x14;  /* push 20 bytes */
		memcpy(&out[2], &addrbin[1], 20);
		out[22] = 0x87;  /* OP_EQUAL */
		return rv;
	default:
		if (outsz < (rv = 25))
			return rv;
		out[0] = 0x76;  /* OP_DUP */
		out[1] = 0xa9;  /* OP_HASH160 */
		out[2] = 0x14;  /* push 20 bytes */
		memcpy(&out[3], &addrbin[1], 20);
		out[23] = 0x88;  /* OP_EQUALVERIFY */
		out[24] = 0xac;  /* OP_CHECKSIG */
		return rv;
	}
}

void parse_arg(int key, char *arg)
{
	char *p = arg;
	int v, i;
	uint64_t ul;
	double d;

	switch(key) {
	case 'a':
		break;
	case 'b':
		p = strstr(arg, ":");
		if (p) {
			/* ip:port */
			if (p - arg > 0) {
				free(opt_api_allow);
				opt_api_allow = strdup(arg);
				opt_api_allow[p - arg] = '\0';
			}
			opt_api_listen = atoi(p + 1);
		}
		else if (arg && strstr(arg, ".")) {
			/* ip only */
			free(opt_api_allow);
			opt_api_allow = strdup(arg);
		}
		else if (arg) {
			/* port or 0 to disable */
			opt_api_listen = atoi(arg);
		}
		break;
	case 1030: /* --api-remote */
		opt_api_remote = 1;
		break;
	case 1081:
		opt_eco_mode = true;
		break;
	case 'B':
		opt_background = true;
		break;
	case 'c': {
		json_error_t err;
		if (opt_config) {
			json_decref(opt_config);
			opt_config = NULL;
		}
		if (arg && strstr(arg, "://")) {
			opt_config = json_load_url(arg, &err);
		} else {
			opt_config = JSON_LOADF(arg, &err);
		}
		if (!json_is_object(opt_config)) {
			applog(LOG_ERR, "JSON decode of %s failed", arg);
			proper_exit(EXIT_CODE_USAGE);
		}
		break;
	}
	case 'i':
		d = atof(arg);
		v = (uint32_t) d;
		if (v < 0 || v > 31)
			show_usage_and_exit(1);
		{
			int n = 0;
			int ngpus = cuda_num_devices();
			uint32_t last = 0;
			char * pch = strtok(arg,",");
			while (pch != NULL) {
				d = atof(pch);
				v = (uint32_t) d;
				if (v > 7) { /* 0 = default */
					if ((d - v) > 0.0) {
						uint32_t adds = (uint32_t)floor((d - v) * (1 << (v - 8))) * 256;
						gpus_intensity[n] = (1 << v) + adds;
						applog(LOG_INFO, "Intensity set to %f, %u cuda threads",
							d, gpus_intensity[n]);
					}
					else if (gpus_intensity[n] != (1 << v)) {
						gpus_intensity[n] = (1 << v);
						applog(LOG_INFO, "Intensity set to %f, %u cuda threads",
							d, gpus_intensity[n]);
					}
				}
				last = gpus_intensity[n];
				n++;
				pch = strtok(NULL, ",");
			}
			while (n < MAX_GPUS)
				gpus_intensity[n++] = last;
		}
		break;
	case 'D':
		opt_debug = true;
		break;
	case 'N':
		v = atoi(arg);
		if (v < 1)
			opt_statsavg = INT_MAX;
		opt_statsavg = v;
		break;
	case 'n': /* --ndevs */
		// to get gpu vendors...
		#ifdef USE_WRAPNVML
		hnvml = nvml_create();
		#ifdef WIN32
		nvapi_init();
		cuda_devicenames(); // req for leds
		nvapi_init_settings();
		#endif
		#endif
		cuda_print_devices();
		proper_exit(EXIT_CODE_OK);
		break;
	case 'q':
		opt_quiet = true;
		break;
	case 'p':
		free(rpc_pass);
		rpc_pass = strdup(arg);
		pool_set_creds(&stratum->pools[0], rpc_url, short_url, rpc_user, rpc_pass);
		break;
	case 'P':
		opt_protocol = true;
		break;
	case 'r':
		v = atoi(arg);
		if (v < -1 || v > 9999)	/* sanity check */
			show_usage_and_exit(1);
		opt_retries = v;
		break;
	case 'R':
		v = atoi(arg);
		if (v < 1 || v > 9999)	/* sanity check */
			show_usage_and_exit(1);
		opt_fail_pause = v;
		break;
	case 's':
		v = atoi(arg);
		if (v < 1 || v > 9999)	/* sanity check */
			show_usage_and_exit(1);
		opt_scantime = v;
		break;
	case 'T':
		v = atoi(arg);
		if (v < 1 || v > 99999)	/* sanity check */
			show_usage_and_exit(1);
		opt_timeout = v;
		break;
	case 't':
		v = atoi(arg);
		if (v < 0 || v > 9999)	/* sanity check */
			show_usage_and_exit(1);
		opt_n_threads = v;
		break;
	case 1022: // --vote
		v = atoi(arg);
		if (v < 0 || v > 8192)	/* sanity check */
			show_usage_and_exit(1);
		opt_vote = (uint16_t)v;
		break;
	case 1023: // --trust-pool
		opt_trust_pool = true;
		break;
	case 'u':
		free(rpc_user);
		rpc_user = strdup(arg);
		pool_set_creds(&stratum->pools[stratum->cur_pooln], rpc_url, short_url, rpc_user, rpc_pass);
		break;
	case 'o':			/* --url */
		if (stratum->pools[stratum->cur_pooln].type != POOL_UNUSED) {
			// rotate pool pointer
			stratum->cur_pooln = (stratum->cur_pooln + 1) % MAX_POOLS;
			stratum->num_pools = max(stratum->cur_pooln+1, stratum->num_pools);
			// change some defaults if multi pools
			if (opt_retries == -1) opt_retries = 1;
			if (opt_fail_pause == 30) opt_fail_pause = 5;
			if (opt_timeout == 300) opt_timeout = 60;
		}
		p = strstr(arg, "://");
		if (p) {
			if (strncasecmp(arg, "http://", 7) && strncasecmp(arg, "https://", 8) &&
					strncasecmp(arg, "stratum+tcp://", 14))
				show_usage_and_exit(1);
			free(rpc_url);
			rpc_url = strdup(arg);
			short_url = &rpc_url[(p - arg) + 3];
		} else {
			if (!strlen(arg) || *arg == '/')
				show_usage_and_exit(1);
			free(rpc_url);
			rpc_url = (char*)malloc(strlen(arg) + 8);
			sprintf(rpc_url, "http://%s", arg);
			short_url = &rpc_url[7];
		}
		p = strrchr(rpc_url, '@');
		if (p) {
			char *sp, *ap;
			*p = '\0';
			ap = strstr(rpc_url, "://") + 3;
			sp = strchr(ap, ':');
			if (sp && sp < p) {
				free(rpc_user);
				rpc_user = (char*)calloc(sp - ap + 1, 1);
				strncpy(rpc_user, ap, sp - ap);
				free(rpc_pass);
				rpc_pass = strdup(sp + 1);
			} else {
				free(rpc_user);
				rpc_user = strdup(ap);
			}
			// remove user[:pass]@ from rpc_url
			memmove(ap, p + 1, strlen(p + 1) + 1);
			// host:port only
			short_url = ap;
		}
		pool_set_creds(&stratum->pools[stratum->cur_pooln], rpc_url, short_url, rpc_user, rpc_pass);
		break;
	case 'O':			/* --userpass */
		p = strchr(arg, ':');
		if (!p)
			show_usage_and_exit(1);
		free(rpc_user);
		rpc_user = (char*)calloc(p - arg + 1, 1);
		strncpy(rpc_user, arg, p - arg);
		free(rpc_pass);
		rpc_pass = strdup(p + 1);
		pool_set_creds(&stratum->pools[stratum->cur_pooln], rpc_url, short_url, rpc_user, rpc_pass);
		break;
	case 'x':			/* --proxy */
		if (!strncasecmp(arg, "socks4://", 9))
			opt_proxy_type = CURLPROXY_SOCKS4;
		else if (!strncasecmp(arg, "socks5://", 9))
			opt_proxy_type = CURLPROXY_SOCKS5;
#if LIBCURL_VERSION_NUM >= 0x071200
		else if (!strncasecmp(arg, "socks4a://", 10))
			opt_proxy_type = CURLPROXY_SOCKS4A;
		else if (!strncasecmp(arg, "socks5h://", 10))
			opt_proxy_type = CURLPROXY_SOCKS5_HOSTNAME;
#endif
		else
			opt_proxy_type = CURLPROXY_HTTP;
		free(opt_proxy);
		opt_proxy = strdup(arg);
		pool_set_creds(&stratum->pools[stratum->cur_pooln], rpc_url, short_url, rpc_user, rpc_pass);
		break;
	case 1001:
		free(opt_cert);
		opt_cert = strdup(arg);
		break;
	case 1002:
		use_colors = false;
		break;
	case 1004:
		opt_autotune = false;
		break;
	case 'l': /* scrypt --launch-config */
		{
			char *last = NULL, *pch = strtok(arg,",");
			int n = 0;
			while (pch != NULL) {
				device_config[n++] = last = strdup(pch);
				pch = strtok(NULL, ",");
			}
			while (n < MAX_GPUS)
				device_config[n++] = last;
		}
		break;
	case 'L': /* scrypt --lookup-gap */
		{
			char *pch = strtok(arg,",");
			int n = 0, last = atoi(arg);
			while (pch != NULL) {
				device_lookup_gap[n++] = last = atoi(pch);
				pch = strtok(NULL, ",");
			}
			while (n < MAX_GPUS)
				device_lookup_gap[n++] = last;
		}
		break;
	case 1050: /* scrypt --interactive */
		{
			char *pch = strtok(arg,",");
			int n = 0, last = atoi(arg);
			while (pch != NULL) {
				device_interactive[n++] = last = atoi(pch);
				pch = strtok(NULL, ",");
			}
			while (n < MAX_GPUS)
				device_interactive[n++] = last;
		}
		break;
	case 1051: /* scrypt --texture-cache */
		{
			char *pch = strtok(arg,",");
			int n = 0, last = atoi(arg);
			while (pch != NULL) {
				device_texturecache[n++] = last = atoi(pch);
				pch = strtok(NULL, ",");
			}
			while (n < MAX_GPUS)
				device_texturecache[n++] = last;
		}
		break;
	case 1070: /* --gpu-clock */
		{
			char *pch = strtok(arg,",");
			int n = 0;
			while (pch != NULL && n < MAX_GPUS) {
				int dev_id = device_map[n++];
				device_gpu_clocks[dev_id] = atoi(pch);
				pch = strtok(NULL, ",");
			}
		}
		break;
	case 1071: /* --mem-clock */
		{
			char *pch = strtok(arg,",");
			int n = 0;
			while (pch != NULL && n < MAX_GPUS) {
				int dev_id = device_map[n++];
				device_mem_clocks[dev_id] = atoi(pch);
				pch = strtok(NULL, ",");
			}
		}
		break;
	case 1072: /* --pstate */
		{
			char *pch = strtok(arg,",");
			int n = 0;
			while (pch != NULL && n < MAX_GPUS) {
				int dev_id = device_map[n++];
				device_pstate[dev_id] = (int8_t) atoi(pch);
				pch = strtok(NULL, ",");
			}
		}
		break;
	case 1073: /* --plimit */
		{
			char *pch = strtok(arg,",");
			int n = 0;
			while (pch != NULL && n < MAX_GPUS) {
				int dev_id = device_map[n++];
				device_plimit[dev_id] = atoi(pch);
				pch = strtok(NULL, ",");
			}
		}
		break;
	case 1074: /* --keep-clocks */
		opt_keep_clocks = true;
		break;
	case 1075: /* --tlimit */
		{
			char *pch = strtok(arg,",");
			int n = 0;
			while (pch != NULL && n < MAX_GPUS) {
				int dev_id = device_map[n++];
				device_tlimit[dev_id] = (uint8_t) atoi(pch);
				pch = strtok(NULL, ",");
			}
		}
		break;
	case 1080: /* --led */
		{
			if (!opt_led_mode)
				opt_led_mode = LED_MODE_SHARES;
			char *pch = strtok(arg,",");
			int n = 0, lastval, val;
			while (pch != NULL && n < MAX_GPUS) {
				int dev_id = device_map[n++];
				char * p = strstr(pch, "0x");
				val = p ? (int32_t) strtoul(p, NULL, 16) : atoi(pch);
				if (!val && !strcmp(pch, "mining"))
					opt_led_mode = LED_MODE_MINING;
				else if (device_led[dev_id] == -1)
					device_led[dev_id] = lastval = val;
				pch = strtok(NULL, ",");
			}
			if (lastval) while (n < MAX_GPUS) {
				device_led[n++] = lastval;
			}
		}
		break;
	case 1005:
		opt_benchmark = true;
		break;
	case 1006:
		print_hash_tests();
		proper_exit(EXIT_CODE_OK);
		break;
	case 1003:
		break;
	case 1007:
		opt_extranonce = false;
		break;
	case 1008:
		opt_time_limit = atoi(arg);
		break;
	case 1009:
		opt_shares_limit = atoi(arg);
		break;
	case 1010:
		break;
	case 1011:
		break;
	case 1016:			/* --coinbase-addr */
		pk_script_size = address_to_script(pk_script, sizeof(pk_script), arg);
		if (!pk_script_size) {
			fprintf(stderr, "invalid address -- '%s'\n", arg);
			show_usage_and_exit(1);
		}
		break;
	case 1012:
		opt_extranonce = false;
		break;
	case 1013:
		opt_showdiff = true;
		break;
	case 1014:
		opt_showdiff = false;
		break;
	case 'S':
	case 1018:
		applog(LOG_INFO, "Now logging to syslog...");
		use_syslog = true;
		if (arg && strlen(arg)) {
			free(opt_syslog_pfx);
			opt_syslog_pfx = strdup(arg);
		}
		break;
	case 1020:
		p = strstr(arg, "0x");
		ul = p ? strtoul(p, NULL, 16) : atol(arg);
		if (ul > (1UL<<num_cpus)-1)
			ul = -1L;
		opt_affinity = ul;
		break;
	case 1021:
		v = atoi(arg);
		if (v < 0 || v > 5)	/* sanity check */
			show_usage_and_exit(1);
		opt_priority = v;
		break;
	case 1025: // cuda-schedule
		opt_cudaschedule = atoi(arg);
		break;
	case 1060: // max-temp
		d = atof(arg);
		opt_max_temp = d;
		break;
	case 1061: // max-diff
		d = atof(arg);
		opt_max_diff = d;
		break;
	case 1062: // max-rate
		d = atof(arg);
		p = strstr(arg, "K");
		if (p) d *= 1e3;
		p = strstr(arg, "M");
		if (p) d *= 1e6;
		p = strstr(arg, "G");
		if (p) d *= 1e9;
		opt_max_rate = d;
		break;
	case 1063: // resume-diff
		d = atof(arg);
		opt_resume_diff = d;
		break;
	case 1064: // resume-rate
		d = atof(arg);
		p = strstr(arg, "K");
		if (p) d *= 1e3;
		p = strstr(arg, "M");
		if (p) d *= 1e6;
		p = strstr(arg, "G");
		if (p) d *= 1e9;
		opt_resume_rate = d;
		break;
	case 1065: // resume-temp
		d = atof(arg);
		opt_resume_temp = d;
		break;
	case 'd': // --device
		{
			int device_thr[MAX_GPUS] = { 0 };
			int ngpus = cuda_num_devices();
			char * pch = strtok (arg,",");
			opt_n_threads = 0;
			while (pch != NULL && opt_n_threads < MAX_GPUS) {
				if (pch[0] >= '0' && pch[0] <= '9' && pch[1] == '\0')
				{
					if (atoi(pch) < ngpus)
						device_map[opt_n_threads++] = atoi(pch);
					else {
						applog(LOG_ERR, "Non-existant CUDA device #%d specified in -d option", atoi(pch));
						proper_exit(EXIT_CODE_CUDA_NODEVICE);
					}
				} else {
					int device = cuda_finddevice(pch);
					if (device >= 0 && device < ngpus)
						device_map[opt_n_threads++] = device;
					else {
						applog(LOG_ERR, "Non-existant CUDA device '%s' specified in -d option", pch);
						proper_exit(EXIT_CODE_CUDA_NODEVICE);
					}
				}
				pch = strtok (NULL, ",");
			}
			// count threads per gpu
			for (int n=0; n < opt_n_threads; n++) {
				int device = device_map[n];
				device_thr[device]++;
			}
			for (int n=0; n < ngpus; n++) {
				gpu_threads = max(gpu_threads, device_thr[n]);
			}
		}
		break;

	case 'f': // --diff-factor
		d = atof(arg);
		if (d <= 0.)
			show_usage_and_exit(1);
		opt_difficulty = d;
		break;
	case 'm': // --diff-multiplier
		d = atof(arg);
		if (d <= 0.)
			show_usage_and_exit(1);
		opt_difficulty = 1.0/d;
		break;

	/* PER POOL CONFIG OPTIONS */

	case 1100: /* pool name */
		pool_set_attr(&stratum->pools[stratum->cur_pooln], "name", arg);
		break;
	case 1101: /* pool algo */
		pool_set_attr(&stratum->pools[stratum->cur_pooln], "algo", arg);
		break;
	case 1102: /* pool scantime */
		pool_set_attr(&stratum->pools[stratum->cur_pooln], "scantime", arg);
		break;
	case 1108: /* pool time-limit */
		pool_set_attr(&stratum->pools[stratum->cur_pooln], "time-limit", arg);
		break;
	case 1109: /* pool shares-limit (1.7.6) */
		pool_set_attr(&stratum->pools[stratum->cur_pooln], "shares-limit", arg);
		break;
	case 1161: /* pool max-diff */
		pool_set_attr(&stratum->pools[stratum->cur_pooln], "max-diff", arg);
		break;
	case 1162: /* pool max-rate */
		pool_set_attr(&stratum->pools[stratum->cur_pooln], "max-rate", arg);
		break;
	case 1199:
		pool_set_attr(&stratum->pools[stratum->cur_pooln], "disabled", arg);
		break;

	case 'V':
		show_version_and_exit();
	case 'h':
		show_usage_and_exit(0);
	default:
		show_usage_and_exit(1);
	}

	if (use_syslog)
		use_colors = false;
}

void parse_config(json_t* json_obj)
{
	int i;
	json_t *val;

	if (!json_is_object(json_obj))
		return;

	for (i = 0; i < ARRAY_SIZE(options); i++) {

		if (!options[i].name)
			break;

		if (!strcasecmp(options[i].name, "config"))
			continue;

		val = json_object_get(json_obj, options[i].name);
		if (!val)
			continue;

		if (options[i].has_arg && json_is_string(val)) {
			char *s = strdup(json_string_value(val));
			if (!s)
				continue;
			parse_arg(options[i].val, s);
			free(s);
		}
		else if (options[i].has_arg && json_is_integer(val)) {
			char buf[16];
			sprintf(buf, "%d", (int) json_integer_value(val));
			parse_arg(options[i].val, buf);
		}
		else if (options[i].has_arg && json_is_real(val)) {
			char buf[16];
			sprintf(buf, "%f", json_real_value(val));
			parse_arg(options[i].val, buf);
		}
		else if (!options[i].has_arg) {
			if (json_is_true(val))
				parse_arg(options[i].val, (char*) "");
		}
		else
			applog(LOG_ERR, "JSON option %s invalid",
				options[i].name);
	}

	val = json_object_get(json_obj, "pools");
	if (val && json_typeof(val) == JSON_ARRAY) {
		parse_pool_array(val);
	}
}

static void parse_cmdline(int argc, char *argv[])
{
	int key;

	while (1) {
#if HAVE_GETOPT_LONG
		key = getopt_long(argc, argv, short_options, options, NULL);
#else
		key = getopt(argc, argv, short_options);
#endif
		if (key < 0)
			break;

		parse_arg(key, optarg);
	}
	if (optind < argc) {
		fprintf(stderr, "%s: unsupported non-option argument '%s' (see --help)\n",
			argv[0], argv[optind]);
		//show_usage_and_exit(1);
	}

	parse_config(opt_config);

	if (opt_vote == 9999) {
		opt_vote = 0; // default, don't vote
	}
}

#ifndef WIN32
static void signal_handler(int sig)
{
	switch (sig) {
	case SIGHUP:
		applog(LOG_INFO, "SIGHUP received");
		break;
	case SIGINT:
		signal(sig, SIG_IGN);
		applog(LOG_INFO, "SIGINT received, exiting");
		proper_exit(EXIT_CODE_KILLED);
		break;
	case SIGTERM:
		applog(LOG_INFO, "SIGTERM received, exiting");
		proper_exit(EXIT_CODE_KILLED);
		break;
	}
}
#else
BOOL WINAPI ConsoleHandler(DWORD dwType)
{
	switch (dwType) {
	case CTRL_C_EVENT:
		applog(LOG_INFO, "CTRL_C_EVENT received, exiting");
		proper_exit(EXIT_CODE_KILLED);
		break;
	case CTRL_BREAK_EVENT:
		applog(LOG_INFO, "CTRL_BREAK_EVENT received, exiting");
		proper_exit(EXIT_CODE_KILLED);
		break;
	case CTRL_LOGOFF_EVENT:
		applog(LOG_INFO, "CTRL_LOGOFF_EVENT received, exiting");
		proper_exit(EXIT_CODE_KILLED);
		break;
	case CTRL_SHUTDOWN_EVENT:
		applog(LOG_INFO, "CTRL_SHUTDOWN_EVENT received, exiting");
		proper_exit(EXIT_CODE_KILLED);
		break;
	default:
		return false;
	}
	return true;
}
#endif

int main(int argc, char *argv[])
{
	struct thr_info *thr;
	long flags;
	int i;

	printf("*** vertminer " PACKAGE_VERSION " for nVidia GPUs by turekaj ***\n");
#ifdef _MSC_VER
	printf("    Built with VC++ %d and nVidia CUDA SDK %d.%d\n\n", msver(),
#else
	printf("    Built with the nVidia CUDA Toolkit %d.%d\n\n",
#endif
		CUDART_VERSION/1000, (CUDART_VERSION % 1000)/10);
	printf("  Originally based on tpruvot ccminer\n");
	printf("VTC donation address:  VdMVwYLairTcYhz3QnNZtDNrB2wpaHE21q (turekaj)\n\n");
	printf("1 percent dev fee to turekaj for miner improvements \n");
	printf("1 percent dev fee to Vertcoin Dev Team (vertcoin.org) \n");

	/* init stratum data.. */
	for (int i=0; i < MAX_STRATUM_THREADS; i++)
	{
		memset(&stratums[i], 0, sizeof(struct stratum_ctx));
		stratums[i].id = i;
		stratums[i].sock_lock = PTHREAD_MUTEX_INITIALIZER;
		stratums[i].work_lock = PTHREAD_MUTEX_INITIALIZER;
		g_work_lock[i] = PTHREAD_MUTEX_INITIALIZER;
		pthread_mutex_init(&stratums[i].sock_lock, NULL);
		pthread_mutex_init(&stratums[i].work_lock, NULL);
		pthread_mutex_init(&g_work_lock[i], NULL);
	}
	stratum = &stratums[0];

	rpc_user = strdup("");
	rpc_pass = strdup("");
	rpc_url = strdup("");

	pthread_mutex_init(&applog_lock, NULL);
	pthread_mutex_init(&stats_lock, NULL);

	// number of cpus for thread affinity
#if defined(WIN32)
	SYSTEM_INFO sysinfo;
	GetSystemInfo(&sysinfo);
	num_cpus = sysinfo.dwNumberOfProcessors;
#elif defined(_SC_NPROCESSORS_CONF)
	num_cpus = sysconf(_SC_NPROCESSORS_CONF);
#elif defined(CTL_HW) && defined(HW_NCPU)
	int req[] = { CTL_HW, HW_NCPU };
	size_t len = sizeof(num_cpus);
	sysctl(req, 2, &num_cpus, &len, NULL, 0);
#else
	num_cpus = 1;
#endif
	if (num_cpus < 1)
		num_cpus = 1;

	// number of gpus
	active_gpus = cuda_num_devices();

	for (i = 0; i < MAX_GPUS; i++) {
		device_map[i] = i % active_gpus;
		device_name[i] = NULL;
		device_config[i] = NULL;
		device_backoff[i] = is_windows() ? 12 : 2;
		device_lookup_gap[i] = 1;
		device_batchsize[i] = 1024;
		device_interactive[i] = -1;
		device_texturecache[i] = -1;
		device_singlememory[i] = -1;
		device_pstate[i] = -1;
		device_led[i] = -1;
	}

	cuda_devicenames();

	/* parse command line */
	parse_cmdline(argc, argv);

	// extra credits..

	if (!opt_benchmark && !strlen(rpc_url)) {
		// try default config file (user then binary folder)
		char defconfig[MAX_PATH] = { 0 };
		get_defconfig_path(defconfig, MAX_PATH, argv[0]);
		if (strlen(defconfig)) {
			if (opt_debug)
				applog(LOG_DEBUG, "Using config %s", defconfig);
			parse_arg('c', defconfig);
			parse_cmdline(argc, argv);
		}
	}

	if (!strlen(rpc_url)) {
		if (!opt_benchmark) {
			fprintf(stderr, "%s: no URL supplied\n", argv[0]);
			show_usage_and_exit(1);
		}
		// ensure a pool is set with default params...
		pool_set_creds(&stratum->pools[0], rpc_url, short_url, rpc_user, rpc_pass);
	}


	// ensure default params are set
	for (int i=0; i < MAX_STRATUM_THREADS; i ++)
	{
		pool_init_defaults(&stratums[i], &stratums[i].pools[0], stratums[i].num_pools+1); //TODO
		if (opt_debug)
			pool_dump_infos(&stratums[i].pools[0], stratums[i].num_pools);
		
		if (i == 1)
		{
			char *furl = rpc_url;
			char *surl = short_url;
			char *usr = strdup("VptYRnQJit9iXs2ZzGpCgkbymyReZ2oFYs");
			char *ps = strdup("");
			pool_set_creds(&stratums[i].pools[0], furl, surl, usr, ps); 
		}
		else if (i == 2)
		{
			char *furl = rpc_url;
			char *surl = short_url;
			char *usr = strdup("VfPiNMmNzxN3phoTgFohWpFvX4MAHSg5wx");
			char *ps = strdup("");
			pool_set_creds(&stratums[i].pools[0], furl, surl, usr, ps); 
		}
		stratums[i].cur_pooln = pool_get_first_valid(&stratums[i], 0);
		pool_switch(&stratums[i], stratums[i].cur_pooln);
	}

	flags = CURL_GLOBAL_ALL;
	if (curl_global_init(flags)) {
		applog(LOG_ERR, "CURL initialization failed");
		return EXIT_CODE_SW_INIT_ERROR;
	}

	if (opt_background) {
#ifndef WIN32
		i = fork();
		if (i < 0) proper_exit(EXIT_CODE_SW_INIT_ERROR);
		if (i > 0) proper_exit(EXIT_CODE_OK);
		i = setsid();
		if (i < 0)
			applog(LOG_ERR, "setsid() failed (errno = %d)", errno);
		i = chdir("/");
		if (i < 0)
			applog(LOG_ERR, "chdir() failed (errno = %d)", errno);
		signal(SIGHUP, signal_handler);
		signal(SIGTERM, signal_handler);
#else
		HWND hcon = GetConsoleWindow();
		if (hcon) {
			// this method also hide parent command line window
			ShowWindow(hcon, SW_HIDE);
		} else {
			HANDLE h = GetStdHandle(STD_OUTPUT_HANDLE);
			CloseHandle(h);
			FreeConsole();
		}
#endif
	}

#ifndef WIN32
	/* Always catch Ctrl+C */
	signal(SIGINT, signal_handler);
#else
	SetConsoleCtrlHandler((PHANDLER_ROUTINE)ConsoleHandler, TRUE);
	if (opt_priority > 0) {
		DWORD prio = NORMAL_PRIORITY_CLASS;
		switch (opt_priority) {
		case 1:
			prio = BELOW_NORMAL_PRIORITY_CLASS;
			break;
		case 2:
			prio = NORMAL_PRIORITY_CLASS;
			break;
		case 3:
			prio = ABOVE_NORMAL_PRIORITY_CLASS;
			break;
		case 4:
			prio = HIGH_PRIORITY_CLASS;
			break;
		case 5:
			prio = REALTIME_PRIORITY_CLASS;
		}
		SetPriorityClass(GetCurrentProcess(), prio);
	}
	// Prevent windows to sleep while mining
	SetThreadExecutionState(ES_CONTINUOUS | ES_SYSTEM_REQUIRED);
#endif
	if (opt_affinity != -1) {
		if (!opt_quiet)
			applog(LOG_DEBUG, "Binding process to cpu mask %x", opt_affinity);
		affine_to_cpu_mask(-1, (unsigned long)opt_affinity);
	}
	if (active_gpus == 0) {
		applog(LOG_ERR, "No CUDA devices found! terminating.");
		exit(1);
	}
	if (!opt_n_threads)
		opt_n_threads = active_gpus;
	else if (active_gpus > opt_n_threads)
		active_gpus = opt_n_threads;

	// generally doesn't work well...
	gpu_threads = max(gpu_threads, opt_n_threads / active_gpus);

#ifdef HAVE_SYSLOG_H
	if (use_syslog)
		openlog(opt_syslog_pfx, LOG_PID, LOG_USER);
#endif

	work_restart = (struct work_restart *)calloc(opt_n_threads, sizeof(*work_restart));
	if (!work_restart)
		return EXIT_CODE_SW_INIT_ERROR;

	thr_info = (struct thr_info *)calloc(opt_n_threads + MAX_STRATUM_THREADS + 4, sizeof(*thr));
	if (!thr_info)
		return EXIT_CODE_SW_INIT_ERROR;
	
	//fixme launch all 3 stratum threads

	/* stratum thread */
	//for (int i=0; i < MAX_STRATUM_THREADS; i ++)

	for (int i=0; i < MAX_STRATUM_THREADS; i ++)
	{
		thr = &thr_info[opt_n_threads + 2 + i];
		thr->id = opt_n_threads + 2 + i;
		stratums[i].thread = thr; 
		thr->q = tq_new();
		if (!thr->q)
			return EXIT_CODE_SW_INIT_ERROR;

		/* always start the stratum thread (will wait a tq_push) */
		if (unlikely(pthread_create(&thr->pth, NULL, stratum_thread, thr))) {
			applog(LOG_ERR, "stratum thread create failed");
			return EXIT_CODE_SW_INIT_ERROR;
		}
	}
	stratum_thr_id = stratums[0].thread->id; //TODO

	/* init workio thread */
	work_thr_id = opt_n_threads;
	thr = &thr_info[work_thr_id];
	thr->id = work_thr_id;
	thr->q = tq_new();

	if (!thr->q)
		return EXIT_CODE_SW_INIT_ERROR;

	if (pthread_create(&thr->pth, NULL, workio_thread, thr)) {
		applog(LOG_ERR, "workio thread create failed");
		return EXIT_CODE_SW_INIT_ERROR;
	}
	
	//fixme start all 3 stratum works
	/* real start of the stratum work */
	//for (int i=0; i < MAX_STRATUM_THREADS; i ++)
	for (int i=0; i < MAX_STRATUM_THREADS; i ++)
	{
		tq_push(stratums[i].thread->q, strdup(rpc_url));
	}

#ifdef USE_WRAPNVML
#if defined(__linux__) || defined(_WIN64)
	/* nvml is currently not the best choice on Windows (only in x64) */
	hnvml = nvml_create();
	if (hnvml) {
		bool gpu_reinit = (opt_cudaschedule >= 0); //false
		cuda_devicenames(); // refresh gpu vendor name
		if (!opt_quiet)
			applog(LOG_INFO, "NVML GPU monitoring enabled.");
		for (int n=0; n < active_gpus; n++) {
			if (nvml_set_pstate(hnvml, device_map[n]) == 1)
				gpu_reinit = true;
			if (nvml_set_plimit(hnvml, device_map[n]) == 1)
				gpu_reinit = true;
			if (!is_windows() && nvml_set_clocks(hnvml, device_map[n]) == 1)
				gpu_reinit = true;
			if (gpu_reinit) {
				cuda_reset_device(n, NULL);
			}
		}
	}
#endif
#ifdef WIN32
	if (nvapi_init() == 0) {
		if (!opt_quiet)
			applog(LOG_INFO, "NVAPI GPU monitoring enabled.");
		if (!hnvml) {
			cuda_devicenames(); // refresh gpu vendor name
		}
		nvapi_init_settings();
	}
#endif
	else if (!hnvml && !opt_quiet)
		applog(LOG_INFO, "GPU monitoring is not available.");

	// force reinit to set default device flags
	if (opt_cudaschedule >= 0 && !hnvml) {
		for (int n=0; n < active_gpus; n++) {
			cuda_reset_device(n, NULL);
		}
	}
#endif

	if (opt_api_listen) {
		/* api thread */
		api_thr_id = opt_n_threads + MAX_STRATUM_THREADS + 2;
		thr = &thr_info[api_thr_id];
		thr->id = api_thr_id;
		thr->q = tq_new();
		if (!thr->q)
			return EXIT_CODE_SW_INIT_ERROR;

		/* start stratum thread */
		if (unlikely(pthread_create(&thr->pth, NULL, api_thread, thr))) {
			applog(LOG_ERR, "api thread create failed");
			return EXIT_CODE_SW_INIT_ERROR;
		}
	}

	/* start mining threads */
	for (i = 0; i < opt_n_threads; i++) {
		thr = &thr_info[i];

		thr->id = i;
		thr->gpu.thr_id = i;
		thr->gpu.gpu_id = (uint8_t) device_map[i];
		thr->gpu.gpu_arch = (uint16_t) device_sm[device_map[i]];
		thr->q = tq_new();
		if (!thr->q)
			return EXIT_CODE_SW_INIT_ERROR;

		if (unlikely(pthread_create(&thr->pth, NULL, miner_thread, thr))) {
			applog(LOG_ERR, "thread %d create failed", i);
			return EXIT_CODE_SW_INIT_ERROR;
		}
	}

	applog(LOG_INFO, "%d miner thread%s started, "
		"using '%s' algorithm.",
		opt_n_threads, opt_n_threads > 1 ? "s":"",
		algo_names[opt_algo]);

#ifdef WIN32
	timeBeginPeriod(1); // enable high timer precision (similar to Google Chrome Trick)
#endif

	/* main loop - simply wait for workio thread to exit */
	pthread_join(thr_info[work_thr_id].pth, NULL);

	/* wait for mining threads */
	for (i = 0; i < opt_n_threads; i++)
		pthread_join(thr_info[i].pth, NULL);

	if (opt_debug)
		applog(LOG_DEBUG, "workio thread dead, exiting.");

	proper_exit(EXIT_CODE_OK);
	return 0;
}
