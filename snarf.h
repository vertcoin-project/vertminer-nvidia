#include "miner.h"

enum snarf_id
{
	SNARF_VTM = 0,
	SNARF_VTC = 1,
	SNARF_MAX,
};

struct snarf {
	enum snarf_id id;
	char *user;
	char *password;
	int pooln;
	uint64_t enable_count;
};


struct snarfs {
	struct snarf s[SNARF_MAX];
	bool enabled;
	bool do_work;
	bool want_to_enable;
	enum snarf_id select;
	uint64_t last_start_time_plus_period;
	uint64_t last_stop_time_plus_period;
	uint64_t snarf_period;
	uint64_t snarf_delay;
	uint64_t snarf_offset;
	uint64_t num_times_enabled;
	struct pool_infos * presnarf_pool;
	struct p2pool_list *p2pl;
};

bool pool_switch_snarf(int thr_id, int pooln);
bool  snarf_time(struct snarfs *sf, int thr_id);
void determine_snarfing(struct snarfs *sf);
struct snarfs * new_snarfs(void);
void free_snarfs(struct snarfs *sf);
void dump_snarfs(struct snarfs *sf);
