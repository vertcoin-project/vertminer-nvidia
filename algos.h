#ifndef ALGOS_H
#define ALGOS_H

#include <string.h>
#include "compat.h"

enum sha_algos {
	ALGO_LYRA2v2,
	ALGO_COUNT
};

extern enum sha_algos opt_algo;

static const char *algo_names[] = {
	"lyra2v2",
	"auto", /* reserved for multi algo */
	""
};

// string to int/enuma
#define algo_to_int(arg) ALGO_LYRA2v2

#endif
