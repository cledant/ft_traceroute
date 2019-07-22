#include "ft_traceroute.h"

void
icmpLoop(t_env *e)
{
	for (uint64_t i = e->opt.startTtl; i < (uint64_t)e->opt.maxTtl; ++i) {
	    printf("TODO THINGS HERE\n");
	}
}