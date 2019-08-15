#include "ft_traceroute.h"

static uint8_t
setValue(int32_t *var,
         int32_t val,
         int32_t min,
         int32_t max,
         char const *errorMsg)
{
    if (val < min || val > max) {
        printf("ft_traceroute: %s: %d\n", errorMsg, val);
        return (0);
    }
    *var = val;
    return (1);
}

static uint8_t
parseMulti(t_option *opt, char const *arg, uint64_t len)
{
    if (arg[0] != '-') {
        opt->displayUsage = TRUE;
        return (0);
    }
    for (uint64_t i = 1; i < len; ++i) {
        if (arg[i] == 'h') {
            opt->displayUsage = TRUE;
        } else if (arg[i] == 'n') {
            opt->noLookup = TRUE;
        } else if (arg[i] == 'I') {
            opt->protocol = IPPROTO_ICMP;
        } else if (arg[i] == 'T') {
            opt->protocol = IPPROTO_TCP;
        }
    }
    return (0);
}

static uint8_t
parseInt(t_option *opt, char const *nextArg, uint64_t i)
{
    if (!nextArg) {
        opt->displayUsage = TRUE;
        return (0);
    }
    uint8_t off = 0;
    switch (i) {
        case 0:
            if (!(off = setValue(&opt->nbProbes,
                                 atoi(nextArg),
                                 1,
                                 MAX_PROBES,
                                 "invalid probe value"))) {
                opt->displayUsage = TRUE;
            }
            return (off);
        case 1:
            if (!(off = setValue(&opt->startTtl,
                                 atoi(nextArg),
                                 1,
                                 MAX_TTL_VALUE,
                                 "invalid start ttl value"))) {
                opt->displayUsage = TRUE;
            }
            return (off);
        case 2:
            if (!(off = setValue(&opt->maxTtl,
                                 atoi(nextArg),
                                 1,
                                 MAX_TTL_VALUE,
                                 "invalid max ttl value"))) {
                opt->displayUsage = TRUE;
            }
            return (off);
        case 3:
            if (!(off = setValue(&opt->port,
                                 atoi(nextArg),
                                 0,
                                 MAX_PORT,
                                 "invalid port value"))) {
                opt->displayUsage = TRUE;
            }
            return (off);
        case 4:
            if (!(off = setValue(&opt->packetSize,
                                 atoi(nextArg),
                                 0,
                                 MAX_PACKET_SIZE,
                                 "invalid packet size value"))) {
                opt->displayUsage = TRUE;
            }
            return (off);
        default:
            return (0);
    }
}

static uint8_t
parseSingle(t_option *opt, char const *arg, char const *nextArgv)
{
    static char const tab[][3] = { "-q", "-f", "-m", "-p", "-s",
                                   "-h", "-n", "-I", "-T" };

    for (uint64_t i = 0; i < NBR_OPTION; ++i) {
        if (!strcmp(arg, tab[i])) {
            if (i < 5) {
                return (parseInt(opt, nextArgv, i));
            } else {
                return (parseMulti(opt, arg, 2));
            }
        }
    }
    return (0);
}

static uint8_t
parseArg(t_option *opt, char const *argv, char const *nextArgv)
{
    uint64_t len = strlen(argv);

    if (len < 2) {
        opt->displayUsage = 1;
        return (0);
    } else if (len == 2) {
        return (parseSingle(opt, argv, nextArgv));
    } else {
        return (parseMulti(opt, argv, len));
    }
}

void
parseOptions(t_option *opt, int32_t argc, char const **argv)
{
    *opt = (t_option){ FALSE,
                       FALSE,
                       IPPROTO_UDP,
                       DEFAULT_NUMBER_OF_PROBES,
                       DEFAULT_START_TTL,
                       DEFAULT_MAX_TTL,
                       DEFAULT_PACKET_SIZE,
                       DEFAULT_OPT_PORT,
                       NULL };

    if (argc == 1) {
        opt->displayUsage = 1;
        return;
    }
    for (int32_t i = 1; i < (argc - 1); ++i) {
        char const *nextPtr = NULL;
        if ((i + 1) < (argc - 1)) {
            nextPtr = argv[i + 1];
        }
        i += parseArg(opt, argv[i], nextPtr);
    }
    if (argv[argc - 1][0] == '-') {
        opt->displayUsage = TRUE;
        return;
    }
    opt->toTrace = argv[argc - 1];
    if (opt->protocol == IPPROTO_ICMP) {
        if (opt->packetSize < MIN_ICMP_SIZE) {
            opt->packetSize = MIN_ICMP_SIZE;
        }
        if (opt->port == DEFAULT_OPT_PORT) {
            opt->port = DEFAULT_SEQ;
        }
    } else if (opt->protocol == IPPROTO_UDP) {
        if (opt->packetSize < MIN_UDP_SIZE) {
            opt->packetSize = MIN_UDP_SIZE;
        }
        if (opt->port == DEFAULT_OPT_PORT) {
            opt->port = DEFAULT_UDP_PORT;
        }
    } else {
        if (opt->packetSize < MIN_TCP_SIZE) {
            opt->packetSize = MIN_TCP_SIZE;
        }
        if (opt->port == DEFAULT_OPT_PORT) {
            opt->port = DEFAULT_TCP_PORT;
        }
    }
}