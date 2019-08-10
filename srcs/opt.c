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
        return (FALSE);
    }
    *var = val;
    return (TRUE);
}

static uint8_t
parseMulti(t_option *opt, char const *arg, uint64_t len)
{
    if (arg[0] != '-') {
        opt->displayUsage = 1;
        return (FALSE);
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
    return (FALSE);
}

static uint8_t
parseInt(t_option *opt, char const *nextArg, uint64_t i)
{
    if (!nextArg) {
        opt->displayUsage = 1;
        return (FALSE);
    }
    switch (i) {
        case 0:
            return (setValue(&opt->nbProbes,
                             atoi(nextArg),
                             0,
                             MAX_PROBES,
                             "invalid probe value"));
        case 1:
            return (setValue(&opt->startTtl,
                             atoi(nextArg),
                             1,
                             MAX_TTL_VALUE,
                             "invalid start ttl value"));
        case 2:
            return (setValue(&opt->maxTtl,
                             atoi(nextArg),
                             1,
                             MAX_TTL_VALUE,
                             "invalid max ttl value"));
        case 3:
            return (setValue(
              &opt->port, atoi(nextArg), 0, MAX_PORT, "invalid port value"));
        case 4:
            return (setValue(&opt->packetSize,
                             atoi(nextArg),
                             0,
                             MAX_PACKET_SIZE,
                             "invalid packet size value"));
        default:
            return (FALSE);
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
    return (FALSE);
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
        opt->displayUsage = 1;
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