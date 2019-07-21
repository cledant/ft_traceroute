#include "ft_traceroute.h"

static void
setValue(int32_t *var,
         int32_t val,
         int32_t min,
         int32_t max,
         char const *errorMsg)
{
    if (val < min || val > max) {
        printf("ft_traceroute: %s: %d\n", errorMsg, val);
        return;
    }
    *var = val;
}

static uint8_t
parseMulti(t_option *opt, char const *arg, uint64_t len)
{
    if (arg[0] != '-') {
        opt->displayUsage = 1;
        return (0);
    }
    for (uint64_t i = 1; i < len; ++i) {
        if (arg[i] == 'h') {
            opt->displayUsage = TRUE;
        } else if (arg[i] == 'n') {
            opt->noLookup = TRUE;
        } else if (arg[i] == 'I') {
            opt->useIcmp = TRUE;
        } else if (arg[i] == 'T') {
            opt->useTcp = TRUE;
        }
    }
    return (0);
}

static uint8_t
parseInt(t_option *opt, char const *nextArg, uint64_t i)
{
    if (!nextArg) {
        opt->displayUsage = 1;
        return (0);
    }
    switch (i) {
        case 0:
            setValue(&opt->nbProbes,
                     atoi(nextArg),
                     0,
                     MAX_PROBES,
                     "invalid probe value");
            break;
        case 1:
            setValue(&opt->startTtl,
                     atoi(nextArg),
                     1,
                     MAX_TTL_VALUE,
                     "invalid start ttl value");
            break;
        case 2:
            setValue(&opt->maxTtl,
                     atoi(nextArg),
                     1,
                     MAX_TTL_VALUE,
                     "invalid max ttl value");
            break;
        case 3:
            setValue(
              &opt->port, atoi(nextArg), 0, MAX_PORT, "invalid port value");
            break;
        case 4:
            setValue(&opt->packetSize,
                     atoi(nextArg),
                     0,
                     MAX_PACKET_SIZE,
                     "invalid packet size value");
            break;
        default:
            return (0);
    }
    return (1);
}

static uint8_t
parseSingle(t_option *opt, char const *arg, char const *nextArgv)
{
    char const tab[NBR_OPTION][3] = { "-q", "-f", "-m", "-p", "-s",
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
                       TRUE,
                       FALSE,
                       FALSE,
                       DEFAULT_NUMBER_OF_PROBES,
                       DEFAULT_START_TTL,
                       DEFAULT_MAX_TTL,
                       DEFAULT_PACKET_SIZE,
                       DEFAULT_PORT,
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
}

void
displayUsage()
{
    printf("Usage: ft_traceroute [-hnIT] [-q nqueries] [-f first_ttl] [-m "
           "max_ttl] [-p port] [-s packet_size] destination\n");
    printf("\t-h : Display usage\n");
    printf("\t-n : No name lookup for host address\n");
    printf("\t-I : Use ICMP echo for probes\n");
    printf("\t-T : Use TCP sync for probes\n");
    printf("\t-q : Number of probe number per hop. Default is 3. Max is 10\n");
    printf("\t-f : TTL value at start. Default is 1\n");
    printf("\t-m : Max TTL value. Default is 30\n");
    printf("\t-p : Port\n\tFor UDP probe : initial port and is incremented at "
           "each probe\n\tICMP probe : initial sequence value\n\tTCP probe : "
           "constant port value\n");
    printf("\t-s : Packet size. From 0 to MTU value minus headers.\n\tMTU "
           "value is usually 1500\n");
}