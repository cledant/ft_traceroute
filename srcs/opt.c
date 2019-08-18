#include "ft_traceroute.h"

static void
parsingExit(t_dest *dest)
{
    if (dest->resolvedAddr) {
        freeaddrinfo(dest->resolvedAddr);
    }
    exit(EXIT_FAIL);
}

static uint8_t
parsingInt32Option(t_parse_opt *opt, int32_t argc)
{
    if (*(opt->argv + 1)) {
        if (!isStrAllDigit(opt->argv + 1)) {
            printf("Cannot handle `-%c' option with arg `%s' (argc %d)\n",
                   *opt->argv,
                   opt->argv + 1,
                   argc);
            return (TRUE);
        }
        opt->off = 0;
        *opt->val = atoi(opt->argv + 1);
    } else if (!(*(opt->argv + 1)) && opt->nextArgv) {
        if (!isStrAllDigit(opt->nextArgv)) {
            printf("Cannot handle `-%c' option with arg `%s' (argc %d)\n",
                   *opt->argv,
                   opt->nextArgv,
                   argc + 1);
            return (TRUE);
        }
        opt->off = 1;
        *opt->val = atoi(opt->nextArgv);
    } else {
        printf("Option `-%c' (argc %d) requires an argument: `-%c %s'\n",
               *opt->argv,
               argc,
               *opt->argv,
               opt->paramName);
        return (TRUE);
    }
    return (FALSE);
}

static uint8_t
parseOption(t_option *opt,
            t_dest *dest,
            char const *argv,
            char const *nextArgv,
            int32_t argc)
{
    t_parse_opt pOpt = { NULL, nextArgv, NULL, NULL, 0 };
    while (*argv) {
        pOpt.argv = argv;
        switch (*argv) {
            case 'h':
                opt->displayUsage = TRUE;
                break;
            case 'n':
                opt->noLookup = TRUE;
                break;
            case 'I':
                opt->protocol = IPPROTO_ICMP;
                break;
            case 'T':
                opt->protocol = IPPROTO_TCP;
                break;
            case 'q':
                pOpt.val = &opt->nbProbes;
                pOpt.paramName = "nqueries";
                if (parsingInt32Option(&pOpt, argc)) {
                    parsingExit(dest);
                }
                return (pOpt.off);
            case 'f':
                pOpt.val = &opt->startTtl;
                pOpt.paramName = "first_ttl";
                if (parsingInt32Option(&pOpt, argc)) {
                    parsingExit(dest);
                }
                return (pOpt.off);
            case 'm':
                pOpt.val = &opt->maxTtl;
                pOpt.paramName = "max_ttl";
                if (parsingInt32Option(&pOpt, argc)) {
                    parsingExit(dest);
                }
                return (pOpt.off);
            case 'p':
                pOpt.val = &opt->port;
                pOpt.paramName = "port";
                if (parsingInt32Option(&pOpt, argc)) {
                    parsingExit(dest);
                }
                return (pOpt.off);
            default:
                printf("Bad option `%c' (argc %d)\n", *argv, argc);
                parsingExit(dest);
                break;
        }
        ++argv;
    }
    return (0);
}

static uint8_t
parseToTrace(t_option *opt, t_dest *dest, char const *argv, int32_t argc)
{
    opt->toTrace = argv;
    dest->toTrace = argv;
    if (resolveAddrToTrace(dest)) {
        printf("Cannot handle \"host\" cmdline arg `%s' on position %ld "
               "(argc %d)\n",
               argv,
               opt->position,
               argc);
        parsingExit(dest);
    }
    ++opt->position;
    return (0);
}

static uint8_t
parsePacketLen(t_option *opt, t_dest *dest, char const *argv, int32_t argc)
{
    if (!isStrAllDigit(argv)) {
        printf("Cannot handle \"packetlen\" cmdline arg `%s' on position %ld "
               "(argc %d)\n",
               argv,
               opt->position,
               argc);
        parsingExit(dest);
    }
    opt->packetSize = atoi(argv);
    ++opt->position;
    return (0);
}

static uint8_t
parseArg(t_option *opt,
         t_dest *dest,
         char const *argv,
         char const *nextArgv,
         int32_t argc)
{
    uint64_t argLen = strlen(argv);

    if (argLen > 1 && argv[0] == '-') {
        return (parseOption(opt, dest, argv + 1, nextArgv, argc));
    } else if (opt->position == 1) {
        return (parseToTrace(opt, dest, argv, argc));
    } else if (opt->position == 2) {
        return (parsePacketLen(opt, dest, argv, argc));
    } else {
        printf("Extra arg `%s' (position %ld, argc %d)\n",
               argv,
               opt->position,
               argc);
        parsingExit(dest);
    }
    return (0);
}

static void
endCheckAndInit(t_option *opt, t_dest *dest)
{
    if (!opt->toTrace) {
        printf("Specify \"host\" missing argument\n");
        parsingExit(dest);
    }
    if (opt->startTtl > opt->maxTtl) {
        printf("first hop out of range\n");
        parsingExit(dest);
    }
    if (opt->maxTtl > MAX_TTL_VALUE) {
        printf("max hops cannot be more than 255\n");
        parsingExit(dest);
    }
    if (opt->packetSize > MAX_PACKET_SIZE) {
        printf("too big packetlen %d specified\n", opt->packetSize);
        parsingExit(dest);
    }
    if (opt->nbProbes > MAX_PROBES || opt->nbProbes < 1) {
        printf("no more than 10 probes per hop\n");
        parsingExit(dest);
    }
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

void
parseOptions(t_option *opt, t_dest *dest, int32_t argc, char const **argv)
{
    *opt = (t_option){ 1,
                       FALSE,
                       FALSE,
                       IPPROTO_UDP,
                       DEFAULT_NUMBER_OF_PROBES,
                       DEFAULT_START_TTL,
                       DEFAULT_MAX_TTL,
                       DEFAULT_PACKET_SIZE,
                       DEFAULT_OPT_PORT,
                       NULL };

    if (argc <= 1) {
        opt->displayUsage = TRUE;
        return;
    }
    for (int32_t i = 1; i < argc; ++i) {
        char const *nextPtr = NULL;

        if ((i + 1) < argc) {
            nextPtr = argv[i + 1];
        }
        i += parseArg(opt, dest, argv[i], nextPtr, i);
    }
    endCheckAndInit(opt, dest);
}