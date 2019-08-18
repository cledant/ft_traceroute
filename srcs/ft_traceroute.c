#include "ft_traceroute.h"

static inline void
cleanEnv(t_env *e)
{
    if (e->probes.sendSocket > 2) {
        close(e->probes.sendSocket);
    }
    if (e->probes.listenSocket > 2) {
        close(e->probes.listenSocket);
    }
    if (e->probes.tcpListenSocket > 2) {
        close(e->probes.tcpListenSocket);
    }
    if (e->dest.resolvedAddr) {
        freeaddrinfo(e->dest.resolvedAddr);
    }
}

static inline uint8_t
init_network(t_env *e)
{
    for (uint64_t i = 0; i < e->probes.nbProbes; ++i) {
        setupRespBuffer(&e->probes.response[i]);
    }
    if (initIcmpSocket(&e->probes)) {
        return (TRUE);
    }
    if (initRawSocket(&e->probes)) {
        return (TRUE);
    }
    printf("ft_traceroute to %s (%s), %d hops max, %d byte packets\n",
           e->dest.addrDest->ai_canonname,
           e->dest.ip,
           e->opt.maxTtl,
           e->opt.packetSize);
    if (getSourceIp(e)) {
        return (TRUE);
    }
    if (e->opt.protocol == IPPROTO_TCP) {
        if (initTcpSocket(&e->probes)) {
            return (TRUE);
        }
    }
    return (FALSE);
}

int
main(int32_t argc, char const **argv)
{
    t_env e = { { 0 }, { 0 }, { 0 } };

    if (getuid()) {
        printf("ft_traceroute: not enough privilege, use sudo\n");
        return (EXIT_FAIL);
    }
    parseOptions(&e.opt, &e.dest, argc, argv);
    if (e.opt.displayUsage) {
        displayUsage();
        return (EXIT_OK);
    }
    e.dest.protocol = e.opt.protocol;
    e.dest.tcpPort = e.opt.port;
    e.probes.nbProbes = e.opt.nbProbes;
    if (init_network(&e)) {
        cleanEnv(&e);
        return (EXIT_FAIL);
    }
    loop(&e);
    cleanEnv(&e);
    return (EXIT_OK);
}