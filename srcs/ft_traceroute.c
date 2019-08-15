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
resolveAddrToPing(t_dest *dest)
{
    if (!(dest->resolvedAddr = resolveAddr(dest->toTrace))) {
        printf("ft_traceroute: %s: Name or service not known\n", dest->toTrace);
        return (TRUE);
    }
    if (getValidIp(dest->resolvedAddr, &dest->addrDest)) {
        printf("ft_traceroute: No valid ip for name or service\n");
        return (TRUE);
    }
    if (!inet_ntop(AF_INET,
                   &((struct sockaddr_in *)dest->addrDest->ai_addr)->sin_addr,
                   dest->ip,
                   INET_ADDRSTRLEN)) {
        printf("ft_traceroute: Ip conversion failed\n");
        return (TRUE);
    }
    return (FALSE);
}

static inline uint8_t
init_network(t_env *e)
{
    if (resolveAddrToPing(&e->dest)) {
        return (TRUE);
    }
    for (uint64_t i = 0; i < e->probes.nbProbes; ++i) {
        setupRespBuffer(&e->probes.response[i]);
    }
    if (initIcmpSocket(&e->probes)) {
        return (TRUE);
    }
    if (initRawSocket(&e->probes)) {
        return (TRUE);
    }
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
        displayUsage();
        return (EXIT_FAIL);
    }
    parseOptions(&e.opt, argc, argv);
    if (e.opt.displayUsage) {
        displayUsage();
        return (EXIT_OK);
    }
    if (e.opt.startTtl > e.opt.maxTtl) {
        printf("ft_traceroute: start ttl out of range\n");
        displayUsage();
        return (EXIT_FAIL);
    }
    e.dest.toTrace = e.opt.toTrace;
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