#include "ft_traceroute.h"

static void
cleanEnv(t_env *e)
{
    if (e->dest.resolvedAddr) {
        freeaddrinfo(e->dest.resolvedAddr);
    }
}

static uint8_t
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

int
main(int32_t argc, char const **argv)
{
    t_env e = { { 0 }, { 0 } };

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
    e.dest.toTrace = e.opt.toTrace;
    if (resolveAddrToPing(&e.dest)) {
        cleanEnv(&e);
        return (EXIT_FAIL);
    }
    printf("ToTrace = %s | IP = %s\n", e.dest.toTrace, e.dest.ip);
    cleanEnv(&e);
    return (EXIT_OK);
}