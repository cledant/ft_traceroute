#include "ft_traceroute.h"

static struct addrinfo *
resolveAddr(char const *addr)
{
    struct addrinfo *dest = NULL;
    struct addrinfo hints = { 0 };

    if (!addr) {
        return (NULL);
    }
    hints.ai_family = AF_INET;
    hints.ai_flags = AI_CANONNAME;
    if (getaddrinfo(addr, NULL, &hints, &dest)) {
        return (NULL);
    }
    return (dest);
}

static uint8_t
checkWildcardIp(struct addrinfo const *list,
                struct addrinfo **dest,
                char *dstIp)
{
    *dest = (struct addrinfo *)list;
    if (((struct sockaddr_in *)list->ai_addr)->sin_addr.s_addr == 0) {
        ((struct sockaddr_in *)list->ai_addr)->sin_addr.s_addr = LOOPBACK;
        strcpy(dstIp, "0.0.0.0");
        return (TRUE);
    }
    return (FALSE);
}

uint8_t
resolveAddrToTrace(t_dest *dest)
{
    if (!(dest->resolvedAddr = resolveAddr(dest->toTrace))) {
        printf("%s: Name or service not known\n", dest->toTrace);
        return (TRUE);
    }
    if (checkWildcardIp(dest->resolvedAddr, &dest->addrDest, dest->ip)) {
        return (FALSE);
    }
    if (!inet_ntop(AF_INET,
                   &((struct sockaddr_in *)dest->addrDest->ai_addr)->sin_addr,
                   dest->ip,
                   INET_ADDRSTRLEN)) {
        printf("%s: Ip conversion failed\n", dest->toTrace);
        return (TRUE);
    }
    return (FALSE);
}
