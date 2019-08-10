#include "ft_traceroute.h"

uint8_t
getValidIp(struct addrinfo const *list, struct addrinfo **dest)
{
    if (!dest || !list) {
        return (TRUE);
    }
    while (list) {
        if (((struct sockaddr_in *)list->ai_addr)->sin_addr.s_addr) {
            *dest = (struct addrinfo *)list;
            return (FALSE);
        }
        list = list->ai_next;
    }
    return (TRUE);
}

struct addrinfo *
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

static inline uint8_t
checkTimeout(t_probes *probes, uint64_t probeIdx)
{
    if ((getCurrentTime() - probes->startTime[probeIdx]) > SEC_IN_US) {
        probes->endTime[probeIdx] = probes->startTime[probeIdx];
        return (TRUE);
    }
    return (FALSE);
}

uint8_t
processResponse(t_probes *probes,
                uint64_t probeIdx,
                uint64_t curSeq,
                int64_t recvBytes,
                uint64_t recvTime)
{
    struct iphdr *ipHdr = (struct iphdr *)probes->response[probeIdx].iovecBuff;

    if (recvBytes < 0 || checkIpHdrChecksum(ipHdr, recvBytes)) {
        return (checkTimeout(probes, probeIdx));
    }
    struct icmphdr *icmpHdr =
      (struct icmphdr *)(probes->response[probeIdx].iovecBuff +
                         sizeof(struct iphdr));
    struct iphdr *err =
      (struct iphdr *)(probes->response[probeIdx].iovecBuff + MIN_ICMP_SIZE);

    if (checkIcmpHdrChecksum(icmpHdr, recvBytes)) {
        return (checkTimeout(probes, probeIdx));
    }
    if (icmpHdr->type == ICMP_DEST_UNREACH) {
        if (swapUint16(err->id) == getpid()) {
            probes->shouldStop = TRUE;
            probes->endTime[probeIdx] = recvTime;
            return (TRUE);
        }
        return (checkTimeout(probes, probeIdx));
    }
    if (icmpHdr->type == ICMP_TIME_EXCEEDED) {
        if (swapUint16(err->id) == getpid()) {
            probes->endTime[probeIdx] = recvTime;
            return (TRUE);
        }
        return (checkTimeout(probes, probeIdx));
    }
    if (swapUint16(icmpHdr->un.echo.id) != getpid() ||
        swapUint16(icmpHdr->un.echo.sequence) != curSeq) {
        return (checkTimeout(probes, probeIdx));
    }
    if (icmpHdr->type == ICMP_ECHOREPLY) {
        probes->endTime[probeIdx] = recvTime;
        probes->shouldStop = TRUE;
        return (TRUE);
    }
    return (checkTimeout(probes, probeIdx));
}