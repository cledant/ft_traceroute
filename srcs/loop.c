#include "ft_traceroute.h"

static inline uint8_t
checkTimeout(t_probes *probes)
{
    if ((getCurrentTime() - probes->startTime[0]) > SEC_IN_US) {
        probes->endTime[0] = probes->startTime[0];
        return (TRUE);
    }
    return (FALSE);
}

static inline uint8_t
processResponse(t_probes *probes,
                uint64_t curSeq,
                int64_t recvBytes,
                uint64_t recvTime)
{
    struct icmphdr *icmpHdr =
      (struct icmphdr *)(probes->response[0].iovecBuff + sizeof(struct iphdr));
    struct iphdr *err =
      (struct iphdr *)(probes->response[0].iovecBuff + MIN_ICMP_SIZE);

    if (recvBytes < 0) {
        if (swapUint16(err->id) == getpid()) {
            probes->endTime[0] = probes->startTime[0];
            return (TRUE);
        }
        return (checkTimeout(probes));
    }
    if (checkIpHdrChecksum((struct iphdr *)probes->response[0].iovecBuff,
                           recvBytes) ||
        checkIcmpHdrChecksum(icmpHdr, recvBytes)) {
        return (checkTimeout(probes));
    }
    if (icmpHdr->type == ICMP_DEST_UNREACH) {
        if (swapUint16(err->id) == getpid()) {
            probes->endTime[0] = probes->startTime[0];
            return (TRUE);
        }
        return (checkTimeout(probes));
    }
    if (icmpHdr->type == ICMP_TIME_EXCEEDED) {
        if (swapUint16(err->id) == getpid()) {
            probes->endTime[0] = recvTime;
            return (TRUE);
        }
        return (checkTimeout(probes));
    }
    if (swapUint16(icmpHdr->un.echo.id) != getpid() ||
        swapUint16(icmpHdr->un.echo.sequence) != curSeq) {
        return (checkTimeout(probes));
    }
    if (icmpHdr->type == ICMP_ECHOREPLY) {
        probes->endTime[0] = recvTime;
        probes->shouldStop = TRUE;
        return (TRUE);
    }
    return (checkTimeout(probes));
}

void
icmpLoop(t_env *e)
{
    uint64_t curSeq = e->opt.port;

    printf("ft_traceroute to %s (%s), %d hops max, %d byte packets\n",
           e->dest.resolvedAddr->ai_canonname,
           e->dest.ip,
           e->opt.maxTtl,
           e->opt.packetSize);
    for (uint64_t curTtl = e->opt.startTtl; curTtl < (uint64_t)e->opt.maxTtl;
         ++curTtl) {
        uint64_t startCurTtl = getCurrentTime();
        for (uint64_t i = 0; i < e->probes.nbProbes; ++i) {
            setIcmpPacket(e->probes.sendBuffer[0],
                          &e->dest,
                          e->opt.packetSize,
                          curSeq,
                          curTtl);
            e->probes.startTime[0] = getCurrentTime();
            int64_t sendBytes = sendto(e->probes.socketList[0],
                                       e->probes.sendBuffer[0],
                                       e->opt.packetSize,
                                       0,
                                       e->dest.addrDest->ai_addr,
                                       e->dest.addrDest->ai_addrlen);
            if (sendBytes < e->opt.packetSize) {
                printf("ft_traceroute: error sending icmp pakcet\n");
                return;
            }
            while (1) {
                int64_t recvBytes = recvmsg(
                  e->probes.socketList[0], &e->probes.response[0].msgHdr, 0);
                if (processResponse(
                      &e->probes, curSeq, recvBytes, getCurrentTime())) {
                    break;
                }
            }
            ++curSeq;
        }
        while ((getCurrentTime() - startCurTtl) < 3 * SEC_IN_US) {
        }
        printLoopStats(&e->probes);
        if (e->probes.shouldStop) {
            return;
        }
    }
}