#include "ft_traceroute.h"

static inline uint8_t
checkTimeout(t_probes *probes, uint64_t probeIdx)
{
    if ((getCurrentTime() - probes->startTime[probeIdx]) > SEC_IN_US) {
        probes->endTime[probeIdx] = probes->startTime[probeIdx];
        return (TRUE);
    }
    return (FALSE);
}

static inline uint8_t
processResponse(t_probes *probes,
                uint64_t probeIdx,
                uint64_t curSeq,
                int64_t recvBytes,
                uint64_t recvTime)
{
    struct icmphdr *icmpHdr =
      (struct icmphdr *)(probes->response[probeIdx].iovecBuff +
                         sizeof(struct iphdr));
    struct iphdr *err =
      (struct iphdr *)(probes->response[probeIdx].iovecBuff + MIN_ICMP_SIZE);

    if (recvBytes < 0) {
        if (swapUint16(err->id) == getpid()) {
            probes->endTime[probeIdx] = probes->startTime[probeIdx];
            return (TRUE);
        }
        return (checkTimeout(probes, probeIdx));
    }
    if (checkIpHdrChecksum((struct iphdr *)probes->response[probeIdx].iovecBuff,
                           recvBytes) ||
        checkIcmpHdrChecksum(icmpHdr, recvBytes)) {
        return (checkTimeout(probes, probeIdx));
    }
    if (icmpHdr->type == ICMP_DEST_UNREACH) {
        if (swapUint16(err->id) == getpid()) {
            probes->endTime[probeIdx] = probes->startTime[probeIdx];
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
        for (uint64_t i = 0; i < e->probes.nbProbes; ++i) {
            setIcmpPacket(e->probes.sendBuffer[0],
                          &e->dest,
                          e->opt.packetSize,
                          curSeq,
                          curTtl);
            memset(&e->probes.response[i].addr, 0, sizeof(struct sockaddr_in));
            e->probes.startTime[i] = getCurrentTime();
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
                  e->probes.socketList[0], &e->probes.response[i].msgHdr, 0);
                if (processResponse(
                      &e->probes, i, curSeq, recvBytes, getCurrentTime())) {
                    break;
                }
            }
            ++curSeq;
        }
        printLoopStats(&e->probes, curTtl, e->opt.noLookup);
        if (e->probes.shouldStop) {
            return;
        }
    }
}