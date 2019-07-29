#include "ft_traceroute.h"

static inline uint8_t
processResponse(t_probes *probes,
                uint64_t curSeq,
                int64_t recvBytes,
                struct timeval *ts)
{
    struct icmphdr *icmpHdr =
      (struct icmphdr *)(probes->response[0].iovecBuff + sizeof(struct iphdr));
    struct timeval timeout;

    if (recvBytes < 0) {
        struct iphdr *err =
          (struct iphdr *)(probes->response[0].iovecBuff + MIN_ICMP_SIZE);
        if (swapUint16(err->id) == getpid()) {
            probes->endTime[0] = probes->startTime[0];
            return (TRUE);
        }
        gettimeofday(&timeout, NULL);
        if ((convertTime(&timeout) - probes->startTime[0]) > SEC_IN_US) {
            probes->endTime[0] = probes->startTime[0];
            return (TRUE);
        }
        return (FALSE);
    }
    if (checkIpHdrChecksum((struct iphdr *)probes->response[0].iovecBuff,
                           recvBytes)) {
        probes->endTime[0] = probes->startTime[0];
        return (TRUE);
    }
    if (checkIcmpHdrChecksum(icmpHdr, recvBytes)) {
        probes->endTime[0] = probes->startTime[0];
        return (TRUE);
    }
    if (icmpHdr->type == ICMP_DEST_UNREACH) {
        struct iphdr *err =
          (struct iphdr *)(probes->response[0].iovecBuff + MIN_ICMP_SIZE);
        if (swapUint16(err->id) == getpid()) {
            probes->endTime[0] = probes->startTime[0];
            return (TRUE);
        }
        gettimeofday(&timeout, NULL);
        if ((convertTime(&timeout) - probes->startTime[0]) > SEC_IN_US) {
            probes->endTime[0] = probes->startTime[0];
            return (TRUE);
        }
        return (FALSE);
    }
    if (icmpHdr->type == ICMP_TIME_EXCEEDED) {
        struct iphdr *err =
          (struct iphdr *)(probes->response[0].iovecBuff + MIN_ICMP_SIZE);
        if (swapUint16(err->id) == getpid()) {
            probes->endTime[0] = convertTime(ts);
            return (TRUE);
        }
        gettimeofday(&timeout, NULL);
        if ((convertTime(&timeout) - probes->startTime[0]) > SEC_IN_US) {
            probes->endTime[0] = probes->startTime[0];
            return (TRUE);
        }
        return (FALSE);
    }
    if (swapUint16(icmpHdr->un.echo.id) != getpid()) {
        return (FALSE);
    }
    if (swapUint16(icmpHdr->un.echo.sequence) != curSeq) {
        return (FALSE);
    }
    if (icmpHdr->type == ICMP_ECHOREPLY) {
        probes->endTime[0] = convertTime(ts);
        probes->shouldStop = TRUE;
        return (TRUE);
    }
    gettimeofday(&timeout, NULL);
    if ((convertTime(&timeout) - probes->startTime[0]) > SEC_IN_US) {
        probes->endTime[0] = probes->startTime[0];
        return (TRUE);
    }
    return (FALSE);
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
        printf("ttl %lu\n", curTtl);
        for (uint64_t i = 0; i < e->probes.nbProbes; ++i) {
            int64_t sendBytes = 0;
            struct timeval ts;

            printf("probe %lu :", i);
            setIcmpPacket(e->probes.sendBuffer[0],
                          &e->dest,
                          e->opt.packetSize,
                          curSeq,
                          curTtl);
            gettimeofday(&ts, NULL);
            e->probes.startTime[0] = convertTime(&ts);
            sendBytes = sendto(e->probes.socketList[0],
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
                gettimeofday(&ts, NULL);
                if (processResponse(&e->probes, curSeq, recvBytes, &ts)) {
                    break;
                }
            }
            printf(" %lu ms\n", e->probes.endTime[0] - e->probes.startTime[0]);
            ++curSeq;
        }
        printf("\n");
        if (e->probes.shouldStop) {
            return;
        }
    }
}