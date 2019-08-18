#include "ft_traceroute.h"

static inline uint8_t
tcpLoop(t_env *e, uint64_t curTtl, uint64_t *curSeq)
{
    for (uint64_t i = 0; i < e->probes.nbProbes; ++i) {
        setPacket(
          e->probes.sendBuffer, &e->dest, e->opt.packetSize, *curSeq, curTtl);
        memset(&e->probes.response[i].addr, 0, sizeof(struct sockaddr_in));
        e->probes.startTime[i] = getCurrentTime();
        int64_t sendBytes = sendto(e->probes.sendSocket,
                                   e->probes.sendBuffer,
                                   e->opt.packetSize,
                                   0,
                                   e->dest.addrDest->ai_addr,
                                   e->dest.addrDest->ai_addrlen);
        if (sendBytes < e->opt.packetSize) {
            printf("ft_traceroute: error sending packet\n");
            return (TRUE);
        }
        while (1) {
            int64_t recvBytes = recvmsg(
              e->probes.tcpListenSocket, &e->probes.response[i].msgHdr, 0);
            if (processTcpResponse(&e->probes,
                                   &e->dest,
                                   i,
                                   *curSeq,
                                   recvBytes,
                                   getCurrentTime())) {
                break;
            }
        }
        ++(*curSeq);
    }
    return (FALSE);
}

static inline uint8_t
icmpLoop(t_env *e, uint64_t curTtl, uint64_t *curSeq, uint8_t *icmpTimeout)
{
    for (uint64_t i = 0; i < e->probes.nbProbes; ++i) {
        setPacket(
          e->probes.sendBuffer, &e->dest, e->opt.packetSize, *curSeq, curTtl);
        memset(&e->probes.response[i].addr, 0, sizeof(struct sockaddr_in));
        e->probes.startTime[i] = getCurrentTime();
        int64_t sendBytes = sendto(e->probes.sendSocket,
                                   e->probes.sendBuffer,
                                   e->opt.packetSize,
                                   0,
                                   e->dest.addrDest->ai_addr,
                                   e->dest.addrDest->ai_addrlen);
        if (sendBytes < e->opt.packetSize) {
            printf("ft_traceroute: error sending packet\n");
            return (TRUE);
        }
        while (1) {
            int64_t recvBytes =
              recvmsg(e->probes.listenSocket, &e->probes.response[i].msgHdr, 0);
            if (processIcmpResponse(
                  &e->probes, i, *curSeq, recvBytes, getCurrentTime())) {
                if (getCurrentTime() - e->probes.startTime[i] > SEC_IN_US) {
                    ++(*icmpTimeout);
                }
                break;
            }
        }
        ++(*curSeq);
    }
    return (FALSE);
}

void
loop(t_env *e)
{
    uint64_t curSeq = e->opt.port;

    for (uint64_t curTtl = e->opt.startTtl;
         curTtl < (uint64_t)e->opt.maxTtl + 1;
         ++curTtl) {
        uint8_t icmpTimeout = 0;

        if (icmpLoop(e, curTtl, &curSeq, &icmpTimeout)) {
            return;
        }
        if (e->opt.protocol == IPPROTO_TCP &&
            icmpTimeout == e->probes.nbProbes) {
            if (tcpLoop(e, curTtl, &curSeq)) {
                return;
            }
        }
        printLoopStats(&e->probes, curTtl, e->opt.noLookup);
        if (e->probes.shouldStop) {
            return;
        }
    }
}