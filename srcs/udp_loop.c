#include "ft_traceroute.h"

void
udpLoop(t_env *e)
{
    uint64_t curPort = e->opt.port;

    printf("ft_traceroute to %s (%s), %d hops max, %d byte packets\n",
           e->dest.resolvedAddr->ai_canonname,
           e->dest.ip,
           e->opt.maxTtl,
           e->opt.packetSize);
    for (uint64_t curTtl = e->opt.startTtl; curTtl < (uint64_t)e->opt.maxTtl;
         ++curTtl) {
        for (uint64_t i = 0; i < e->probes.nbProbes; ++i) {
            memset(&e->probes.sendBuffer, 0, USHRT_MAX);
            memset(&e->probes.response[i].addr, 0, sizeof(struct sockaddr_in));
            setUdpPacket(e->probes.sendBuffer,
                         &e->dest,
                         e->opt.packetSize,
                         curPort,
                         curTtl);
            e->probes.startTime[i] = getCurrentTime();
            int64_t sendBytes = sendto(e->probes.sendSocket,
                                       e->probes.sendBuffer,
                                       e->opt.packetSize,
                                       0,
                                       e->dest.addrDest->ai_addr,
                                       e->dest.addrDest->ai_addrlen);
            if (sendBytes < e->opt.packetSize) {
                printf("ft_traceroute: error sending udp pakcet\n");
                return;
            }
            while (1) {
                int64_t recvBytes = recvmsg(
                  e->probes.listenSocket, &e->probes.response[i].msgHdr, 0);
                if (processResponse(
                      &e->probes, i, curPort, recvBytes, getCurrentTime())) {
                    break;
                }
            }
            ++curPort;
        }
        printLoopStats(&e->probes, curTtl, e->opt.noLookup);
        if (e->probes.shouldStop) {
            return;
        }
    }
}