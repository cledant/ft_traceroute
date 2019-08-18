#include "ft_traceroute.h"

static inline void
setImcpHeader(struct icmphdr *icmpHdr, uint16_t seq, uint16_t icmpMsgSize)
{
    icmpHdr->type = ICMP_ECHO;
    icmpHdr->code = 0;
    icmpHdr->un.echo.id = swapUint16(getpid());
    icmpHdr->un.echo.sequence = swapUint16(seq);
    icmpHdr->checksum = 0;
    icmpHdr->checksum = computeChecksum((uint16_t *)icmpHdr, icmpMsgSize);
}

static inline void
setIpHdr(struct iphdr *ipHdr,
         uint8_t ttl,
         uint16_t packetSize,
         t_dest const *dest)
{
    ipHdr->version = 4;
    ipHdr->tos = 0;
    ipHdr->ihl = 5;
    ipHdr->tot_len = packetSize;
    ipHdr->id = swapUint16(getpid());
    ipHdr->frag_off = 0;
    ipHdr->ttl = ttl;
    ipHdr->protocol = IPPROTO_ICMP;
    ipHdr->check = 0;
    ipHdr->saddr = 0;
    ipHdr->daddr =
      ((struct sockaddr_in *)dest->addrDest->ai_addr)->sin_addr.s_addr;
}

static inline uint8_t
processGetIpResponse(t_probes *probes,
                     t_dest *dest,
                     uint64_t curSeq,
                     int64_t recvBytes)
{
    struct iphdr *ipHdr = (struct iphdr *)probes->response[0].iovecBuff;

    if (recvBytes < 0 || checkIpHdrChecksum(ipHdr)) {
        return (checkTimeout(probes, 0));
    }
    struct icmphdr *icmpHdr =
      (struct icmphdr *)(probes->response[0].iovecBuff + sizeof(struct iphdr));
    struct iphdr const *err =
      (struct iphdr *)(probes->response[0].iovecBuff + MIN_ICMP_SIZE);

    if (checkIcmpHdrChecksum(icmpHdr, recvBytes)) {
        return (checkTimeout(probes, 0));
    }
    if (icmpHdr->type == ICMP_DEST_UNREACH ||
        icmpHdr->type == ICMP_TIME_EXCEEDED) {
        if (swapUint16(err->id) == getpid()) {
            dest->sourceIp = ipHdr->daddr;
            return (TRUE);
        }
        return (checkTimeout(probes, 0));
    }
    if (swapUint16(icmpHdr->un.echo.id) != getpid() ||
        swapUint16(icmpHdr->un.echo.sequence) != curSeq) {
        return (checkTimeout(probes, 0));
    }
    if (icmpHdr->type == ICMP_ECHOREPLY) {
        dest->sourceIp = ipHdr->daddr;
        return (TRUE);
    }
    return (checkTimeout(probes, 0));
}

uint8_t
getSourceIp(t_env *e)
{
    uint8_t buff[MIN_ICMP_SIZE];

    setIpHdr((struct iphdr *)buff, 1, MIN_ICMP_SIZE, &e->dest);
    setImcpHeader((struct icmphdr *)(buff + sizeof(struct iphdr)),
                  0,
                  sizeof(struct icmphdr));
    int64_t sendBytes = sendto(e->probes.listenSocket,
                               buff,
                               MIN_ICMP_SIZE,
                               0,
                               e->dest.addrDest->ai_addr,
                               e->dest.addrDest->ai_addrlen);
    e->probes.startTime[0] = getCurrentTime();
    if (sendBytes < MIN_ICMP_SIZE) {
        printf("connect: Invalid argument\n");
        return (TRUE);
    }
    while (1) {
        int64_t recvBytes =
          recvmsg(e->probes.listenSocket, &e->probes.response[0].msgHdr, 0);
        if (processGetIpResponse(&e->probes, &e->dest, 0, recvBytes)) {
            break;
        }
    }
    if (!e->dest.sourceIp) {
        printf("connect: Invalid argument\n");
        return (TRUE);
    }
    return (FALSE);
}