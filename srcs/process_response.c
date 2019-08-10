#include "ft_traceroute.h"

inline uint8_t
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

    if (recvBytes < 0 || checkIpHdrChecksum(ipHdr)) {
        return (checkTimeout(probes, probeIdx));
    }
    struct icmphdr *icmpHdr =
      (struct icmphdr *)(probes->response[probeIdx].iovecBuff +
                         sizeof(struct iphdr));
    struct iphdr const *err =
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

uint8_t
processTcpResponse(t_probes *probes,
                   t_dest const *dest,
                   uint64_t probeIdx,
                   uint32_t curSeq,
                   int64_t recvBytes,
                   uint64_t recvTime)
{
    struct iphdr *ipHdr = (struct iphdr *)probes->response[probeIdx].iovecBuff;

    if (recvBytes < 0 || checkIpHdrChecksum(ipHdr)) {
        return (checkTimeout(probes, probeIdx));
    }
    struct tcphdr *tcpHdr =
      (struct tcphdr *)(probes->response[probeIdx].iovecBuff +
                        sizeof(struct iphdr));

    if (checkTcpHdrChecksum(tcpHdr, ipHdr, recvBytes)) {
        return (checkTimeout(probes, probeIdx));
    }
    if (ipHdr->saddr !=
        ((struct sockaddr_in *)(dest->addrDest->ai_addr))->sin_addr.s_addr) {
        return (checkTimeout(probes, probeIdx));
    }
    if (tcpHdr->th_flags != (TH_ACK | TH_SYN)) {
        return (checkTimeout(probes, probeIdx));
    }
    if (tcpHdr->th_ack == swapUint32(getpid() + curSeq + 1)) {
        probes->endTime[probeIdx] = recvTime;
        return (TRUE);
    }
    return (checkTimeout(probes, probeIdx));
}