#include "ft_traceroute.h"

inline uint8_t
checkTcpHdrChecksum(struct tcphdr *tcpHdr,
                    struct iphdr const *ipHdr,
                    int64_t recvBytes)
{
    if (recvBytes < MIN_TCP_SIZE) {
        return (FALSE);
    }
    uint16_t recvChecksum = tcpHdr->th_sum;
    tcpHdr->th_sum = 0;
    tcpHdr->th_sum = computeTcpChecksum(tcpHdr,
                                        (uint8_t *)ipHdr + MIN_TCP_SIZE,
                                        recvBytes - MIN_TCP_SIZE,
                                        ipHdr->saddr,
                                        ipHdr->daddr);
    if (tcpHdr->th_sum == recvChecksum) {
        return (FALSE);
    }
    return (TRUE);
}

inline uint8_t
checkIcmpHdrChecksum(struct icmphdr *icmpHdr, int64_t recvBytes)
{
    if (recvBytes < MIN_ICMP_SIZE) {
        return (FALSE);
    }
    uint16_t recvChecksum = icmpHdr->checksum;
    icmpHdr->checksum = 0;
    icmpHdr->checksum =
      computeChecksum((uint16_t *)icmpHdr, recvBytes - sizeof(struct iphdr));
    if (icmpHdr->checksum == recvChecksum) {
        return (FALSE);
    }
    return (TRUE);
}

inline uint8_t
checkIpHdrChecksum(struct iphdr *ipHdr)
{
    uint16_t recvChecksum = ipHdr->check;
    ipHdr->check = 0;
    ipHdr->check = computeChecksum((uint16_t *)ipHdr, sizeof(struct iphdr));
    if (ipHdr->check == recvChecksum) {
        return (FALSE);
    }
    return (TRUE);
}