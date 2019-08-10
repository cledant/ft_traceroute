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

inline uint16_t
computeChecksum(uint16_t const *ptr, uint16_t packetSize)
{
    uint32_t checksum = 0;
    uint64_t size = packetSize;

    while (size > 1) {
        checksum += *ptr;
        size -= sizeof(uint16_t);
        ++ptr;
    }
    if (size == 1) {
        checksum += *(uint8_t *)ptr;
    }
    checksum = (checksum >> 16) + (checksum & 0xFFFF);
    checksum += (checksum >> 16);
    return (~checksum);
}

inline uint16_t
computeTcpChecksum(struct tcphdr const *tcpHdr,
                   uint8_t const *data,
                   uint16_t dataSize,
                   uint32_t srcIp,
                   uint32_t destIp)
{
    uint8_t buff[USHRT_MAX] = { 0 };
    t_pseudoHdr *pHdr = (t_pseudoHdr *)buff;

    pHdr->saddr = srcIp;
    pHdr->daddr = destIp;
    pHdr->zeros = 0;
    pHdr->protocol = IPPROTO_TCP;
    pHdr->len = swapUint16(sizeof(struct tcphdr) + dataSize);
    memcpy(buff + sizeof(t_pseudoHdr), tcpHdr, sizeof(struct tcphdr));
    if (dataSize && data) {
        memcpy(
          buff + sizeof(t_pseudoHdr) + sizeof(struct tcphdr), data, dataSize);
    }
    return (
      computeChecksum((uint16_t *)buff,
                      sizeof(t_pseudoHdr) + sizeof(struct tcphdr) + dataSize));
}