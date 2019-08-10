#include "ft_traceroute.h"

inline uint8_t
checkIcmpHdrChecksum(struct icmphdr *icmpHdr, int64_t recvBytes)
{
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
checkIpHdrChecksum(struct iphdr *ipHdr, int64_t recvBytes)
{
    uint16_t recvChecksum = ipHdr->check;
    ipHdr->check = 0;
    ipHdr->check = computeChecksum((uint16_t *)ipHdr, recvBytes);
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
                   char const *destIp)
{
    uint8_t buff[USHRT_MAX] = { 0 };
    t_pseudoHdr *pHdr = (t_pseudoHdr *)buff;

    pHdr->saddr = inet_addr("192.168.1.205");
    pHdr->daddr = inet_addr(destIp);
    pHdr->zeros = 0;
    pHdr->protocol = IPPROTO_TCP;
    pHdr->len = swapUint16(sizeof(struct tcphdr) + dataSize);
    memcpy(buff + sizeof(t_pseudoHdr), tcpHdr, sizeof(struct tcphdr));
    memcpy(buff + sizeof(t_pseudoHdr) + sizeof(struct tcphdr), data, dataSize);
    return (
      computeChecksum((uint16_t *)buff,
                      sizeof(t_pseudoHdr) + sizeof(struct tcphdr) + dataSize));
}