#include "ft_traceroute.h"

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

inline uint16_t
computeUdpChecksum(struct udphdr const *udpHdr,
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
    pHdr->protocol = IPPROTO_UDP;
    pHdr->len = swapUint16(sizeof(struct udphdr) + dataSize);
    memcpy(buff + sizeof(t_pseudoHdr), udpHdr, sizeof(struct tcphdr));
    if (dataSize && data) {
        memcpy(
          buff + sizeof(t_pseudoHdr) + sizeof(struct udphdr), data, dataSize);
    }
    return (
      computeChecksum((uint16_t *)buff,
                      sizeof(t_pseudoHdr) + sizeof(struct udphdr) + dataSize));
}