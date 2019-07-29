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