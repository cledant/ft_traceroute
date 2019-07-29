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

void
setIcmpPacket(uint8_t *buff,
              t_dest const *dest,
              uint16_t packetSize,
              uint16_t seq,
              uint16_t ttl)
{
    struct iphdr *ipHdr = (struct iphdr *)buff;
    struct icmphdr *icmpHdr = (struct icmphdr *)(buff + sizeof(struct iphdr));
    uint8_t *msg = (uint8_t *)icmpHdr + sizeof(struct icmphdr);

    if (packetSize > MIN_ICMP_SIZE) {
        memset(msg, 42, packetSize - MIN_ICMP_SIZE);
    }
    setImcpHeader(icmpHdr, seq, packetSize - sizeof(struct iphdr));
    setIpHdr(ipHdr, ttl, packetSize, dest);
}
