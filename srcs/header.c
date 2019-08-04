#include "ft_traceroute.h"

static inline void
setUdpHeader(struct udphdr *udpHdr, uint16_t port, uint16_t udpMsgSize)
{
    udpHdr->source = 0;
    udpHdr->dest = swapUint16(port);
    udpHdr->len = swapUint16(udpMsgSize);
    udpHdr->check = 0;
}

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
    ipHdr->protocol = dest->protocol;
    ipHdr->check = 0;
    ipHdr->saddr = 0;
    ipHdr->daddr =
      ((struct sockaddr_in *)dest->addrDest->ai_addr)->sin_addr.s_addr;
}

void
setPacket(uint8_t *buff,
          t_dest const *dest,
          uint16_t packetSize,
          uint16_t seq,
          uint16_t ttl)
{
    struct iphdr *ipHdr = (struct iphdr *)buff;

    if (dest->protocol == IPPROTO_ICMP) {
        struct icmphdr *icmpHdr =
          (struct icmphdr *)(buff + sizeof(struct iphdr));
        uint8_t *msg = (uint8_t *)icmpHdr + sizeof(struct icmphdr);

        if (packetSize > MIN_ICMP_SIZE) {
            memset(msg, 42, packetSize - MIN_ICMP_SIZE);
        }
        setImcpHeader(icmpHdr, seq, packetSize - sizeof(struct iphdr));
    } else if (dest->protocol == IPPROTO_UDP) {
        struct udphdr *udpHdr = (struct udphdr *)(buff + sizeof(struct iphdr));
        uint8_t *msg = (uint8_t *)udpHdr + sizeof(struct udphdr);

        if (packetSize > MIN_UDP_SIZE) {
            memset(msg, 42, packetSize - MIN_UDP_SIZE);
        }
        setUdpHeader(udpHdr, seq, packetSize - sizeof(struct iphdr));
    }
    setIpHdr(ipHdr, ttl, packetSize, dest);
}