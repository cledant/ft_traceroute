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
    ipHdr->protocol = IPPROTO_UDP;
    ipHdr->check = 0;
    ipHdr->saddr = 0;
    ipHdr->daddr =
      ((struct sockaddr_in *)dest->addrDest->ai_addr)->sin_addr.s_addr;
}

void
setUdpPacket(uint8_t *buff,
             t_dest const *dest,
             uint16_t packetSize,
             uint16_t port,
             uint16_t ttl)
{
    struct iphdr *ipHdr = (struct iphdr *)buff;
    struct udphdr *udpHdr = (struct udphdr *)(buff + sizeof(struct iphdr));
    uint8_t *msg = (uint8_t *)udpHdr + sizeof(struct udphdr);

    if (packetSize > MIN_UDP_SIZE) {
        memset(msg, 42, packetSize - MIN_UDP_SIZE);
    }
    setIpHdr(ipHdr, ttl, packetSize, dest);
    setUdpHeader(udpHdr, port, packetSize - sizeof(struct iphdr));
}