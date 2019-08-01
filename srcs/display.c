#include "ft_traceroute.h"

void
displayUsage()
{
    printf("Usage: ft_traceroute [-hnIT] [-q nqueries] [-f first_ttl] [-m "
           "max_ttl] [-p port] [-s packet_size] destination\n");
    printf("\t-h : Display usage\n");
    printf("\t-n : No name lookup for host address\n");
    printf("\t-I : Use ICMP echo for probes\n");
    printf("\t-T : Use TCP sync for probes\n");
    printf("\t-q : Number of probe number per hop. Default is 3. Max is 10\n");
    printf("\t-f : TTL value at start. Default is 1\n");
    printf("\t-m : Max TTL value. Default is 30\n");
    printf("\t-p : Port\n\tFor UDP probe : initial port and is incremented at "
           "each probe\n\tICMP probe : initial sequence value\n\tTCP probe : "
           "constant port value\n");
    printf("\t-s : Packet size. From 0 to MTU value minus headers.\n\tMTU "
           "value is usually 1500\n");
}

void
printIcmpHdr(struct icmphdr const *icmpHdr)
{
    printf("===ICMP HEADER VALUES===\n\tType: %u\n\tCode: %u\n\tPid: "
           "%u\n\tSequence: %u\n\tChecksum: %u\n----------\n",
           icmpHdr->type,
           icmpHdr->code,
           swapUint16(icmpHdr->un.echo.id),
           swapUint16(icmpHdr->un.echo.sequence),
           icmpHdr->checksum);
}

void
printLoopStats(t_probes const *probes)
{
    (void)probes;
    printf("TODO\n");
}