#include "ft_traceroute.h"

void
displayUsage()
{
    printf("Usage: ft_traceroute [-hnIT] [-q nqueries] [-f first_ttl] [-m "
           "max_ttl] [-p port] host [packet_size]\n");
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
    printf(
      "\tPacket size. From 0 to MTU value.\n\tMTU value is usually 1500\n");
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
printLoopStats(t_probes const *probes, uint64_t curTtl, uint8_t noLookup)
{
    uint8_t sameDest = 0;
    uint8_t init = FALSE;

    printf("%2lu ", curTtl);
    for (uint64_t i = 0; i < probes->nbProbes; ++i) {
        if (((!init || memcmp(&probes->response[sameDest].addr,
                           &probes->response[i].addr,
                           sizeof(struct sockaddr_in))) &&
             (probes->endTime[i] - probes->startTime[i])) &&
            probes->response[i].addr.sin_addr.s_addr) {
            char ip[INET_ADDRSTRLEN] = { 0 };

            sameDest = i;
            init = TRUE;
            inet_ntop(AF_INET,
                      &probes->response[i].addr.sin_addr.s_addr,
                      ip,
                      INET_ADDRSTRLEN);
            if (!noLookup) {
                char fqdn[NI_MAXHOST] = { 0 };

                if (getnameinfo((struct sockaddr *)&probes->response[i].addr,
                                sizeof(struct sockaddr),
                                fqdn,
                                NI_MAXHOST,
                                NULL,
                                0,
                                0)) {
                    printf(" %s (%s)", ip, ip);

                } else {
                    printf(" %s (%s)", fqdn, ip);
                }
            } else {
                printf(" %s", ip);
            }
        }
        if (!(probes->endTime[i] - probes->startTime[i])) {
            printf(" *");
        } else {
            printf("  %.3f ms",
                   (probes->endTime[i] - probes->startTime[i]) /
                     (double)SEC_IN_MS);
        }
    }
    printf("\n");
}