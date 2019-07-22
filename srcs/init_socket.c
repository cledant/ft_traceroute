#include "ft_traceroute.h"

uint8_t
initIcmpSocket(t_probes *socketList)
{
    uint8_t set = 1;
    struct timeval timeout = { 1, 0 };

    for (uint64_t i = 0; i < socketList->nbProbes; ++i) {

        if ((socketList->socketList[i] =
               socket(AF_INET, SOCK_RAW, IPPROTO_ICMP)) < 3) {
            printf("ft_ping : Error initializing socket\n");
            return (-1);
        }
        // Timeout
        if (setsockopt(socketList->socketList[i],
                       SOL_SOCKET,
                       SO_RCVTIMEO,
                       &timeout,
                       sizeof(struct timeval))) {
            printf("ft_traceroute: Error setting timeout params\n");
            return (TRUE);
        }
        // Manual Ip header
        if (setsockopt(socketList->socketList[i],
                       IPPROTO_IP,
                       IP_HDRINCL,
                       &set,
                       sizeof(uint8_t))) {
            printf("ft_traceroute: Error setting socket ip header\n");
            return (TRUE);
        }
    }
    return (FALSE);
}