#include "ft_traceroute.h"

uint8_t
initRawSocket(t_probes *socketList)
{
    if ((socketList->sendSocket = socket(AF_INET, SOCK_RAW, IPPROTO_RAW)) <
        3) {
        printf("ft_traceroute : Error initializing socket\n");
        return (TRUE);
    }
    return (FALSE);
}

uint8_t
initIcmpSocket(t_probes *socketList)
{
    uint8_t set = 1;
    struct timeval timeout = { 1, 0 };

    if ((socketList->listenSocket = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP)) <
        3) {
        printf("ft_traceroute : Error initializing socket\n");
        return (TRUE);
    }
    // Timeout
    if (setsockopt(socketList->listenSocket,
                   SOL_SOCKET,
                   SO_RCVTIMEO,
                   &timeout,
                   sizeof(struct timeval))) {
        printf("ft_traceroute: Error setting timeout params\n");
        return (TRUE);
    }
    // Manual Ip header
    if (setsockopt(socketList->listenSocket,
                   IPPROTO_IP,
                   IP_HDRINCL,
                   &set,
                   sizeof(uint8_t))) {
        printf("ft_traceroute: Error setting socket ip header\n");
        return (TRUE);
    }
    return (FALSE);
}