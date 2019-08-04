#include "ft_traceroute.h"

uint8_t
initUdpSocket(t_probes *socketList)
{
    if ((socketList->sendSocket = socket(AF_INET, SOCK_RAW, IPPROTO_RAW)) <
        3) {
        printf("ft_traceroute : Error initializing socket\n");
        return (TRUE);
    }
    return (FALSE);
}