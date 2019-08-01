#include "ft_traceroute.h"

inline uint64_t
getCurrentTime()
{
    struct timeval ts;

    gettimeofday(&ts, NULL);
    return (convertTime(&ts));
}

inline uint64_t
convertTime(struct timeval const *ts)
{
    return (ts->tv_sec * SEC_IN_US + ts->tv_usec);
}

inline uint16_t
swapUint16(uint16_t val)
{
    return ((val << 8) | (val >> 8));
}

void
setupRespBuffer(t_response *resp)
{
    resp->iovec[0].iov_base = resp->iovecBuff;
    resp->iovec[0].iov_len = USHRT_MAX;
    resp->msgHdr.msg_iov = resp->iovec;
    resp->msgHdr.msg_iovlen = 1;
    resp->msgHdr.msg_name = &resp->addr;
    resp->msgHdr.msg_namelen = sizeof(struct sockaddr_in);
    resp->msgHdr.msg_control = NULL;
    resp->msgHdr.msg_controllen = 0;
}