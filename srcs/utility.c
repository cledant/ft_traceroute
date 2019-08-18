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

inline uint32_t
swapUint32(uint32_t val)
{
    return ((val << 24) | (val << 8 & 0x00FF0000) | (val >> 8 & 0x0000FF00) |
            (val >> 24 & 0x000000FF));
}

inline void
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

inline uint8_t
isStrAllDigit(char const *str)
{
    while (*str) {
        if (!isdigit(*str)) {
            return (FALSE);
        }
        ++str;
    }
    return (TRUE);
}