#ifndef FT_TRACEROUTE_H
#define FT_TRACEROUTE_H

#include <arpa/inet.h>
#include <limits.h>
#include <linux/icmp.h>
#include <linux/ip.h>
#include <math.h>
#include <netdb.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/types.h>
#include <unistd.h>

#define EXIT_FAIL -1
#define EXIT_OK 0
#define SEC_IN_US 1000000
#define SEC_IN_MS 1000
#define TRUE 1
#define FALSE 0
#define DEFAULT_NUMBER_OF_PROBES 3
#define DEFAULT_START_TTL 1
#define DEFAULT_MAX_TTL 30
#define DEFAULT_PACKET_SIZE 60
#define DEFAULT_OPT_PORT -1
#define DEFAULT_UDP_PORT 33434
#define DEFAULT_SEQ 0
#define NBR_OPTION 9
#define MAX_PROBES 10
#define MAX_TTL_VALUE UCHAR_MAX
#define MAX_PORT USHRT_MAX
#define MAX_PACKET_SIZE 65000
#define MIN_ICMP_SIZE (uint8_t)(sizeof(struct icmphdr) + sizeof(struct iphdr))
#define MIN_UDP_SIZE (uint8_t)(sizeof(struct udphdr) + sizeof(struct iphdr))

typedef struct s_option
{
    uint8_t displayUsage;
    uint8_t noLookup;
    int32_t protocol;
    int32_t nbProbes;
    int32_t startTtl;
    int32_t maxTtl;
    int32_t packetSize;
    int32_t port;
    char const *toTrace;
} t_option;

typedef struct s_dest
{
    char const *toTrace;
    int32_t protocol;
    struct addrinfo *resolvedAddr;
    struct addrinfo *addrDest;
    char ip[INET_ADDRSTRLEN];
} t_dest;

typedef struct s_response
{
    struct sockaddr_in addr;
    struct iovec iovec[1];
    struct msghdr msgHdr;
    uint8_t iovecBuff[USHRT_MAX];
} t_response;

typedef struct s_probes
{
    uint64_t nbProbes;
    int32_t sendSocket;
    int32_t listenSocket;
    uint64_t startTime[MAX_PROBES];
    uint64_t endTime[MAX_PROBES];
    uint8_t sendBuffer[USHRT_MAX];
    t_response response[MAX_PROBES];
    uint8_t shouldStop;
} t_probes;

typedef struct s_env
{
    t_option opt;
    t_dest dest;
    t_probes probes;
} t_env;

// opt.c
void parseOptions(t_option *opt, int32_t argc, char const **argv);

// utility_network.c
uint8_t getValidIp(struct addrinfo const *list, struct addrinfo **dest);
struct addrinfo *resolveAddr(char const *addr);
uint8_t processResponse(t_probes *probes,
                        uint64_t probeIdx,
                        uint64_t curSeq,
                        int64_t recvBytes,
                        uint64_t recvTime);

// loop.c
void loop(t_env *e);

// utility.c
uint64_t getCurrentTime();
uint64_t convertTime(struct timeval const *ts);
uint16_t swapUint16(uint16_t val);
void setupRespBuffer(t_response *resp);

// display.c
void displayUsage();
void printIcmpHdr(struct icmphdr const *icmpHdr);
void printLoopStats(t_probes const *probes, uint64_t curTtl, uint8_t noLookup);

// checksum.c
uint8_t checkIcmpHdrChecksum(struct icmphdr *icmpHdr, int64_t recvBytes);
uint8_t checkIpHdrChecksum(struct iphdr *ipHdr, int64_t recvBytes);
uint16_t computeChecksum(uint16_t const *ptr, uint16_t packetSize);

// socket.c
uint8_t initRawSocket(t_probes *socketList);
uint8_t initIcmpSocket(t_probes *socketList);

// header.c
void setPacket(uint8_t *buff,
               t_dest const *dest,
               uint16_t packetSize,
               uint16_t port,
               uint16_t ttl);
#endif
