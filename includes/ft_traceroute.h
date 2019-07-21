#ifndef FT_TRACEROUTE_H
#define FT_TRACEROUTE_H

#include <arpa/inet.h>
#include <limits.h>
#include <linux/icmp.h>
#include <linux/ip.h>
#include <math.h>
#include <netdb.h>
#include <netinet/tcp.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
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
#define DEFAULT_PORT 4242
#define NBR_OPTION 9
#define MAX_PROBES 10
#define MAX_TTL_VALUE UCHAR_MAX
#define MAX_PORT USHRT_MAX
#define MAX_PACKET_SIZE 65000
#define ECHOREPLY 0
#define TTL_ERROR 11

typedef struct s_option
{
    uint8_t displayUsage;
    uint8_t noLookup;
    uint8_t useUdp;
    uint8_t useIcmp;
    uint8_t useTcp;
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

typedef struct s_env
{
    t_option opt;
    t_dest dest;
} t_env;

// opt.c
void parseOptions(t_option *opt, int32_t argc, char const **argv);
void displayUsage();

// init_network.c
uint8_t getValidIp(struct addrinfo const *list, struct addrinfo **dest);
struct addrinfo *resolveAddr(char const *addr);

#endif
