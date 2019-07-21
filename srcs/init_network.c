#include "ft_traceroute.h"

uint8_t
getValidIp(struct addrinfo const *list, struct addrinfo **dest)
{
	if (!dest || !list) {
		return (TRUE);
	}
	while (list) {
		if (((struct sockaddr_in *)list->ai_addr)->sin_addr.s_addr) {
			*dest = (struct addrinfo *)list;
			return (FALSE);
		}
		list = list->ai_next;
	}
	return (TRUE);
}

struct addrinfo *
resolveAddr(char const *addr)
{
	struct addrinfo *dest = NULL;
	struct addrinfo hints = { 0 };

	if (!addr) {
		return (NULL);
	}
	hints.ai_family = AF_INET;
	hints.ai_flags = AI_CANONNAME;
	if (getaddrinfo(addr, NULL, &hints, &dest)) {
		return (NULL);
	}
	return (dest);
}