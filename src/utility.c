/*
 * utility.c
 *
 * This file is part of si6mfd: Simple IPv6 multicast forwarding daemon.
 *
 * Author: Satoru Noguchi <satoru-n@is.naist.jp>
 *
 *      Copyright 2011-2012, NAIST
 *      Copyright 2010-2011, INRIA
 * 
 * This software is Copyright 2010-2011 by the above mentioned author(s)
 * and organization(s), All Rights Reserved. 
 *
 * Current version of this software is for the internal use only. 
 * It is not allowed to re-distribute the software.
 */
#include <arpa/inet.h>
#include <ifaddrs.h>
#include <netdb.h>
#include <net/if.h>
#include <string.h>
#include <sys/ioctl.h>
#include <syslog.h>
#include <sys/socket.h>
#include <unistd.h>

#include "utility.h"

int get_ifindex (char * ifname)
{
	struct ifreq ifr;
	int fd = socket(AF_INET6, SOCK_DGRAM, 0);

	if (fd < 0) {
		syslog(LOG_ERR, "Unable to create socket for obtain IF index.");
		return -1;
	}

	strncpy(ifr.ifr_name, ifname, IFNAMSIZ);
	if ( ioctl(fd, SIOCGIFINDEX, &ifr) == -1) {
		syslog(LOG_ERR, "Unable to find the device %s.", ifname);
  		return -1;
	}
	return ifr.ifr_ifindex ;
}

struct in6_addr *get_ingress_addr(char *iif) {
	struct ifaddrs *ifaddr, *ifa;
	int family;
	int isFind = 1;
	struct in6_addr *ret;

	ret = (struct in6_addr *)malloc(sizeof(struct in6_addr));

	if (getifaddrs(&ifaddr) == -1) {
		syslog(LOG_ERR, "Unable to get interface addresses of ingress IF.");
		return NULL;
	}

	for (ifa = ifaddr; ifa != NULL; ifa = ifa->ifa_next) {
		family = ifa->ifa_addr->sa_family;

		if ((strcmp(ifa->ifa_name, iif) == 0) && family == AF_INET6){
			*ret = ((struct sockaddr_in6 *)ifa->ifa_addr)->sin6_addr;

			if (!IN6_IS_ADDR_UNSPECIFIED(ret) &&
			    !IN6_IS_ADDR_LOOPBACK(ret) &&
			    !IN6_IS_ADDR_MULTICAST(ret) &&
			    !IN6_IS_ADDR_LINKLOCAL(ret)) {
					isFind = 0;
					break;
			}
		}
	}
	freeifaddrs(ifaddr);

	if(isFind == 0)
		return ret;
	else
		return NULL;
}


int is_same_prefix(const struct in6_addr *addr1, const struct in6_addr *addr2,
				       int pfxlen)
{
	int rem = pfxlen % 8;  //suffix bits
	int oct = pfxlen >> 3; //bytes
	int ret;

	if(rem != 0){
		ret = (addr1->s6_addr[oct] ^ addr2->s6_addr[oct]) & (0xFF << (8 - rem));
		if (ret != 0)
		return 1;
	}

	ret = memcmp(addr1->s6_addr, addr2->s6_addr, oct);
	if(ret == 0)
		return 0;

	return 1;
}
