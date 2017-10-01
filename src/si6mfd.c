/*
 * si6mfd.c
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
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <strings.h>
#include <syslog.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <linux/mroute6.h>
#include <net/if.h>
#include <net/route.h>
#include <netinet/ip6.h>
#include <netinet/icmp6.h>
#include <sys/ioctl.h>
#include <sys/param.h>
#include <sys/socket.h>
#include <sys/select.h>
#include <sys/types.h>
#include <sys/uio.h>

#include "si6mfd.h"
#include "utility.h"

static char rawsocket_buffer[8192];
static int mcast6_routing_socket = -1;

int activate_mcast6()
{
	int v = 1;
	struct icmp6_filter icmp6filter;

	/* Open multicast routing socket */
	mcast6_routing_socket = socket(AF_INET6, SOCK_RAW, IPPROTO_ICMPV6);
	if (mcast6_routing_socket < 0)
	{
		syslog(LOG_ERR, "Unable to create IPv6 multicast routing socket.");
		return -1;
	}

	/* Set mulcast routing socket to block all ICMP6 packets */
	ICMP6_FILTER_SETBLOCKALL(&icmp6filter);
	if (setsockopt(mcast6_routing_socket, IPPROTO_ICMPV6, ICMP6_FILTER, &icmp6filter, sizeof(icmp6filter)) < 0)
	{
		syslog(LOG_ERR, "Unable to set ICMP6 filter to multicast routing socket.");
		return -1;
	}
	
	/* Activate kernel IPv6 multicast routing */
	if (setsockopt(mcast6_routing_socket, IPPROTO_IPV6, MRT6_INIT, (void *)&v, sizeof(int)) < 0)
	{
		syslog(LOG_ERR, "Unable to set MRT6_INIT to kernel.");
		return -1;
	}
	return 0;
}

int shutdown_mcast6()
{
	if (setsockopt(mcast6_routing_socket, IPPROTO_IPV6, MRT6_DONE, NULL, 0) < 0)
	{
		syslog(LOG_ERR, "Unable to disable IPv6 multicast routing.");
		return -1;
	}
	return 0;
}

int add_mcast6_virtual_if(int physical_if_index, int virtual_if_index)
{
	struct mif6ctl mc;
	memset(&mc, 0, sizeof(mc));
	mc.mif6c_pifi = physical_if_index;
	mc.mif6c_mifi = virtual_if_index;

	if (setsockopt(mcast6_routing_socket, IPPROTO_IPV6, MRT6_ADD_MIF,
				   (void *)&mc, sizeof(mc)))
	{
		syslog(LOG_INFO, "Unable to add multicast virtual interface, id: %d", virtual_if_index);
		return -1;
	}
	return 0;
}

int add_mcast6_fwd_entry(struct sockaddr_in6 mc6_origin, struct sockaddr_in6 mc6_grpaddr)
{
	int srcvif_index, dstvif_index;

	if(is_same_prefix(&(mc6_origin.sin6_addr), ingress_addr, 64) == 0){
		syslog(LOG_INFO, "Received a mcast packet (src %s, grp %s). Add a mc_forwarding entry (I-->E)\n",
				inet_ntop(AF_INET6, &(mc6_origin.sin6_addr), src_addr_str, INET6_ADDRSTRLEN),
				inet_ntop(AF_INET6, &(mc6_grpaddr.sin6_addr), dst_addr_str, INET6_ADDRSTRLEN));
		srcvif_index = INGRESS_VIF_INDEX;
		dstvif_index = EGRESS_VIF_INDEX;
	}else{
		syslog(LOG_INFO, "Received a mcast packet (src %s, grp %s). Add a mc_forwarding entry (E-->I)\n",
				inet_ntop(AF_INET6, &(mc6_origin.sin6_addr), src_addr_str, INET6_ADDRSTRLEN),
				inet_ntop(AF_INET6, &(mc6_grpaddr.sin6_addr), dst_addr_str, INET6_ADDRSTRLEN));
		srcvif_index = EGRESS_VIF_INDEX;
		dstvif_index = INGRESS_VIF_INDEX;
	}

	struct mf6cctl mc;
	memset(&mc, 0, sizeof(mc));
	memcpy(&mc.mf6cc_origin, &mc6_origin, sizeof(mc.mf6cc_origin));
	memcpy(&mc.mf6cc_mcastgrp, &mc6_grpaddr, sizeof(mc.mf6cc_mcastgrp));
	mc.mf6cc_parent = srcvif_index;
	IF_ZERO(&mc.mf6cc_ifset);
	IF_SET(dstvif_index, &mc.mf6cc_ifset);

	if (setsockopt(mcast6_routing_socket, IPPROTO_IPV6, MRT6_ADD_MFC,
				   (void *)&mc, sizeof(mc)))
	{
		syslog(LOG_INFO, "Unable to add mcast forwarding entry: src %s, grp %s",
				inet_ntop(AF_INET6, &(mc6_origin.sin6_addr), src_addr_str, INET6_ADDRSTRLEN),
				inet_ntop(AF_INET6, &(mc6_grpaddr.sin6_addr), dst_addr_str, INET6_ADDRSTRLEN));
		return -1;
	}
	return 0;
}

int sim6fd_init (char *iif, char *eif)
{
	ingress_addr = get_ingress_addr(iif);
	if(ingress_addr == NULL){
		syslog(LOG_ERR, "Ingress interface does not have appropriate"
				" IPv6 address(Global unicast address).\n");
		return -1;
	}

	char inaddr[INET6_ADDRSTRLEN];
	inet_ntop(AF_INET6, ingress_addr, inaddr, INET6_ADDRSTRLEN);
	syslog(LOG_INFO, "Ingress interface's address: %s\n",inaddr);

	if (activate_mcast6() < 0)
		return -1;

	if (add_mcast6_virtual_if(get_ifindex(eif), EGRESS_VIF_INDEX) < 0)
		return -1;

	if (add_mcast6_virtual_if(get_ifindex(iif), INGRESS_VIF_INDEX) < 0)
		return -1;

	return 0;
}

int sim6fd_main()
{
		fd_set readfs;
		struct mld_hdr * mh = NULL;
		struct mrt6msg * mc6_upcall = NULL;

		FD_ZERO(&readfs);
		FD_SET(mcast6_routing_socket, &readfs);

		if (select(mcast6_routing_socket+1, &readfs, NULL, NULL, NULL) < 0)
		{
			syslog(LOG_ERR, "Unable to issue SELECT.");
			return -1;
		}

		if (read(mcast6_routing_socket, rawsocket_buffer, sizeof(rawsocket_buffer)) < 0)
		{
			syslog(LOG_ERR, "Unable to read multicast routing socket.");
			return -1;
		}

		mh = (struct mld_hdr *)rawsocket_buffer;
		syslog(LOG_INFO, "ICMP6 message type %d", mh->mld_icmp6_hdr.icmp6_type);

		if (mh->mld_icmp6_hdr.icmp6_type == 0)
		{
			mc6_upcall = (struct mrt6msg *)rawsocket_buffer;
			if (mc6_upcall->im6_msgtype == MRT6MSG_NOCACHE) // kernel detected a new origin/grp pair.
			{
				struct sockaddr_in6 mc6_origin, mc6_grpaddr;
				memset(&mc6_origin, 0, sizeof(mc6_origin));
				memset(&mc6_grpaddr, 0, sizeof(mc6_grpaddr));

				mc6_origin.sin6_addr = mc6_upcall->im6_src;
				mc6_grpaddr.sin6_addr = mc6_upcall->im6_dst;

				if (IN6_IS_ADDR_MC_LINKLOCAL(&mc6_grpaddr.sin6_addr)||
						IN6_IS_ADDR_MC_NODELOCAL(&mc6_grpaddr.sin6_addr)) {
					syslog(LOG_INFO, "Received a [link|node]-local scope mcast packet (grp %s), igonore.\n",
							inet_ntop(AF_INET6, &mc6_grpaddr.sin6_addr, dst_addr_str, INET6_ADDRSTRLEN));
				} else {
					if(add_mcast6_fwd_entry(mc6_origin, mc6_grpaddr) < 0)
						return -1;
				}
			 }
		}
		return 0;
}
