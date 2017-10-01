/*
 * si6mfd.h
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
#ifndef SI6MFD_H_
#define SI6MFD_H_

#define EGRESS_VIF_INDEX 1
#define INGRESS_VIF_INDEX 2

#include <netinet/in.h>

char src_addr_str[INET6_ADDRSTRLEN], dst_addr_str[INET6_ADDRSTRLEN], mc_addr_str[INET6_ADDRSTRLEN];
struct in6_addr *ingress_addr;
int activate_mcast6();
int shutdown_mcast6();
int add_mcast6_virtual_if(int physical_if_index, int virtual_if_index);
int add_mcast6_fwd_entry(struct sockaddr_in6 mc6_origin, struct sockaddr_in6 mc6_grpaddr);
int sim6fd_init (char *iif, char *eif);
int sim6fd_main();

#endif /* SI6MFD_H_ */
