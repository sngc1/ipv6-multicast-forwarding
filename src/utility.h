/*
 * utility.h
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
#ifndef UTILITY_H_
#define UTILITY_H_

#include <stdio.h>
#include <stdlib.h>
#include <strings.h>
#include <netinet/in.h>

int get_ifindex (char * ifname);
struct in6_addr *get_ingress_addr(char *iif);
int is_same_prefix(const struct in6_addr *addr1,
					const struct in6_addr *addr2,
				    int pfxlen);

#endif /* UTILITY_H_ */
