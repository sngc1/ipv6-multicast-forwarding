/*
 * main.c
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
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <syslog.h>
#include <unistd.h>

#include "si6mfd.h"

volatile int issigterm = 0;
volatile int issigint = 0;

static void Usage(char *bname)
{
	fprintf(stderr,
		"Usage: %s -i <IIF> -e <EIF> [options]\n Descriptions:\n"
		"  -i <IIF>           Set ingress interface name\n"
		"  -e <EIF>           Set egress interface name\n"
		" options:\n"
		"  -?, -h, --help     Display this help text\n"
		"  -d                 Start as daemon, detach from terminal\n\n"
		" Example:\n \t $sudo %s -i eth0 -e tun0 -d\n",
		bname, bname);
}

void sigtermh (int sig)
{
	signal(SIGTERM, sigtermh);
	++issigterm;

	if (issigterm > 1)
		abort();
}

void siginth (int sig)
{
	signal(SIGINT, siginth);
	++issigint;

	if (issigint > 1)
		abort();
}

int main_loop(char *iif, char *eif)
{
	if (sim6fd_init (iif, eif))
		return -1;

	for(;;)
	{
		if (sim6fd_main())
			return -1;

		if (issigterm || issigint)
			break;
	}

	if (shutdown_mcast6() < 0)
		return -1;
	
	return 0;
}

int main(int argc, char **argv)
{
	int rtn = 1;
	char *iif, *eif;
	int isDaemon = 0;
	char *bin_name;
	bin_name = ((bin_name = strrchr(argv[0], '/')) != NULL ) ? bin_name+1 : argv[0];

	if (argc != 5 && argc != 6){
		Usage(bin_name);
		exit(EXIT_FAILURE);
	}
    
	int c;
	while((c = getopt(argc, argv, "i:e:d")) > 0){
		switch(c){
			case 'i':
				iif = optarg;
				break;
			case 'e':
				eif = optarg;
				break;
			case 'd':
				isDaemon = 1;
				break;
			case ':':
				fprintf(stderr, "%s: unknown option.\n", bin_name);
				Usage(bin_name);
				exit(EXIT_FAILURE);
			case '?':
				Usage(bin_name);
				exit(EXIT_FAILURE);
		}
	}

	if (isDaemon){
		if(daemon(0,0) < 0){
			perror("daemon:");
			goto close;
		} else{
			openlog(bin_name, LOG_PID, LOG_DAEMON);
			syslog(LOG_INFO, "%s started as a daemon. IIF=%s, EIF=%s\n", bin_name, iif, eif);
		}
	}
	else{
		openlog(bin_name, LOG_PID|LOG_PERROR, LOG_DAEMON);
		syslog(LOG_INFO, "%s started in debug mode. IIF=%s, EIF=%s\n", bin_name, iif, eif);
	}

	signal(SIGINT, siginth);
	signal(SIGTERM, sigtermh);

	rtn = main_loop(iif, eif);

close:
	syslog(LOG_INFO, "%s has been terminated.", bin_name);
	closelog();
	return rtn;
}

