/*
 *  $Id$
 */

/*
 * can-sniffer.c
 *
 * Copyright (c) 2002-2007 Volkswagen Group Electronic Research
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. Neither the name of Volkswagen nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * Alternatively, provided that this notice is retained in full, this
 * software may be distributed under the terms of the GNU General
 * Public License ("GPL") version 2, in which case the provisions of the
 * GPL apply INSTEAD OF those given above.
 *
 * The provided data structures and external interfaces from this code
 * are not restricted to be used by modules with a GPL compatible license.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 * OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH
 * DAMAGE.
 *
 * Send feedback to <socketcan-users@lists.berlios.de>
 *
 */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>

#include <sys/time.h>
#include <sys/ioctl.h>
#include <net/if.h>

#include <linux/can.h>
#include <linux/can/bcm.h>

#define U64_DATA(p) (*(unsigned long long*)(p)->data)

#define ANYDEV   "any"

struct snif {
	int flags;
	struct can_frame current;
};

void rx_setup (int fd, int id, int filter_id_only);
void print_snifline(struct can_frame current);
int handle_bcm(int fd, struct snif *sniftab);
//int handle_timeo(int fd, struct snif *sniftab);
int handle_timeo(int fd, struct snif *sniftab, void (*out)(struct can_frame current));
int recv_loop(int s, long loop, struct snif *sniftab, struct timeval start_tv, struct timeval tv, long *lastcms, void (*out)(struct can_frame current));
int init(struct snif *sniftab, char* interface, int *s, int filter_id_only);

int main()
{
	char *interface = "vcan0";
	struct snif sniftab[2048];
	memset(&sniftab,0x00,sizeof(sniftab));

	int filter_id_only = 0;
	long loop = 2;
	int s;

	if(init(sniftab,interface,&s,filter_id_only)){return 1;}

	struct timeval start_tv;
	gettimeofday(&start_tv, NULL);

	struct timeval tv;
	tv.tv_sec = tv.tv_usec = 0;
	long lastcms = 0;

	while(!recv_loop(s,loop, sniftab, start_tv, tv, &lastcms, &print_snifline));
	close(s);
	return 0;
}

int init(struct snif *sniftab, char* interface, int *s, int filter_id_only)
{
	if (strlen(interface) >= IFNAMSIZ) {
		printf("name of CAN device '%s' is too long!\n", interface);
		return 1;
	}

	if ((*s = socket(PF_CAN, SOCK_DGRAM, CAN_BCM)) < 0) {
		perror("socket");
		return 1;
	}

	struct sockaddr_can addr;
	struct ifreq ifr;

	addr.can_family = AF_CAN;

	if (strcmp(ANYDEV, interface)) {
		strcpy(ifr.ifr_name, interface);
		if (ioctl(*s, SIOCGIFINDEX, &ifr) < 0) {
			perror("SIOCGIFINDEX");
			exit(1);
		}
		addr.can_ifindex = ifr.ifr_ifindex;
	}
	else
		addr.can_ifindex = 0; /* any can interface */

	if (connect(*s, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
		perror("connect");
		return 1;
	}

	for (int i=0; i < 2048 ;i++) /* initial BCM setup */
		rx_setup(*s, i, filter_id_only);
	return 0;
}

int recv_loop(int s, long loop, struct snif *sniftab, struct timeval start_tv, struct timeval tv, long *lastcms, void (*out)(struct can_frame current))
{
	fd_set rdfs;
	struct timeval timeo;
	
	FD_ZERO(&rdfs);
	FD_SET(0, &rdfs);
	FD_SET(s, &rdfs);

	timeo.tv_sec  = 0;
	timeo.tv_usec = 100000 * loop;

	if ((select(s+1, &rdfs, NULL, NULL, &timeo)) < 0) {return -1;}

	gettimeofday(&tv, NULL);
	long currcms = (tv.tv_sec - start_tv.tv_sec) * 10 + (tv.tv_usec / 100000);

	if(FD_ISSET(s, &rdfs) && !handle_bcm(s, sniftab)){return -1;}
	if (currcms - *lastcms >= loop) {
		if(!handle_timeo(s, sniftab, out)){return -1;}
		*lastcms = currcms;
	}

	return 0;
}

void rx_setup (int fd, int id, int filter_id_only){

	struct {
		struct bcm_msg_head msg_head;
		struct can_frame frame;
	} txmsg;

	txmsg.msg_head.opcode  = RX_SETUP;
	txmsg.msg_head.can_id  = id;
	txmsg.msg_head.flags   = RX_CHECK_DLC;
	txmsg.msg_head.ival1.tv_sec  = 0;
	txmsg.msg_head.ival1.tv_usec = 0;
	txmsg.msg_head.ival2.tv_sec  = 0;
	txmsg.msg_head.ival2.tv_usec = 0;
	txmsg.msg_head.nframes = 1;
	U64_DATA(&txmsg.frame) = (__u64) 0xFFFFFFFFFFFFFFFFULL;

	if (filter_id_only)
		txmsg.msg_head.flags |= RX_FILTER_ID;

	if (write(fd, &txmsg, sizeof(txmsg)) < 0)
		perror("write");
};

int handle_bcm(int fd, struct snif *sniftab){

	int nbytes, id;

	struct {
		struct bcm_msg_head msg_head;
		struct can_frame frame;
	} bmsg;

	if ((nbytes = read(fd, &bmsg, sizeof(bmsg))) < 0) {
		perror("bcm read");
		return 0; /* quit */
	}

	id = bmsg.msg_head.can_id;

	if ((bmsg.msg_head.opcode != RX_CHANGED) || (nbytes != sizeof(bmsg))) {
		printf("received strange BCM opcode %d!\n", bmsg.msg_head.opcode);
		printf("received strange BCM data length %d!\n", nbytes);
		return 0; /* quit */
	}

	sniftab[id].current = bmsg.frame;
	sniftab[id].flags = 1;
	
	return 1; /* ok */
};

int handle_timeo(int fd, struct snif *sniftab, void (*out)(struct can_frame current)){

	for (int id=0; id < 2048; id++) {

		if (sniftab[id].flags) {
			out(sniftab[id].current);
			sniftab[id].flags = 0;
		}
	}

	return 1; /* ok */

};

void print_snifline(struct can_frame current){
		for (int i=0; i<current.can_dlc; i++)
			printf("%02X ", current.data[i]);

		if (current.can_dlc < 8)
			printf("%*s", (8 - current.can_dlc) * 3, "");

	putchar('\n');
};

