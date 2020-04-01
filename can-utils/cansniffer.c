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
#include <fcntl.h>
#include <signal.h>
#include <ctype.h>
#include <libgen.h>
#include <time.h>

#include <sys/time.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <linux/sockios.h>
#include <sys/ioctl.h>
#include <sys/uio.h>
#include <net/if.h>

#include <linux/can.h>
#include <linux/can/bcm.h>

#define U64_DATA(p) (*(unsigned long long*)(p)->data)

#define ANYDEV   "any"

/* flags */

#define ENABLE  1 /* by filter or user */
#define DISPLAY 2 /* is on the screen */
#define UPDATE  4 /* needs to be printed on the screen */

/* flags testing & setting */

#define is_set(id, flag) (sniftab[id].flags & flag)

#define do_set(id, flag) (sniftab[id].flags |= flag)
#define do_clr(id, flag) (sniftab[id].flags &= ~flag)

/* time defaults */

#define HOLD    10 /* in 100ms */
#define LOOP     2 /* in 100ms */

#define STARTLINESTR "X  time    ID  data ... "

struct snif {
	int flags;
	long hold;
	struct can_frame last;
	struct can_frame current;
} sniftab[2048];


extern int optind;

static int filter_id_only;
static long hold = HOLD;
static long loop = LOOP;
static char *interface;

void rx_setup (int fd, int id);
void print_snifline(int id);
int handle_bcm(int fd, long currcms);

int main()
{
	char *device_name = "vcan0";
	fd_set rdfs;
	int s;
	long currcms = 0;
	long lastcms = 0;
	int ret;
	struct timeval timeo, start_tv, tv;
	struct sockaddr_can addr;
	struct ifreq ifr;
	int i;

	for (i=0; i < 2048 ;i++) /* default: check all CAN-IDs */
		do_set(i, ENABLE);

	if (strlen(device_name) >= IFNAMSIZ) {
		printf("name of CAN device '%s' is too long!\n", device_name);
		return 1;
	}

	interface = device_name;

	if ((s = socket(PF_CAN, SOCK_DGRAM, CAN_BCM)) < 0) {
		perror("socket");
		return 1;
	}

	addr.can_family = AF_CAN;

	if (strcmp(ANYDEV, device_name)) {
		strcpy(ifr.ifr_name, device_name);
		if (ioctl(s, SIOCGIFINDEX, &ifr) < 0) {
			perror("SIOCGIFINDEX");
			exit(1);
		}
		addr.can_ifindex = ifr.ifr_ifindex;
	}
	else
		addr.can_ifindex = 0; /* any can interface */

	if (connect(s, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
		perror("connect");
		return 1;
	}

	for (i=0; i < 2048 ;i++) /* initial BCM setup */
		if (is_set(i, ENABLE))
			rx_setup(s, i);

	gettimeofday(&start_tv, NULL);
	tv.tv_sec = tv.tv_usec = 0;

	while (1) {

		FD_ZERO(&rdfs);
		FD_SET(0, &rdfs);
		FD_SET(s, &rdfs);

		timeo.tv_sec  = 0;
		timeo.tv_usec = 100000 * loop;

		if ((ret = select(s+1, &rdfs, NULL, NULL, &timeo)) < 0) {
			//perror("select");
			exit(-1);
		}

		gettimeofday(&tv, NULL);
		currcms = (tv.tv_sec - start_tv.tv_sec) * 10 + (tv.tv_usec / 100000);

		if (FD_ISSET(s, &rdfs))
			if(!handle_bcm(s, currcms))
			{
			exit(-1);
			}

		if (currcms - lastcms >= loop) {
			if(!handle_timeo(s, currcms))
			{
			exit(-1);
			}
			lastcms = currcms;
		}
	}

	close(s);
	return 0;
}

void rx_setup (int fd, int id){

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

int handle_bcm(int fd, long currcms){

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

	do_set(id, DISPLAY);
	do_set(id, UPDATE);
	
	return 1; /* ok */
};

int handle_timeo(int fd, long currcms){

	int i;

	for (i=0; i < 2048; i++) {

		if is_set(i, ENABLE) {

				if is_set(i, DISPLAY) {

						if (is_set(i, UPDATE)){
							print_snifline(i);
							sniftab[i].hold = currcms + hold;
							do_clr(i, UPDATE);
						}
						else
							if ((sniftab[i].hold) && (sniftab[i].hold < currcms)) {
								print_snifline(i);
								sniftab[i].hold = 0; /* disable update by hold */
							}
					}
				sniftab[i].last      = sniftab[i].current;
			}
	}

	return 1; /* ok */

};

void print_snifline(int id){

	int i;

		for (i=0; i<sniftab[id].current.can_dlc; i++)
			printf("%02X ", sniftab[id].current.data[i]);

		if (sniftab[id].current.can_dlc < 8)
			printf("%*s", (8 - sniftab[id].current.can_dlc) * 3, "");

	putchar('\n');
};

