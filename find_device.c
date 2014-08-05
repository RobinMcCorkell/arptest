/*
 * This file is part of arptest
 *
 * find_device.c: extract from arping.c in iputils
 *
 *		This program is free software; you can redistribute it and/or
 *		modify it under the terms of the GNU General Public License
 *		as published by the Free Software Foundation; either version
 *		2 of the License, or (at your option) any later version.
 *
 * Authors:	Alexey Kuznetsov, <kuznet@ms2.inr.ac.ru>
 * 		YOSHIFUJI Hideaki <yoshfuji@linux-ipv6.org>
 */

#define _GNU_SOURCE

#include <stdlib.h>
#include <sys/param.h>
#include <sys/socket.h>
#include <linux/sockios.h>
#include <sys/file.h>
#include <sys/time.h>
#include <sys/signal.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <linux/if_packet.h>
#include <linux/if_ether.h>
#include <net/if_arp.h>
#include <sys/uio.h>

#include <netdb.h>
#include <unistd.h>
#include <stdio.h>
#include <ctype.h>
#include <errno.h>
#include <string.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "find_device.h"

#ifdef USE_SYSFS

static int sysfs_devattr_ulong_dec(char *ptr, struct sysfs_devattr_values *v, unsigned idx);
static int sysfs_devattr_ulong_hex(char *ptr, struct sysfs_devattr_values *v, unsigned idx);
static int sysfs_devattr_macaddr(char *ptr, struct sysfs_devattr_values *v, unsigned idx);

struct sysfs_devattrs {
	const char *name;
	int (*handler)(char *ptr, struct sysfs_devattr_values *v, unsigned int idx);
	int free;
} sysfs_devattrs[SYSFS_DEVATTR_NUM] = {
	[SYSFS_DEVATTR_IFINDEX] = {
		.name		= "ifindex",
		.handler	= sysfs_devattr_ulong_dec,
	},
	[SYSFS_DEVATTR_ADDR_LEN] = {
		.name		= "addr_len",
		.handler	= sysfs_devattr_ulong_dec,
	},
	[SYSFS_DEVATTR_FLAGS] = {
		.name		= "flags",
		.handler	= sysfs_devattr_ulong_hex,
	},
#if 0
	[SYSFS_DEVATTR_TYPE] = {
		.name		= "type",
		.handler	= sysfs_devattr_ulong_dec,
	},
	[SYSFS_DEVATTR_ADDRESS] = {
		.name		= "address",
		.handler	= sysfs_devattr_macaddr,
		.free		= 1,
	},
#endif
	[SYSFS_DEVATTR_BROADCAST] = {
		.name		= "broadcast",
		.handler	= sysfs_devattr_macaddr,
		.free		= 1,
	},
};
#endif

/*
 * find_device()
 *
 * This function checks if the device is okay for ARP
 *
 * Return value:
 *	>0	: Succeeded, and appropriate device not found.
 *		  device.ifindex remains 0.
 *	0	: Succeeded, and approptiate device found.
 *		  device.ifindex is set.
 *	<0	: Failed.  Support not found, or other
 *		: system error.  Try other method.
 *
 * We have several implementations for this.
 *	by_ifaddrs():	requires getifaddr() in glibc, and rtnetlink in
 *			kernel. default and recommended for recent systems.
 *	by_sysfs():	requires libsysfs , and sysfs in kernel.
 *	by_ioctl():	unable to list devices without ipv4 address; this
 *			means, you need to supply the device name for
 *			DAD purpose.
 */
/* Common check for ifa->ifa_flags */
static int check_ifflags(unsigned int ifflags, int fatal, const char *devname)
{
	if (!(ifflags & IFF_UP)) {
		if (fatal) {
/*			if (!quiet)*/
				printf("Interface \"%s\" is down\n", devname);
			exit(2);
		}
		return -1;
	}
	if (ifflags & (IFF_NOARP | IFF_LOOPBACK)) {
		if (fatal) {
/*			if (!quiet)*/
				printf("Interface \"%s\" is not ARPable\n", devname);
/*			exit(dad ? 0 : 2);*/
			exit(2);
		}
		return -1;
	}
	return 0;
}

int find_device_by_ifaddrs(struct device *dev)
{
#ifndef WITHOUT_IFADDRS
	int rc;
	struct ifaddrs *ifa0, *ifa;
	int count = 0;

	rc = getifaddrs(&ifa0);
	if (rc) {
		perror("getifaddrs");
		return -1;
	}

	for (ifa = ifa0; ifa; ifa = ifa->ifa_next) {
		if (!ifa->ifa_addr)
			continue;
		if (ifa->ifa_addr->sa_family != AF_PACKET)
			continue;
		if (dev->name && ifa->ifa_name && strcmp(ifa->ifa_name, dev->name))
			continue;

		if (check_ifflags(ifa->ifa_flags, dev->name != NULL, dev->name) < 0)
			continue;

		if (!((struct sockaddr_ll *)ifa->ifa_addr)->sll_halen)
			continue;
		if (!ifa->ifa_broadaddr)
			continue;

		dev->ifa = ifa;

		if (count++)
			break;
	}

	if (count == 1 && dev->ifa) {
		dev->ifindex = if_nametoindex(dev->ifa->ifa_name);
		if (!dev->ifindex) {
			perror("arping: if_nametoindex");
			freeifaddrs(ifa0);
			return -1;
		}
/*		dev->name  = dev->ifa->ifa_name; */
		return 0;
	}
	return 1;
#else
	return -1;
#endif
}

#ifdef USE_SYSFS
static void sysfs_devattr_values_init(struct sysfs_devattr_values *v, int do_free)
{
	int i;
	if (do_free) {
		free(v->ifname);
		for (i = 0; i < SYSFS_DEVATTR_NUM; i++) {
			if (sysfs_devattrs[i].free)
				free(v->value[i].ptr);
		}
	}
	memset(v, 0, sizeof(*v));
}

static int sysfs_devattr_ulong(char *ptr, struct sysfs_devattr_values *v, unsigned int idx,
				     unsigned int base)
{
	unsigned long *p;
	char *ep;

	if (!ptr || !v)
		return -1;

	p = &v->value[idx].ulong;
	errno = 0;
	*p = strtoul(ptr, &ep, base);
	if ((*ptr && isspace(*ptr & 0xff)) || errno || (*ep != '\0' && *ep != '\n'))
		goto out;

	return 0;
out:
	return -1;
}

static int sysfs_devattr_ulong_dec(char *ptr, struct sysfs_devattr_values *v, unsigned int idx)
{
	int rc = sysfs_devattr_ulong(ptr, v, idx, 10);
	return rc;
}

static int sysfs_devattr_ulong_hex(char *ptr, struct sysfs_devattr_values *v, unsigned int idx)
{
	int rc = sysfs_devattr_ulong(ptr, v, idx, 16);
	return rc;
}

static int sysfs_devattr_macaddr(char *ptr, struct sysfs_devattr_values *v, unsigned int idx)
{
	unsigned char *m;
	int i;
	unsigned int addrlen;

	if (!ptr || !v)
		return -1;

	addrlen = v->value[SYSFS_DEVATTR_ADDR_LEN].ulong;
	m = malloc(addrlen);

	for (i = 0; i < addrlen; i++) {
		if (i && *(ptr + i * 3 - 1) != ':')
			goto out;
		if (sscanf(ptr + i * 3, "%02hhx", &m[i]) != 1)
			goto out;
	}

	v->value[idx].ptr = m;
	return 0;
out:
	free(m);
	return -1;
}
#endif

int find_device_by_sysfs(struct device *dev)
{
	int rc = -1;
#ifdef USE_SYSFS
	struct sysfs_class *cls_net;
	struct dlist *dev_list;
	struct sysfs_class_device *dev_sysfs;
	struct sysfs_attribute *dev_attr;
	struct sysfs_devattr_values sysfs_devattr_values;
	int count = 0;

	if (!dev->sysfs) {
		dev->sysfs = malloc(sizeof(*dev->sysfs));
		sysfs_devattr_values_init(dev->sysfs, 0);
	}

	cls_net = sysfs_open_class("net");
	if (!cls_net) {
		perror("sysfs_open_class");
		return -1;
	}

	dev_list = sysfs_get_class_devices(cls_net);
	if (!dev_list) {
		perror("sysfs_get_class_devices");
		goto out;
	}

	sysfs_devattr_values_init(&sysfs_devattr_values, 0);

	dlist_for_each_data(dev_list, dev_sysfs, struct sysfs_class_device) {
		int i;
		int rc = -1;

		if (dev->name && strcmp(dev_sysfs->name, dev->name))
			goto do_next;

		sysfs_devattr_values_init(&sysfs_devattr_values, 1);

		for (i = 0; i < SYSFS_DEVATTR_NUM; i++) {

			dev_attr = sysfs_get_classdev_attr(dev_sysfs, sysfs_devattrs[i].name);
			if (!dev_attr) {
				perror("sysfs_get_classdev_attr");
				rc = -1;
				break;
			}
			if (sysfs_read_attribute(dev_attr)) {
				perror("sysfs_read_attribute");
				rc = -1;
				break;
			}
			rc = sysfs_devattrs[i].handler(dev_attr->value, &sysfs_devattr_values, i);

			if (rc < 0)
				break;
		}

		if (rc < 0)
			goto do_next;

		if (check_ifflags(sysfs_devattr_values.value[SYSFS_DEVATTR_FLAGS].ulong,
				  dev->name != NULL, dev->name) < 0)
			goto do_next;

		if (!sysfs_devattr_values.value[SYSFS_DEVATTR_ADDR_LEN].ulong)
			goto do_next;

		if (dev->sysfs->value[SYSFS_DEVATTR_IFINDEX].ulong) {
			if (dev->sysfs->value[SYSFS_DEVATTR_FLAGS].ulong & IFF_RUNNING)
				goto do_next;
		}

		sysfs_devattr_values.ifname = strdup(dev_sysfs->name);
		if (!sysfs_devattr_values.ifname) {
			perror("malloc");
			goto out;
		}

		sysfs_devattr_values_init(dev->sysfs, 1);
		memcpy(dev->sysfs, &sysfs_devattr_values, sizeof(*dev->sysfs));
		sysfs_devattr_values_init(&sysfs_devattr_values, 0);

		if (count++)
			break;

		continue;
do_next:
		sysfs_devattr_values_init(&sysfs_devattr_values, 1);
	}

	if (count == 1) {
		dev->ifindex = dev->sysfs->value[SYSFS_DEVATTR_IFINDEX].ulong;
/*		dev->name = dev->sysfs->ifname; */
	}
	rc = !dev->ifindex;
out:
	sysfs_close_class(cls_net);
#endif
	return rc;
}

static int check_device_by_ioctl(int s, struct ifreq *ifr, struct device *dev)
{
	if (ioctl(s, SIOCGIFFLAGS, ifr) < 0) {
		perror("ioctl(SIOCGIFINDEX");
		return -1;
	}

	if (check_ifflags(ifr->ifr_flags, dev->name != NULL, dev->name) < 0)
		return 1;

	if (ioctl(s, SIOCGIFINDEX, ifr) < 0) {
		perror("ioctl(SIOCGIFINDEX");
		return -1;
	}

	return 0;
}

int find_device_by_ioctl(struct device *dev)
{
	int s;
	struct ifreq *ifr0, *ifr, *ifr_end;
	size_t ifrsize = sizeof(*ifr);
	struct ifconf ifc;
	static struct ifreq ifrbuf;
	int count = 0;

	s = socket(AF_INET, SOCK_DGRAM, 0);
	if (s < 0) {
		perror("socket");
		return -1;
	}

	memset(&ifrbuf, 0, sizeof(ifrbuf));

/*	if (dev->name) {*/
		strncpy(ifrbuf.ifr_name, dev->name, sizeof(ifrbuf.ifr_name) - 1);
		if (check_device_by_ioctl(s, &ifrbuf, dev))
			goto out;
		count++;
/*	} else {
		do {
			int rc;
			ifr0 = malloc(ifrsize);
			if (!ifr0) {
				perror("malloc");
				goto out;
			}

			ifc.ifc_buf = (char *)ifr0;
			ifc.ifc_len = ifrsize;

			rc = ioctl(s, SIOCGIFCONF, &ifc);
			if (rc < 0) {
				perror("ioctl(SIOCFIFCONF");
				goto out;
			}

			if (ifc.ifc_len + sizeof(*ifr0) + sizeof(struct sockaddr_storage) - sizeof(struct sockaddr) <= ifrsize)
				break;
			ifrsize *= 2;
			free(ifr0);
			ifr0 = NULL;
		} while(ifrsize < INT_MAX / 2);

		if (!ifr0) {
			fprintf(stderr, "arping: too many interfaces!?\n");
			goto out;
		}

		ifr_end = (struct ifreq *)(((char *)ifr0) + ifc.ifc_len - sizeof(*ifr0));
		for (ifr = ifr0; ifr <= ifr_end; ifr++) {
			if (check_device_by_ioctl(s, &ifrbuf, dev))
				continue;
			memcpy(&ifrbuf.ifr_name, ifr->ifr_name, sizeof(ifrbuf.ifr_name));
			if (count++)
				break;
		}
	}*/

	close(s);

	if (count == 1) {
		dev->ifindex = ifrbuf.ifr_ifindex;
/*		dev->name = ifrbuf.ifr_name; */
	}
	return !dev->ifindex;
out:
	close(s);
	return -1;
}

int find_device(struct device *dev)
{
	int rc;
	rc = find_device_by_ifaddrs(dev);
	if (rc >= 0)
		goto out;
	rc = find_device_by_sysfs(dev);
	if (rc >= 0)
		goto out;
	rc = find_device_by_ioctl(dev);
out:
	return rc;
}

