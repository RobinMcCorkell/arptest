#ifndef FIND_DEVICE_H
#define FIND_DEVICE_H

/* find_device_by_sysfs */
#ifdef USE_SYSFS
#include <sysfs/libsysfs.h>

union sysfs_devattr_value {
	unsigned long	ulong;
	void		*ptr;
};

enum {
	SYSFS_DEVATTR_IFINDEX,
	SYSFS_DEVATTR_FLAGS,
	SYSFS_DEVATTR_ADDR_LEN,
#if 0
	SYSFS_DEVATTR_TYPE,
	SYSFS_DEVATTR_ADDRESS,
#endif
	SYSFS_DEVATTR_BROADCAST,
	SYSFS_DEVATTR_NUM
};

struct sysfs_devattr_values
{
	char *ifname;
	union sysfs_devattr_value	value[SYSFS_DEVATTR_NUM];
};
#endif

/* find_device_by_ifaddrs */
#ifndef WITHOUT_IFADDRS
#include <ifaddrs.h>
#endif

/* device definition */
struct device {
	const char *name;
	int ifindex;
#ifndef WITHOUT_IFADDRS
	struct ifaddrs *ifa;
#endif
#ifdef USE_SYSFS
	struct sysfs_devattr_values *sysfs;
#endif
};

int find_device_by_ifaddrs(struct device *dev);
int find_device_by_sysfs(struct device *dev);
int find_device_by_ioctl(struct device *dev);

int find_device(struct device *dev);

#endif
