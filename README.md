Host Availability Tester with ARP
=================================

arptest can test if a particular IP address is available from a particular
interface, and will print out its MAC address if it is. Otherwise, if a timeout
occurs, nothing will be printed and arptest will exit with a non-zero exit code.

arptest will still work even if the interface has no IP address assigned, but
has a link.

Usage
-----

	arptest [options] iface ipaddr

iface  : interface to send/receive ARP packets from/to
ipaddr : IP address of host to test

### Options

-w : timeout for receiving ARP reply

### Return Values

ERR_SUCCESS = 0 : success
ERR_FAIL    = 1 : timeout reached, no reply
ERR_ARGS    = 2 : error in command parameters
ERR_SYS     = 3 : system error

In case of any error besides ERR_FAIL, output will be printed to stderr
describing the error.

In case of success, the MAC address of the host matching ipaddr will be printed
to stdout.

Installation
------------

No special libraries are required, just the Linux headers for your kernel
version. Ensure that your C compiler is capable of C99 support.

    make
    make install

Installation path can be adjusted in Makefile
