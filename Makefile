CFLAGS := $(CFLAGS) -std=c99

bindir := /usr/bin

all: arptest

arptest: arptest.o find_device.o

install: arptest
	install -T arptest $(DESTDIR)$(bindir)/arptest

clean:
	rm -f arptest *.o

.PHONY: install clean
