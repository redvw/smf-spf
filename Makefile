CC = gcc
PREFIX = /usr
SBINDIR = $(PREFIX)/sbin
DATADIR = /var/run/smfs
CONFDIR = /etc/mail/smfs
USER = smfs
GROUP = smfs
PROG = smf-spf
#DEBUG = 1

# Linux
LDFLAGS = -lmilter -lpthread -lspf2

# FreeBSD
#LDFLAGS = -lmilter -pthread -L/usr/local/lib -lspf2

# Solaris
#LDFLAGS = -lmilter -lpthread -lsocket -lnsl -lresolv -lspf2

# Sendmail v8.11
#LDFLAGS += -lsmutil

ifndef OPTFLAGS
OPTFLAGS = -O2 -g
endif

ifdef DEBUG
CFLAGS = -g -O0
else
CFLAGS = $(OPTFLAGS) -DNDEBUG
endif
CFLAGS += -D_REENTRANT -fomit-frame-pointer


all:	$(PROG)

$(PROG): $(PROG).o
	$(CC) $(LDFLAGS) -o $@ $^

%.o:	%.c
	$(CC) $(CFLAGS) -c $<

clean:
	rm -f smf-spf.o smf-spf *~

install:
	@./install.sh
	@cp -f -p $(PROG) $(SBINDIR)
	@if test ! -d $(DATADIR); then \
	mkdir -m 700 $(DATADIR); \
	chown $(USER):$(GROUP) $(DATADIR); \
	fi
	@if test ! -d $(CONFDIR); then \
	mkdir -m 755 $(CONFDIR); \
	fi
	@if test ! -f $(CONFDIR)/$(PROG).conf; then \
	cp -p $(PROG).conf $(CONFDIR)/$(PROG).conf; \
	else \
	cp -p $(PROG).conf $(CONFDIR)/$(PROG).conf.new; \
	fi
	@echo Please, inspect and edit the $(CONFDIR)/$(PROG).conf file.
