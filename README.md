SPF Mail Filter for Sendmail/Postfix
====================================

This is a lightweight Sendmail milter that implements the [Sender
Policy Framework (SPF)](http://www.openspf.org) with the help of the
[libSPF2 library](https://www.libspf2.org). 
SPF can be used to prevent forgery of the envelope sender (MAIL FORM)
address. A sending domain may specify IP addresses and host names that
are authorized to send mail on its behalf; E-mail originating from
other hosts can be rejected, quarantined or otherwise flagged for spam
filtering and other verification purposes.

The code here is an alternative for other milters, such as 
spfmilter, spf-milter and milter-spiff.

This milter was originally developed in 2005-2007 by Eugene Kurmanin
(email defunct), but then apparently abandoned. RedHat briefly carried
it in their Fedora repositories, but dropped it as it was unmaintained.
I added a number of features I needed in 2009, and systemd support in
2018. It has been running well for some 10 years on my private mail
gateway.

There is an alternative, independent fork Kurmanin's original code at
https://github.com/jcbf/smf-spf. I was unaware of it until very recently.
Take your pick. We might join the two forks one day.

What follows comes largely form the original README, with updates
and corrections as applicable.

Ole Hansen, December 2018

Features
--------

- external editable configuration file;
- whitelist by an IP address (in CIDR notation);
- whitelist by a PTR (reverse DNS) record;
- whitelist by an envelope sender e-Mail address;
- whitelist by an envelope recipient e-Mail address;
- scalable and tunable fast in-memory cache engine;
- SMTP AUTH support;
- experimental RFC-4408 standard compliance;
- standard Received-SPF: header builder;
- option to blocking of e-Mail messages at SPF Fail results;
- quarantine mode for e-Mail messages at SPF Fail/SoftFail results;
- option to Subject tagging of e-Mail messages at SPF Fail/SoftFail results.

Installation
------------

Requirements: Linux/FreeBSD/Solaris, Sendmail v8.12 and higher compiled with
milter support enabled, Sendmail Development Kit, POSIX threads library,
libSPF2 library. A fast local caching DNS server is strongly recommended.
This milter requires libSPF2 v1.2.5 from http://www.libspf2.org/.
Under FreeBSD, BIND v8 is required (pkg_add -r bind) for libSPF2 building.

Edit the Makefile according to version of your Sendmail program and OS.

As root, do:
```
make
make install
```

Inspect and edit the `/etc/mail/smfs/smf-spf.conf` file.

Then start the milter like this:
```
/usr/local/sbin/smf-spf
```

or
```
/usr/local/sbin/smf-spf -c /etc/mail/smfs/smf-spf.conf
```

Add this milter to start-up scripts before starting of Sendmail daemon.
Look at the contributed samples of start-up scripts in the `init` directory.

Configuration
-------------

Add these lines to your Sendmail configuration file (usually `sendmail.mc`):
```
define(`confMILTER_MACROS_HELO', confMILTER_MACROS_HELO`, {verify}')dnl
INPUT_MAIL_FILTER(`smf-spf', `S=unix:/var/run/smfs/smf-spf.sock, T=S:30s;R:1m')dnl
```

IMPORTANT: make sure that `/var/run` is not a group writable directory!
If so, do `chmod 755 /var/run`, or switch to another directory if you do
not have the required permissions.

Rebuild your Sendmail configuration file and restart Sendmail daemon.

To get log messages for this milter in a separate file under Linux,
add this line to `/etc/rsyslog.conf` and restart Syslog daemon:
```
FAC.info   -/var/log/spf.log
```

Under FreeBSD do
```
touch /var/log/spf.log
```

add these lines to `syslog.conf`, and restart Syslog daemon:
```
!smf-spf
FAC.info   -/var/log/spf.log
```

where FAC is the syslog facility that you set in `smf-spf.conf`
("mail" by default).

If you want to exclude SPF None and cached SPF results from logging,
set the syslog priority to "notice" instead of "info".

In quarantine mode, SPF Fail/SoftFail e-Mail messages will be redirected
to the specified quarantine mailbox. All envelope recipients, except whitelisted
ones, will be removed, and inserted into original e-Mail messages as
`X-SPF-Original-To:` headers.

Successfully authenticated senders will bypass all SPF checks.

Below are a few additional Sendmail configuration options that may be useful.
```
define(`confPRIVACY_FLAGS', `goaway,noetrn,nobodyreturn,noreceipts')dnl
define(`confTO_COMMAND', `1m')dnl
define(`confTO_IDENT', `0s')dnl
define(`confMAX_DAEMON_CHILDREN', `256')dnl enlarge if needed
define(`confCONNECTION_RATE_THROTTLE', `8')dnl enlarge if needed
define(`confBAD_RCPT_THROTTLE', `1')dnl Sendmail v8.12+
FEATURE(`greet_pause', `5000')dnl Sendmail v8.13+
```

Creating an SPF record
----------------------

Of course, don't forget to publish your own SPF record as a TXT field in DNS,
for example like this snippet from a BIND zone file shows:
```
@  TXT  "v=spf1 a mx -all"
```

The documentation on [SPF record syntax](http://www.openspf.org/SPF_Record_Syntax)
may help with generating more complex records.
