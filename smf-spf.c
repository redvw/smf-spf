/*  Copyright (C) 2005, 2006 by Eugene Kurmanin <me@kurmanin.info>
 *  Modifications (C) 2009 Ole Hansen <ole@redvw.com>
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 */

/* TODO: check strdup() calls for NULL return */

#ifndef _REENTRANT
#error Compile with -D_REENTRANT flag
#endif

#include <arpa/inet.h>
#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#ifndef __sun__
#include <getopt.h>
#endif
#include <grp.h>
#include <libmilter/mfapi.h>
#include <netinet/in.h>
#include <pthread.h>
#include <pwd.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <syslog.h>
#include <time.h>
#include <unistd.h>
#include <assert.h>
#include <spf2/spf.h>

/* TODO: use compilation-time defines to set these */
#define CONFIG_FILE		"/etc/mail/smfs/smf-spf.conf"
#define WORK_SPACE		"/var/run/smfs"
#define OCONN			"unix:" WORK_SPACE "/smf-spf.sock"
#define USER			"smfs"
#define TAG_STRING		"[SPF:fail]"
#define QUARANTINE_BOX		"postmaster"
#define SYSLOG_FACILITY		LOG_MAIL
#define SPF_TTL			3600
#define DELAY_CHECKS		0
#define REFUSE_FAIL		1
#define REJECT_TEMPERROR	1
#define REJECT_PERMERROR	0
#define TAG_SUBJECT		1
#define RECEIVED_HDRFMT         0xFF
#define ADD_SIGNATURE           1
#define ADD_AUTHRESULT          0
#define WRAP_HEADER             1
#define HEADER_WIDTH            78
#define QUARANTINE		0

#define MAXLINE			128
#define HASH_POWER		16
#define FACILITIES_AMOUNT	10
#define NOJOBID                 "(unknown jobid)"

#define SMF_SPF_HDRFMT_RESULT   0x01
#define SMF_SPF_HDRFMT_TXT      0x02
#define SMF_SPF_HDRFMT_RECEIVER 0x04
#define SMF_SPF_HDRFMT_CLIENTIP 0x08
#define SMF_SPF_HDRFMT_ENVFROM  0x10
#define SMF_SPF_HDRFMT_HELO     0x20

#define SMF_SPF_AUTHFMT_RESULT  0x01
#define SMF_SPF_AUTHFMT_VERBOSE 0x02

#define SAFE_FREE(x)		if (x) { free(x); x = NULL; }

#define hash_size(x)		((unsigned long) 1 << x)
#define hash_mask(x)		(hash_size(x) - 1)

#ifdef __sun__
int daemon(int nochdir, int noclose) {
    pid_t pid;
    int fd = 0;

    if ((pid = fork()) < 0) {
	fprintf(stderr, "fork: %s\n", strerror(errno));
	return 1;
    }
    else
	if (pid > 0) _exit(0);
    if ((pid = setsid()) == -1) {
	fprintf(stderr, "setsid: %s\n", strerror(errno));
	return 1;
    }
    if ((pid = fork()) < 0) {
	fprintf(stderr, "fork: %s\n", strerror(errno));
	return 1;
    }
    else
	if (pid > 0) _exit(0);
    if (!nochdir && chdir("/")) {
	fprintf(stderr, "chdir: %s\n", strerror(errno));
	return 1;
    }
    if (!noclose) {
	dup2(fd, fileno(stdout));
	dup2(fd, fileno(stderr));
	dup2(open("/dev/null", O_RDONLY, 0), fileno(stdin));
    }
    return 0;
}
#endif

typedef struct cache_data {
    SPF_result_t status;
    SPF_errcode_t errcode;
} cache_data;

typedef struct cache_item {
    char *item;
    unsigned long hash;
    cache_data data;
    time_t exptime;
    struct cache_item *next;
} cache_item;

typedef struct CIDR {
    unsigned char ip[16];
    unsigned short int mask;
    sa_family_t addr_family;
    struct CIDR *next;
} CIDR;

typedef struct STR {
    char *str;
    struct STR *next;
} STR;

typedef struct config {
    char *tag;
    char *quarantine_box;
    char *run_as_user;
    char *sendmail_socket;
    CIDR *cidrs;
    STR *ptrs;
    STR *froms;
    STR *tos;
    int delay_checks;
    int refuse_fail;
    int reject_temperror;
    int reject_permerror;
    int tag_subject;
    int received_header_format;
    int add_signature_header;
    int add_authresult_header;
    int wrap_header;
    int header_width;
    int quarantine;
    int syslog_facility;
    unsigned long spf_ttl;
} config;

typedef struct facilities {
    char *name;
    int facility;
} facilities;

struct context {
    char addr[64];
    sa_family_t addr_family;
    char fqdn[MAXLINE];
    char site[MAXLINE];
    char helo[MAXLINE];
    char from[MAXLINE];
    char sender[MAXLINE];
    int check_done;
    int is_bounce;
    int bounce_rcpt_ok;
    int nrcpt;
    char *subject;
    STR *rcpts;
    SPF_result_t status;
    SPF_errcode_t errcode;
};

/* The thread-safe SPF server, allocated in main() */
static SPF_server_t *spf_server = NULL;

static cache_item **cache = NULL;
static const char *config_file = CONFIG_FILE;
static config conf;
static pthread_mutex_t cache_mutex;
static facilities syslog_facilities[] = {
    { "daemon", LOG_DAEMON },
    { "mail", LOG_MAIL },
    { "local0", LOG_LOCAL0 },
    { "local1", LOG_LOCAL1 },
    { "local2", LOG_LOCAL2 },
    { "local3", LOG_LOCAL3 },
    { "local4", LOG_LOCAL4 },
    { "local5", LOG_LOCAL5 },
    { "local6", LOG_LOCAL6 },
    { "local7", LOG_LOCAL7 }
};

static sfsistat smf_connect(SMFICTX *, char *, _SOCK_ADDR *);
static sfsistat smf_helo(SMFICTX *, char *);
static sfsistat smf_envfrom(SMFICTX *, char **);
static sfsistat smf_envrcpt(SMFICTX *, char **);
static sfsistat smf_data(SMFICTX *);
static sfsistat smf_header(SMFICTX *, char *, char *);
static sfsistat smf_eom(SMFICTX *);
static sfsistat smf_abort(SMFICTX *);
static sfsistat smf_close(SMFICTX *);

static void strscpy(register char *dst, register const char *src, size_t size) {
    register size_t i;

    for (i = 0; i < size && (dst[i] = src[i]) != 0; i++) continue;
    dst[i] = '\0';
}

static void strtolower(register char *str) {

    for (; *str; str++)
	if (isascii(*str) && isupper(*str)) *str = tolower(*str);
}

static int check_yesno(const char *key, const char *val) {
    if (val[0] == 'y' || val[0] == 'Y' || val[0] == 't' || val[0] == 'T' || !strcasecmp(val, "on"))
        return 1;
    if (val[0] == 'n' || val[0] == 'N' || val[0] == 'f' || val[0] == 'F' || !strncasecmp(val, "off", 2))
        return 0;
    fprintf(stderr, "Warning: unrecognized configuration value: key=%s, val=%s. Assuming \"off\"\n", key, val);
    return 0;
}

static unsigned long translate(char *value) {
    unsigned long unit;
    size_t len = strlen(value);

    switch (value[len - 1]) {
	case 'm':
	case 'M':
	    unit = 60;
	    value[len - 1] = '\0';
	    break;
	case 'h':
	case 'H':
	    unit = 3600;
	    value[len - 1] = '\0';
	    break;
	case 'd':
	case 'D':
	    unit = 86400;
	    value[len - 1] = '\0';
	    break;
	default:
	    return atol(value);
    }
    return (atol(value) * unit);
}

static unsigned long hash_code(register const char *key) {
    register unsigned long hash = 0;
    register size_t i, len = strlen(key);

    for (i = 0; i < len; i++) {
	hash += key[i];
	hash += (hash << 10);
	hash ^= (hash >> 6);
    }
    hash += (hash << 3);
    hash ^= (hash >> 11);
    hash += (hash << 15);
    return hash;
}

static int cache_init(void) {

    if (!(cache = calloc(1, hash_size(HASH_POWER) * sizeof(void *)))) return 0;
    return 1;
}

static void cache_destroy(void) {
    unsigned long i, size = hash_size(HASH_POWER);
    cache_item *it, *it_next;

    for (i = 0; i < size; i++) {
	it = cache[i];
	while (it) {
	    it_next = it->next;
	    SAFE_FREE(it->item);
	    SAFE_FREE(it);
	    it = it_next;
	}
    }
    SAFE_FREE(cache);
}

static struct cache_data *cache_get(const char *key) {
    unsigned long hash = hash_code(key);
    cache_item *it = cache[hash & hash_mask(HASH_POWER)];
    time_t curtime = time(NULL);

    while (it) {
	if (it->hash == hash && it->exptime > curtime && it->item && !strcmp(key, it->item)) return &(it->data);
	it = it->next;
    }
    return NULL;
}

static void cache_put(const char *key, unsigned long ttl, SPF_result_t status, SPF_errcode_t errcode) {
    unsigned long hash = hash_code(key);
    time_t curtime = time(NULL);
    cache_item *it, *parent = NULL;

    it = cache[hash & hash_mask(HASH_POWER)];
    while (it) {
	if (it->hash == hash && it->exptime > curtime && it->item && !strcmp(key, it->item)) return;
	it = it->next;
    }
    it = cache[hash & hash_mask(HASH_POWER)];
    while (it) {
	if (it->exptime < curtime) {
	    SAFE_FREE(it->item);
	    it->item = strdup(key);
	    it->hash = hash;
	    it->data.status = status;
	    it->data.errcode = errcode;
	    it->exptime = curtime + ttl;
	    return;
	}
	parent = it;
	it = it->next;
    }
    if ((it = (cache_item *) calloc(1, sizeof(cache_item)))) {
	it->item = strdup(key);
	it->hash = hash;
	it->data.status = status;
	it->data.errcode = errcode;
	it->exptime = curtime + ttl;
	if (parent)
	    parent->next = it;
	else
	    cache[hash & hash_mask(HASH_POWER)] = it;
    }
}

static void free_config(void) {

    SAFE_FREE(conf.tag);
    SAFE_FREE(conf.quarantine_box);
    SAFE_FREE(conf.run_as_user);
    SAFE_FREE(conf.sendmail_socket);
    if (conf.cidrs) {
	CIDR *it = conf.cidrs, *it_next;

	while (it) {
	    it_next = it->next;
	    free(it);
	    it = it_next;
	}
    }
    if (conf.ptrs) {
	STR *it = conf.ptrs, *it_next;

	while (it) {
	    it_next = it->next;
	    SAFE_FREE(it->str);
	    free(it);
	    it = it_next;
	}
    }
    if (conf.froms) {
	STR *it = conf.froms, *it_next;

	while (it) {
	    it_next = it->next;
	    SAFE_FREE(it->str);
	    free(it);
	    it = it_next;
	}
    }
    if (conf.tos) {
	STR *it = conf.tos, *it_next;

	while (it) {
	    it_next = it->next;
	    SAFE_FREE(it->str);
	    free(it);
	    it = it_next;
	}
    }
}

static int load_config(void) {
    FILE *fp;
    char buf[2 * MAXLINE];

    conf.tag = strdup(TAG_STRING);
    conf.quarantine_box = strdup(QUARANTINE_BOX);
    conf.run_as_user = strdup(USER);
    conf.sendmail_socket = strdup(OCONN);
    conf.syslog_facility = SYSLOG_FACILITY;
    conf.delay_checks = DELAY_CHECKS;
    conf.refuse_fail = REFUSE_FAIL;
    conf.reject_temperror = REJECT_TEMPERROR;
    conf.reject_permerror = REJECT_PERMERROR;
    conf.tag_subject = TAG_SUBJECT;
    conf.received_header_format = RECEIVED_HDRFMT;
    conf.add_signature_header = ADD_SIGNATURE;
    conf.add_authresult_header = ADD_AUTHRESULT;
    conf.wrap_header = WRAP_HEADER;
    conf.header_width = HEADER_WIDTH;
    conf.quarantine = QUARANTINE;
    conf.spf_ttl = SPF_TTL;
    if (!(fp = fopen(config_file, "r"))) return 0;
    while (fgets(buf, sizeof(buf) - 1, fp)) {
	char key[MAXLINE];
	char val[MAXLINE];
	char *p = NULL;

	if ((p = strchr(buf, '#'))) *p = '\0';
	if (!(strlen(buf))) continue;
	if (sscanf(buf, "%127s %127s", key, val) != 2) continue;
	if (!strncasecmp(key, "whitelistip", 11)) {
	    char *slash = NULL;
	    unsigned short int mask;
	    int ipv6 = 0;
	    struct in_addr sin_addr;
	    struct in6_addr sin6_addr;

	    if (!strcmp(key+11, "6"))
	        ipv6 = 1;
	    else if (key[11] != '\0')
	        continue;

	    mask = (ipv6 == 1) ? 128 : 32;
	    if ((slash = strchr(val, '/'))) {
	        unsigned short int nbits = mask;
		*slash = '\0';
		if ((mask = atoi(++slash)) > nbits) mask = nbits;
	    }
	    if (val[0] &&
		((ipv6 == 0 && inet_pton(AF_INET,  val, &sin_addr) > 0) ||
		 (ipv6 == 1 && inet_pton(AF_INET6, val, &sin6_addr) > 0))) {

	        CIDR *it = (CIDR *) calloc(1, sizeof(CIDR));
		if (!conf.cidrs)
		  conf.cidrs = it;
		else if (it) {
		    it->next = conf.cidrs;
		    conf.cidrs = it;
		}
		if (conf.cidrs) {
		    if( ipv6 == 0 ) {
		        memcpy(conf.cidrs->ip, &sin_addr.s_addr, 4);
			conf.cidrs->addr_family = AF_INET;
		    } else {
		        memcpy(conf.cidrs->ip, sin6_addr.s6_addr, 16);
			conf.cidrs->addr_family = AF_INET6;
		    }
		    conf.cidrs->mask = mask;
		}
	    }
	    continue;
	}
	if (!strcasecmp(key, "whitelistptr")) {
	    STR *it = NULL;

	    if (!conf.ptrs)
		conf.ptrs = (STR *) calloc(1, sizeof(STR));
	    else
		if ((it = (STR *) calloc(1, sizeof(STR)))) {
		    it->next = conf.ptrs;
		    conf.ptrs = it;
		}
	    if (conf.ptrs && !conf.ptrs->str) conf.ptrs->str = strdup(val);
	    continue;
	}
	if (!strcasecmp(key, "whitelistfrom")) {
	    STR *it = NULL;

	    if (!conf.froms)
		conf.froms = (STR *) calloc(1, sizeof(STR));
	    else
		if ((it = (STR *) calloc(1, sizeof(STR)))) {
		    it->next = conf.froms;
		    conf.froms = it;
		}
	    if (conf.froms && !conf.froms->str) {
		strtolower(val);
		conf.froms->str = strdup(val);
	    }
	    continue;
	}
	if (!strcasecmp(key, "whitelistto")) {
	    STR *it = NULL;

	    if (!conf.tos)
		conf.tos = (STR *) calloc(1, sizeof(STR));
	    else
		if ((it = (STR *) calloc(1, sizeof(STR)))) {
		    it->next = conf.tos;
		    conf.tos = it;
		}
	    if (conf.tos && !conf.tos->str) {
		strtolower(val);
		conf.tos->str = strdup(val);
	    }
	    continue;
	}
	if (!strcasecmp(key, "delaychecks")) {
	    conf.delay_checks = check_yesno(key, val);
	    continue;
	}
	if (!strcasecmp(key, "refusefail")) {
	    conf.refuse_fail = check_yesno(key, val);
	    continue;
	}
	if (!strcasecmp(key, "rejecttemperror")) {
	    conf.reject_temperror = check_yesno(key, val);
	    continue;
	}
	if (!strcasecmp(key, "rejectpermerror")) {
	    conf.reject_permerror = check_yesno(key, val);
	    continue;
	}
	if (!strcasecmp(key, "tagsubject")) {
	    conf.tag_subject = check_yesno(key, val);
	    continue;
	}
	if (!strcasecmp(key, "tag")) {
	    SAFE_FREE(conf.tag);
	    conf.tag = strdup(val);
	    continue;
	}
	if (!strcasecmp(key, "addheader")) {
	    char *tok, *str;
	    conf.received_header_format = 0;
	    for (str = val; ; str=NULL ) {
	        tok = strtok(str, ",");
		if (tok == NULL) break;
		while (*tok && isspace(*tok)) tok++;
		if (*tok == '\0') continue;
		if (!strncasecmp(tok, "off", 2) ||
		    !strncasecmp(tok, "false", 1) ||
		    !strncasecmp(tok, "no", 1)) {
		    conf.received_header_format = 0;
		    break;
		} else if (!strcasecmp(tok, "on") ||
			   !strncasecmp(tok, "true", 1) ||
			   !strncasecmp(tok, "yes", 1)) {
		    conf.received_header_format = RECEIVED_HDRFMT;
		    break;
		} else if (!strncasecmp(tok, "result", 3)) {
		     conf.received_header_format |= SMF_SPF_HDRFMT_RESULT;
		} else if (!strncasecmp(tok, "description", 1) ||
			   !strncasecmp(tok, "verbose", 1)) {
		    conf.received_header_format |= SMF_SPF_HDRFMT_TXT;
		} else if (!strncasecmp(tok, "receiver", 3)) {
		    conf.received_header_format |= SMF_SPF_HDRFMT_RECEIVER;
		} else if (!strncasecmp(tok, "clientip", 1) ||
			   !strncasecmp(tok, "ip", 1)) {
		    conf.received_header_format |= SMF_SPF_HDRFMT_CLIENTIP;
		} else if (!strncasecmp(tok, "envfrom", 1)) {
		    conf.received_header_format |= SMF_SPF_HDRFMT_ENVFROM;
		} else if (!strncasecmp(tok, "helo", 1)) {
		    conf.received_header_format |= SMF_SPF_HDRFMT_HELO;
		} else {
		    fprintf(stderr, "Warning: unknown configuration token, key=%s, val=%s, tok=%s\n", key, val, tok);
		}
	    }
	    if (conf.received_header_format)
		conf.received_header_format |= SMF_SPF_HDRFMT_RESULT;
	    continue;
	}
	if (!strcasecmp(key, "addauthresultheader")) {
	    conf.add_authresult_header = 0;
	    if (!strncasecmp(val, "off", 2) ||
		!strncasecmp(val, "false", 1) ||
		!strncasecmp(val, "no", 1)) {
		conf.add_authresult_header = 0;
	    } else if (!strcasecmp(val, "on") ||
		       !strncasecmp(val, "true", 1) ||
		       !strncasecmp(val, "yes", 1)) {
		conf.add_authresult_header = SMF_SPF_AUTHFMT_RESULT;
	    } else if (!strncasecmp(val, "verbose", 1)) {
		conf.add_authresult_header = SMF_SPF_AUTHFMT_VERBOSE;
	    } else {
		fprintf(stderr, "Warning: unknown configuration value, key=%s, val=%s\n", key, val);
	    }
	    continue;
	}
	if (!strcasecmp(key, "addsignatureheader")) {
	    conf.add_signature_header = check_yesno(key, val);
	    continue;
	}
	if (!strcasecmp(key, "wrapheader")) {
	    conf.wrap_header = check_yesno(key, val);
	    continue;
	}
	if (!strcasecmp(key, "headerwidth")) {
	    conf.header_width = atoi(val);
	    if (conf.header_width > 998 || conf.header_width < 64) {
		conf.header_width = HEADER_WIDTH;
	    }
	    continue;
	}
	if (!strcasecmp(key, "quarantine")) {
	    conf.quarantine = check_yesno(key, val);
	    continue;
	}
	if (!strcasecmp(key, "quarantinebox")) {
	    SAFE_FREE(conf.quarantine_box);
	    conf.quarantine_box = strdup(val);
	    continue;
	}
	if (!strcasecmp(key, "ttl")) {
	    conf.spf_ttl = translate(val);
	    continue;
	}
	if (!strcasecmp(key, "user")) {
	    SAFE_FREE(conf.run_as_user);
	    conf.run_as_user = strdup(val);
	    continue;
	}
	if (!strcasecmp(key, "socket")) {
	    SAFE_FREE(conf.sendmail_socket);
	    conf.sendmail_socket = strdup(val);
	    continue;
	}
	if (!strcasecmp(key, "syslog")) {
	    int i;

	    for (i = 0; i < FACILITIES_AMOUNT; i++)
		if (!strcasecmp(val, syslog_facilities[i].name))
		    conf.syslog_facility = syslog_facilities[i].facility;
	    continue;
	}
    }
    fclose(fp);
    return 1;
}

/*
 * int
 * bitncmp(l, r, n)
 *      compare bit masks l and r, for n bits.
 * return:
 *      -1, 1, or 0 in the libc tradition.
 * note:
 *      network byte order assumed.  this means 192.5.5.240/28 has
 *      0x11110000 in its fourth octet.
 * author:
 *      Paul Vixie (ISC), June 1996
 */
static int bitncmp(const void *l, const void *r, int n)
{
  unsigned int lb, rb;
  int x, b;
 
  b = n / 8;
  x = memcmp(l, r, b);
  if (x)
    return x;

  lb = ((const unsigned char *)l)[b];
  rb = ((const unsigned char *)r)[b];
  for (b = n % 8; b > 0; b--) {
    if ((lb & 0x80) != (rb & 0x80)) {
      if (lb & 0x80)
	return 1;
      return -1;
    }
    lb <<= 1;
    rb <<= 1;
  }
  return 0;
}

static int ip_check(const unsigned char *checkaddr, sa_family_t addr_family) {
    CIDR *it = conf.cidrs;

    while (it) {
      if (it->addr_family == addr_family &&
	  bitncmp(it->ip, checkaddr, it->mask) == 0) return 1;
	it = it->next;
    }
    return 0;
}

static int ptr_check(const char *ptr) {
    STR *it = conf.ptrs;

    while (it) {
	if (it->str && strlen(it->str) <= strlen(ptr) && !strcasecmp(ptr + strlen(ptr) - strlen(it->str), it->str)) return 1;
	it = it->next;
    }
    return 0;
}

static int from_check(const char *from) {
    STR *it = conf.froms;

    while (it) {
	if (it->str && strstr(from, it->str)) return 1;
	it = it->next;
    }
    return 0;
}

static int to_check(const char *to) {
    STR *it = conf.tos;

    while (it) {
	if (it->str && strstr(to, it->str)) return 1;
	it = it->next;
    }
    return 0;
}

static void die(const char *reason) {

    syslog(LOG_ERR, "[ERROR] die: %s", reason);
    smfi_stop();
    sleep(60);
    abort();
}

static void mutex_lock(pthread_mutex_t *mutex) {

    if (pthread_mutex_lock(mutex)) die("pthread_mutex_lock");
}

static void mutex_unlock(pthread_mutex_t *mutex) {

    if (pthread_mutex_unlock(mutex)) die("pthread_mutex_unlock");
}

static int address_preparation(register char *dst, register const char *src) {
    register const char *start = NULL, *stop = NULL;
    int tail;

    if (!(start = strchr(src, '<'))) return 0;
    if (!(stop = strrchr(src, '>'))) return 0;
    if (++start >= --stop) return 0;
    strscpy(dst, start, stop - start + 1);
    tail = strlen(dst) - 1;
    if ((dst[0] >= 0x07 && dst[0] <= 0x0d) || dst[0] == 0x20) return 0;
    if ((dst[tail] >= 0x07 && dst[tail] <= 0x0d) || dst[tail] == 0x20) return 0;
    if (!strchr(dst, '@')) return 0;
    return 1;
}

static void add_rcpt(struct context *context, const char* rcpt) {
    STR *it = NULL;

    if (!context->rcpts)
	context->rcpts = (STR *) calloc(1, sizeof(STR));
    else
	if ((it = (STR *) calloc(1, sizeof(STR)))) {
	    it->next = context->rcpts;
	    context->rcpts = it;
	}
    if (context->rcpts && !context->rcpts->str) context->rcpts->str = strdup(rcpt);
}

static void wrap_header(char* header, size_t len, size_t indent, size_t width) {
    const size_t tab = 8;
    size_t nchars, pos;
    char *buf, *p, *q, *start;
    int buflen, spc, newchars, startline;

    if (!header || indent>=width || width<2*tab)
        return;

    nchars = strlen(header);
    if ((nchars+indent) < width )
        return;

    buflen = nchars+1+2*(nchars/(width-tab)+1);
    if (buflen>len)
        return;
    buf = (char*)malloc(buflen);
    if (!buf)
        return;

    start = p = header;
    q = buf;
    pos = indent+1;
    newchars = spc = 0;
    startline = 1;
    while (*p) {
        if (*p == ' ') {
	    if (newchars) {
	        strncpy(q, start, p-start);
		q += p-start;
		newchars = 0;
		if (spc) {
		    pos++;
		}
	    }
	    if (!startline) {
	        start = p;
		spc = 1;
	    }
	} else {
	    if (startline) {
	        start = p;
		startline = 0;
	    }
	    newchars = 1;
	    pos++;
	}
	p++;
	if (pos>width) {
	    pos = tab+1;
	    if (spc) {
	        strcpy(q, "\n\t");
		q += 2;
		start++;
		startline = 1;
	    }
	    if (newchars) {
	        strncpy(q, start, p-start);
		q += p-start;
		startline = 0;
		newchars = 0;
		if (spc) {
		    pos += p-start;
		}
	    }
	    if (!spc) {
	        strcpy(q, "\n\t ");
		q += 3;
		startline = 2;
		pos++;
	    }
	    start = p;
	    spc = 0;
	}
    }
    if (newchars) {
        strncpy(q, start, p-start);
	q += p-start;
    } else if (startline && q != buf) {
        q -= 2;
	if (startline == 2) q--;
    }
    *q = '\0';
    strcpy(header, buf);
    free(buf);
}

static int safe_ret(size_t size, int nchars) {
    if( nchars >= (int)size || nchars < 0 ) {
        nchars = 0;
    }
    return nchars;
}

static SPF_result_t fixup_libspf2_result(SPF_result_t status, SPF_errcode_t errcode)
{
    /* Buggy libspf2 often does not assign a result code in case of an error */
    if (status == SPF_RESULT_INVALID) {
	switch (errcode) {
	case SPF_E_NOT_SPF:
	    status = SPF_RESULT_NONE;
	    break;
	case SPF_E_NO_MEMORY:
	case SPF_E_DNS_ERROR:  /* This combination may also be be a PERMERROR :-/ */
	    status = SPF_RESULT_TEMPERROR;
	    break;
	/* These two deserve an "invalid" result code */
	case SPF_E_INTERNAL_ERROR:
	case SPF_E_UNINIT_VAR:
	    break;
	default:
	    status = SPF_RESULT_PERMERROR;
	    break;
	}
    }
    return status;
}

static int write_spf_txt(char *spf_txt, size_t LEN, const struct context *context) {
    int nchars = 0;

    switch (context->status) {
    case SPF_RESULT_PASS:
        nchars = safe_ret(LEN, snprintf(spf_txt, LEN, " (%s: domain of %s designates %s as permitted sender)",
					context->site, context->sender, context->addr));
	break;
    case SPF_RESULT_FAIL:
        nchars = safe_ret(LEN, snprintf(spf_txt, LEN, " (%s: domain of %s does not designate %s as permitted sender)",
					context->site, context->sender, context->addr));
	break;
    case SPF_RESULT_SOFTFAIL:
        nchars = safe_ret(LEN, snprintf(spf_txt, LEN, " (%s: transitioning domain of %s does not designate %s as "
					"permitted sender)", context->site, context->sender, context->addr));
	break;
    case SPF_RESULT_NEUTRAL:
        nchars = safe_ret(LEN, snprintf(spf_txt, LEN, " (%s: sender %s is neither permitted nor denied by domain of %s)",
					context->site, context->addr, context->sender));
	break;
    case SPF_RESULT_NONE:
	nchars = safe_ret(LEN, snprintf(spf_txt, LEN, " (%s: domain of %s does not designate permitted sender hosts)",
					context->site, context->sender));
	break;
    case SPF_RESULT_TEMPERROR:
	nchars = safe_ret(LEN, snprintf(spf_txt, LEN, " (%s: error in processing during lookup of %s: %s)",
					context->site, context->sender, SPF_strerror(context->errcode)));
    case SPF_RESULT_PERMERROR:
	nchars = safe_ret(LEN, snprintf(spf_txt, LEN, " (%s: unrecoverable error during lookup of %s: %s)",
					context->site, context->sender, SPF_strerror(context->errcode)));
    default:
        break;
    }
    return nchars;
}

static void insert_headers(SMFICTX *ctx, const struct context *context) {
    const size_t LEN = 974;
    size_t pos = 0;
    const char *spf_result = SPF_strresult(context->status);
    char *spf_hdr = (char *)malloc(LEN);

    if (!spf_hdr) {
        return;
    }

    if (conf.received_header_format) {
        *spf_hdr = 0;
	pos = safe_ret(LEN, snprintf(spf_hdr, LEN, "%s", spf_result));
        if (conf.received_header_format & SMF_SPF_HDRFMT_TXT) {
	    pos += write_spf_txt(spf_hdr+pos, LEN-pos, context);
	}
        if (conf.received_header_format & SMF_SPF_HDRFMT_RECEIVER) {
	    pos += safe_ret(LEN, snprintf(spf_hdr+pos, LEN-pos, " receiver=%s;", context->site));
	}
        if (conf.received_header_format & SMF_SPF_HDRFMT_CLIENTIP) {
	    pos += safe_ret(LEN, snprintf(spf_hdr+pos, LEN-pos, " client-ip=%s;", context->addr));
	}
        if (conf.received_header_format & SMF_SPF_HDRFMT_ENVFROM) {
	    /* As per erratum of the SPF RFC, the envelope-from is to be a quoted string */
	    size_t len = strlen(context->from);
	    char *quoted_from = (char*)malloc(len+3);
	    if (quoted_from) {
		const char *p = context->from;
		if (len>0 && p[len-1] == '>') {
		    len--;
		}
		if (*p == '<') {
		    p++;
		    len--;
		}
		*quoted_from = '"';
		strncpy(quoted_from+1, p, len);
		strcpy(quoted_from+len+1, "\"");
		pos += safe_ret(LEN, snprintf(spf_hdr+pos, LEN-pos, " envelope-from=%s;", quoted_from));
		free(quoted_from);
	    }
	}
        if (conf.received_header_format & SMF_SPF_HDRFMT_HELO) {
	    pos += safe_ret(LEN, snprintf(spf_hdr+pos, LEN-pos, " helo=%s;", context->helo));
	}
	if (conf.wrap_header) {
	    wrap_header(spf_hdr, LEN, 14, conf.header_width);
	}
	smfi_insheader(ctx, 1, "Received-SPF", spf_hdr);
    }

    if (conf.add_authresult_header) {
	const char *spf_authresult = spf_result;

	/* Conform to RFC 5451 */
	if (!strcmp(spf_authresult, "fail")) {
	    spf_authresult = "hardfail";
	}
        *spf_hdr = 0;
        pos = safe_ret(LEN, snprintf(spf_hdr, LEN, "%s; spf=%s", context->site, spf_authresult));
	if (conf.add_authresult_header & SMF_SPF_AUTHFMT_VERBOSE) {
	    pos += write_spf_txt(spf_hdr+pos, LEN-pos, context);
	}
	snprintf(spf_hdr+pos, LEN-pos, " smtp.mailfrom=%s", context->sender);
	if (conf.wrap_header) {
	    wrap_header(spf_hdr, LEN, 24, conf.header_width);
	}
	smfi_insheader(ctx, 1, "Authentication-Results", spf_hdr);
    }

    if (conf.add_signature_header) {
        smfi_insheader(ctx, 1, "X-SPF-Scan-By", "smf-spf v2.1.0 - http://smfs.sf.net/");
    }

    free(spf_hdr);
}

static void free_msgdata(struct context *context) {
    if (!context) return;
    context->check_done = 0;
    context->is_bounce = 0;
    context->bounce_rcpt_ok = 0;
    context->nrcpt = 0;
    if (context->rcpts) {
	STR *it = context->rcpts, *it_next;
	while (it) {
	    it_next = it->next;
	    SAFE_FREE(it->str);
	    free(it);
	    it = it_next;
	}
	context->rcpts = NULL;
    }
    SAFE_FREE(context->subject);
}

static sfsistat check_spf(SMFICTX *ctx, struct context *context) {
    SPF_request_t *spf_request = NULL;
    SPF_response_t *spf_response = NULL;
    SPF_result_t status = SPF_RESULT_NONE;
    SPF_errcode_t errcode = SPF_E_SUCCESS;
    char *key = NULL;
    const cache_data *data = NULL;
    const char *cache_notice = "";
    const char *jobid;
    int badalloc = 1;
    int do_cache = (cache && conf.spf_ttl);

    if (do_cache) {
	size_t len = strlen(context->addr) + strlen(context->sender) + 2;
	key = (char*)malloc(len);
	if (!key) goto nomem;
	snprintf(key, len, "%s|%s", context->addr, strchr(context->sender, '@') + 1);
	mutex_lock(&cache_mutex);
	data = cache_get(key);
	mutex_unlock(&cache_mutex);
    }
    if (data) {
	status = data->status;
	errcode = data->errcode;
	cache_notice = " (cached)";
	badalloc = 0;
    } else {
	SPF_server_set_rec_dom(spf_server, context->site);
	spf_request = SPF_request_new(spf_server);
	if (!spf_request) goto nomem1;
	if (context->addr_family == AF_INET) {
	    SPF_request_set_ipv4_str(spf_request, context->addr);
	} else {
	    SPF_request_set_ipv6_str(spf_request, context->addr);
	}
	SPF_request_set_helo_dom(spf_request, context->helo);
	SPF_request_set_env_from(spf_request, context->sender);
	errcode = SPF_request_query_mailfrom(spf_request, &spf_response);
	if (!spf_response) goto nomem1;
	status = SPF_response_result(spf_response);
	status = fixup_libspf2_result(status, errcode);
	if (do_cache && status != SPF_RESULT_INVALID && status != SPF_RESULT_TEMPERROR) {
	    mutex_lock(&cache_mutex);
	    cache_put(key, conf.spf_ttl, status, errcode);
	    mutex_unlock(&cache_mutex);
	}
	badalloc = 0;
	SPF_response_free(spf_response);
    nomem1:
	if (spf_request) SPF_request_free(spf_request);
    }
nomem:
    if (badalloc) {
	status = SPF_RESULT_TEMPERROR;
	errcode = SPF_E_NO_MEMORY;
    }
    jobid = smfi_getsymval(ctx, "i");
    if (jobid == NULL) {
	jobid = NOJOBID;
    }
    if (status == SPF_RESULT_INVALID || status == SPF_RESULT_PERMERROR || status == SPF_RESULT_TEMPERROR) {
	syslog(LOG_NOTICE, "%s: SPF %s (%s)%s: %s, %s, %s, %s", jobid, SPF_strresult(status),
	       SPF_strerror(errcode), cache_notice, context->addr, context->fqdn, context->helo, context->from);
    } else {
	syslog(LOG_NOTICE, "%s: SPF %s%s: %s, %s, %s, %s", jobid, SPF_strresult(status), cache_notice,
	       context->addr, context->fqdn, context->helo, context->from);
    }
    context->status = status;
    context->errcode = errcode;
    context->check_done = 1;
    if (status == SPF_RESULT_FAIL && conf.refuse_fail) {
	char reject[2 * MAXLINE];
	snprintf(reject, sizeof(reject), "Rejected. See http://www.openspf.org/why.html?sender=%s&ip=%s&receiver=%s",
		 context->sender, context->addr, context->site);
	smfi_setreply(ctx, "550", "5.7.1", reject);
	return SMFIS_REJECT;
    }
    if (status == SPF_RESULT_TEMPERROR && conf.reject_temperror) {
	smfi_setreply(ctx, "451", "4.4.3", "Please try again later");
	return SMFIS_TEMPFAIL;
    }
    if (status == SPF_RESULT_PERMERROR && conf.reject_permerror) {
	char reject[2 * MAXLINE];
	snprintf(reject, sizeof(reject), "Bad sender SPF record: %s", SPF_strerror(context->errcode));
	smfi_setreply(ctx, "550", "5.5.2", reject);
	return SMFIS_REJECT;
    }
    return SMFIS_CONTINUE;
}



static sfsistat smf_connect(SMFICTX *ctx, char *name, _SOCK_ADDR *sa) {
    struct context *context = NULL;
    char host[64];
    sa_family_t addr_family;
    unsigned char in_addr[16];

    if (sa == NULL) {
      syslog(LOG_INFO, "Connect from sdin, filter skipped" );
      return SMFIS_ACCEPT;
    }
    strscpy(host, "undefined", sizeof(host) - 1);
    addr_family = sa->sa_family;
    switch (addr_family) {
	case AF_INET: {
	    struct sockaddr_in *sin = (struct sockaddr_in *)sa;

	    memcpy(in_addr, &sin->sin_addr.s_addr, 4);
	    inet_ntop(AF_INET, in_addr, host, sizeof(host));
	    break;
	}
        case AF_INET6: {
	    struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *)sa;

	    memcpy(in_addr, sin6->sin6_addr.s6_addr, 16);
	    inet_ntop(AF_INET6, in_addr, host, sizeof(host));
	    break;
	}
        default:
            syslog(LOG_INFO, "Unknown connection type, filter skipped" );
            return SMFIS_ACCEPT;
    }
    if (conf.cidrs && ip_check(in_addr, addr_family)) return SMFIS_ACCEPT;
    if (conf.ptrs && ptr_check(name)) return SMFIS_ACCEPT;
    if (!(context = calloc(1, sizeof(*context)))) {
	syslog(LOG_ERR, "[ERROR] %s", strerror(errno));
	return SMFIS_TEMPFAIL;
    }
    smfi_setpriv(ctx, context);
    strscpy(context->addr, host, sizeof(context->addr) - 1);
    strscpy(context->fqdn, name, sizeof(context->fqdn) - 1);
    strscpy(context->helo, "undefined", sizeof(context->helo) - 1);
    context->addr_family = addr_family;
    context->status = SPF_RESULT_NONE;
    context->errcode = SPF_E_SUCCESS;

    return SMFIS_CONTINUE;
}

static sfsistat smf_helo(SMFICTX *ctx, char *arg) {
    struct context *context = (struct context *)smfi_getpriv(ctx);

    strscpy(context->helo, arg, sizeof(context->helo) - 1);
    return SMFIS_CONTINUE;
}

static sfsistat smf_envfrom(SMFICTX *ctx, char **args) {
    struct context *context = (struct context *)smfi_getpriv(ctx);
    const char *verify = smfi_getsymval(ctx, "{verify}");
    const char *site = NULL;

    if (smfi_getsymval(ctx, "{auth_authen}")) return SMFIS_ACCEPT;
    if (verify && strcmp(verify, "OK") == 0) return SMFIS_ACCEPT;
    if (*args) strscpy(context->from, *args, sizeof(context->from) - 1);
    /* If this is a bounce (null sender), check the HELO domain (at DATA) */
    if (strstr(context->from, "<>")) {
	context->is_bounce = 1;
	strtolower(context->helo);
	snprintf(context->sender, sizeof(context->sender), "postmaster@%s", context->helo);
    } else {
	if (!address_preparation(context->sender, context->from)) {
	    smfi_setreply(ctx, "550", "5.1.7", "Sender address does not conform to RFC-2821 syntax");
	    return SMFIS_REJECT;
	}
	strtolower(context->sender);
	if (conf.froms && from_check(context->sender)) {
	    return SMFIS_ACCEPT;
	}
    }
    site = smfi_getsymval(ctx, "j");
    strscpy(context->site, ((site != NULL) ? site : "localhost"), sizeof(context->site) - 1);

    if (conf.delay_checks || conf.tos || context->is_bounce) {
	return SMFIS_CONTINUE;
    }
    return check_spf(ctx, context);
}

static sfsistat smf_envrcpt(SMFICTX *ctx, char **args) {
    struct context *context = (struct context *)smfi_getpriv(ctx);
    const char *rcpt = *args;
    char *recipient;
    size_t len;
    int match = 0;

    if (!rcpt || (len = strlen(rcpt)) == 0) {
	syslog(LOG_ERR, "[ERROR] NULL recipient?" );
	smfi_setreply(ctx, "550", "5.1.3", "Bad recipient address");
	return SMFIS_REJECT;
    }
    context->nrcpt++;
    recipient = (char*)malloc(len+1);
    if (!recipient) {
	syslog(LOG_ERR, "[ERROR] %s", strerror(errno));
	return SMFIS_TEMPFAIL;
    }
    if (!address_preparation(recipient, rcpt)) {
	smfi_setreply(ctx, "550", "5.1.3", "Recipient address does not conform to RFC-2821 syntax");
	free(recipient);
	return SMFIS_REJECT;
    }
    if (context->is_bounce && context->nrcpt > 1) {
	smfi_setreply(ctx, "550", "5.5.3", "Recipient address rejected: Multi-recipient bounce");
	free(recipient);
	return SMFIS_REJECT;
    }
    if (conf.tos) {
	strtolower(recipient);
	match = to_check(recipient);
	if (match && context->is_bounce) {
	    context->bounce_rcpt_ok = 1;
	}
    }
    free(recipient);
    if (match || context->is_bounce) {
	/* Must CONTINUE here to see other RCPTs */
	return SMFIS_CONTINUE;
    }
    if (!context->check_done) {
	sfsistat ret;

	if ((ret = check_spf(ctx, context)) != SMFIS_CONTINUE) {
	    return ret;
	}
    }
    if (conf.quarantine && (context->status == SPF_RESULT_FAIL || context->status == SPF_RESULT_SOFTFAIL)) {
	add_rcpt(context, rcpt);
    }
    return SMFIS_CONTINUE;
}

static sfsistat smf_data(SMFICTX *ctx) {
    struct context *context = (struct context *)smfi_getpriv(ctx);

    /* FIXME: add NDEBUG to Makefile */
    assert(!(context->is_bounce && context->check_done));
    assert(!(context->bounce_rcpt_ok && !context->is_bounce));

    if (context->is_bounce) {
	if (context->bounce_rcpt_ok) return SMFIS_CONTINUE;
	/* FIXME: should indicate identity=helo somehow */
	return check_spf(ctx, context);
    }
    return SMFIS_CONTINUE;
}

static sfsistat smf_header(SMFICTX *ctx, char *name, char *value) {
    struct context *context = (struct context *)smfi_getpriv(ctx);

    if (!strcasecmp(name, "Subject") && (context->status == SPF_RESULT_FAIL || context->status == SPF_RESULT_SOFTFAIL) &&
	conf.tag_subject && !context->subject) {
	context->subject = strdup(value);
    }
    return SMFIS_CONTINUE;
}

static sfsistat smf_eom(SMFICTX *ctx) {
    struct context *context = (struct context *)smfi_getpriv(ctx);

    if (!context) return SMFIS_CONTINUE;

    if (context->check_done) {
	if ((context->status == SPF_RESULT_FAIL || context->status == SPF_RESULT_SOFTFAIL) && conf.tag_subject) {
	    char *subj = NULL;

	    if (context->subject) {
		size_t len = strlen(context->subject) + strlen(conf.tag) + 2;

		if ((subj = calloc(1, len))) snprintf(subj, len, "%s %s", conf.tag, context->subject);
	    }
	    else {
		size_t len = strlen(conf.tag) + 1;

		if ((subj = calloc(1, len))) snprintf(subj, len, "%s", conf.tag);
	    }
	    if (subj) {
		if (context->subject)
		    smfi_chgheader(ctx, "Subject", 1, subj);
		else
		     smfi_addheader(ctx, "Subject", subj);
		free(subj);
	    }
	}

	if (conf.received_header_format || conf.add_authresult_header) {
	    insert_headers(ctx, context);
	}

	if (context->rcpts) {
	    STR *it = context->rcpts;

	    while (it) {
		if (it->str) {
		    smfi_delrcpt(ctx, it->str);
		    smfi_addheader(ctx, "X-SPF-Original-To", it->str);
		}
		it = it->next;
	    }
	    smfi_addrcpt(ctx, conf.quarantine_box);
	}
    }
    free_msgdata(context);
    return SMFIS_CONTINUE;
}

static sfsistat smf_abort(SMFICTX *ctx) {
    struct context *context = (struct context *)smfi_getpriv(ctx);

    free_msgdata(context);
    return SMFIS_CONTINUE;
}

static sfsistat smf_close(SMFICTX *ctx) {
    struct context *context = (struct context *)smfi_getpriv(ctx);

    assert(!context || (context->rcpts == NULL && context->subject == NULL));
    SAFE_FREE(context);
    smfi_setpriv(ctx, NULL);
    return SMFIS_CONTINUE;
}

struct smfiDesc smfilter = {
    "smf-spf",
    SMFI_VERSION,
    SMFIF_ADDHDRS|SMFIF_CHGHDRS|SMFIF_ADDRCPT|SMFIF_DELRCPT,
    smf_connect,
    smf_helo,
    smf_envfrom,
    smf_envrcpt,
    smf_header,
    NULL,
    NULL,
    smf_eom,
    smf_abort,
    smf_close,
    NULL,
    smf_data,
    NULL
};

int main(int argc, char **argv) {
    const char *ofile = NULL;
    int ch, ret = 0;

    while ((ch = getopt(argc, argv, "hc:")) != -1) {
	switch (ch) {
	    case 'h':
		fprintf(stderr, "Usage: smf-spf -c <config file>\n");
		return 0;
	    case 'c':
		if (optarg) config_file = optarg;
		break;
	    default:
		break;
	}
    }
    memset(&conf, 0, sizeof(conf));
    if (!load_config()) fprintf(stderr, "Warning: smf-spf configuration file load failed\n");
    tzset();
    openlog("smf-spf", LOG_PID|LOG_NDELAY, conf.syslog_facility);
    if (!(spf_server = SPF_server_new(SPF_DNS_RESOLV, 0))) {
	syslog(LOG_ERR, "[ERROR] SPF server init failed");
	fprintf(stderr, "failed to create SPF_server\n");
	goto done;
    }
    if (!strncmp(conf.sendmail_socket, "unix:", 5))
	ofile = conf.sendmail_socket + 5;
    else
	if (!strncmp(conf.sendmail_socket, "local:", 6)) ofile = conf.sendmail_socket + 6;
    if (ofile) unlink(ofile);
    if (!getuid()) {
	struct passwd *pw;

	if ((pw = getpwnam(conf.run_as_user)) == NULL) {
	    fprintf(stderr, "%s: %s\n", conf.run_as_user, strerror(errno));
	    goto done;
	}
	setgroups(1, &pw->pw_gid);
	if (setgid(pw->pw_gid)) {
	    fprintf(stderr, "setgid: %s\n", strerror(errno));
	    goto done;
	}
	if (setuid(pw->pw_uid)) {
	    fprintf(stderr, "setuid: %s\n", strerror(errno));
	    goto done;
	}
    }
    if (smfi_setconn((char *)conf.sendmail_socket) != MI_SUCCESS) {
	fprintf(stderr, "smfi_setconn failed: %s\n", conf.sendmail_socket);
	goto done;
    }
    if (smfi_register(smfilter) != MI_SUCCESS) {
	fprintf(stderr, "smfi_register failed\n");
	goto done;
    }
    if (daemon(0, 0)) {
	fprintf(stderr, "daemonize failed: %s\n", strerror(errno));
	goto done;
    }
    if (pthread_mutex_init(&cache_mutex, 0)) {
	fprintf(stderr, "pthread_mutex_init failed\n");
	goto done;
    }
    umask(0177);
    if (conf.spf_ttl && !cache_init()) syslog(LOG_ERR, "[ERROR] cache engine init failed");
    ret = smfi_main();
    if (ret != MI_SUCCESS) syslog(LOG_ERR, "[ERROR] terminated due to a fatal error");
    if (cache) cache_destroy();
    pthread_mutex_destroy(&cache_mutex);
done:
    if (spf_server) SPF_server_free(spf_server);
    free_config();
    closelog();
    return ret;
}

