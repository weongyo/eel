/*-
 * Copyright (c) 2013 Weongyo Jeong <weongyo@gmail.com>
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
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#include "config.h"
#include <sys/epoll.h>
#include <assert.h>
#include <errno.h>
#include <pthread.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include <openssl/crypto.h>
#include <openssl/err.h>

/* vendor-specific headers */
#include "curl/curl.h"
#include "gumbo.h"
#include "uriparser/Uri.h"

#include "callout.h"
#include "eel.h"
#include "vct.h"
#include "vsb.h"

#define	EPOLLEVENT_MAX		(4 * 1024)

#define	FNV1_32_INIT		((uint32_t) 33554467UL)
#define	FNV_32_PRIME		((uint32_t) 0x01000193UL)
#define	LINK_NHASH_LOG2		9
#define	LINK_NHASH		(1 << LINK_NHASH_LOG2)
#define	LINK_HASHVAL(x, y)	fnv_32_buf((x), (y), FNV1_32_INIT)
#define	LINK_HASH(x, y)		(&linktbl[LINK_HASHVAL(x, y) & linkmask])

#define	LINK_LOCK_INIT()	AZ(pthread_mutex_init(&link_lock, NULL))
#define	LINK_LOCK()		AZ(pthread_mutex_lock(&link_lock))
#define	LINK_UNLOCK()		AZ(pthread_mutex_unlock(&link_lock))
#define	LINK_DESTROY()		AZ(pthread_mutex_destroy(&link_lock))

VTAILQ_HEAD(linkhead, link);
struct link {
	unsigned		magic;
#define	LINK_MAGIC		0xc771947b
	unsigned		flags;
#define	LINK_F_ONLINKCHAIN	(1 << 0)
#define	LINK_F_DONE		(1 << 1)
#define	LINK_F_JAVASCRIPT	(1 << 2)
#define	LINK_F_BODY		(1 << 3)
	int			refcnt;
	struct linkhead		*head;
	uint32_t		n_lookup;
	VTAILQ_ENTRY(link)	list;
	VTAILQ_ENTRY(link)	chain;
	VTAILQ_ENTRY(link)	expire_chain;
	double			t_fetched;

	char			*url;
	char			*hdr_etag;
	char			*hdr_last_modified;
	struct vsb		*body;
};

static pthread_mutex_t		link_lock;
static int			n_links;
static struct linkhead		*linktbl;
static struct linkhead		linkchain = VTAILQ_HEAD_INITIALIZER(linkchain);
static struct linkhead		expire_linkchain =
    VTAILQ_HEAD_INITIALIZER(expire_linkchain);
static u_long			linkmask;

struct worker;

struct sess {
	unsigned		magic;
#define	SESS_MAGIC		0xb733fc97
	curl_socket_t		fd;
	struct reqmulti		*reqm;
};

struct script {
	unsigned		magic;
#define	SCRIPT_MAGIC		0x2b4bf359
	unsigned		type;
#define	SCRIPT_T_REQ		1
#define	SCRIPT_T_BUFFER		2
#define	SCRIPT_T_LINK		3
	const void		*priv;
	const char		*filename;	/* only for SCRIPT_T_BUFFER */
	unsigned int		line;		/* only for SCRIPT_T_BUFFER */	
	VTAILQ_ENTRY(script)	list;
};

#define MAX_HDR		50

struct req {
	unsigned		magic;
#define	REQ_MAGIC		0x9ba52f21
	unsigned		flags;
#define	REQ_F_PARSEHEADER	(1 << 0)
	struct link		*link;
	CURL			*c;
	struct curl_slist	*slist;
	struct reqmulti		*reqm;
	VTAILQ_ENTRY(req)	list;

	/*
	 * Response-related variables.
	 */
	struct vsb		*header;
	char			*resp[MAX_HDR];
	struct vsb		*body;
	uint64_t		bodylen;
	GumboOutput		*goutput;
	const GumboOptions	*goptions;
	void			*scriptpriv;
	VTAILQ_HEAD(, script)	scripthead;

	struct req		*parent;
	int			subreqs_count;
	int			subreqs_onqueue;
	VTAILQ_HEAD(, req)	subreqs;
	VTAILQ_ENTRY(req)	subreqs_list;
};

struct reqmulti {
	unsigned		magic;
#define	REQMULTI_MAGIC		0x6be15330
	CURLM			*curlm;
	int			busy;
	int			n_reqs;
	struct worker		*wrk;
	VTAILQ_HEAD(, req)	reqhead;
	VTAILQ_ENTRY(reqmulti)	list;
};

struct worker {
	unsigned		magic;
#define	WORKER_MAGIC		0x44505226
	struct reqmulti		*reqmulti_active;
	VTAILQ_HEAD(, reqmulti)	reqmultihead;
	int			efd;
	struct callout		co_reqmulti;
	struct callout		co_reqfire;
	struct callout		co_timo;
	struct callout_block	cb;
	int			n_conns;
	void			*confpriv;
};

static struct reqmulti *
		RQM_get(struct worker *wrk);
static void	RQM_release(struct reqmulti *reqm);
static int	req_urlnorm(struct req *req, const char *value, char *urlbuf,
		    size_t urlbuflen);

/*----------------------------------------------------------------------*/

static void
JCL_fetch(struct worker *wrk, struct req *req)
{

	EJS_fetch(wrk->confpriv, (void *)req);
}

/*----------------------------------------------------------------------*/

static double
TIM_mono(void)
{
	struct timespec ts;

	assert(clock_gettime(CLOCK_MONOTONIC, &ts) == 0);
	return (ts.tv_sec + 1e-9 * ts.tv_nsec);
}

/*----------------------------------------------------------------------*/

static uint32_t
fnv_32_buf(const void *buf, size_t len, uint32_t hval)
{
	const u_int8_t *s = (const u_int8_t *)buf;

	while (len-- != 0) {
		hval *= FNV_32_PRIME;
		hval ^= *s++;
	}
	return hval;
}

static struct linkhead *
lnk_init(int elements, u_long *hashmask)
{
	long hashsize;
	struct linkhead *hashtbl;
	int i;

	assert(elements > 0);
	for (hashsize = 1; hashsize <= elements; hashsize <<= 1)
		continue;
	hashsize >>= 1;

	hashtbl = malloc((u_long)hashsize * sizeof(*hashtbl));
	assert(hashtbl != NULL);

	for (i = 0; i < hashsize; i++)
		VTAILQ_INIT(&hashtbl[i]);
	*hashmask = hashsize - 1;
	return (hashtbl);
}

static void
LNK_start(void)
{

	LINK_LOCK_INIT();
	linktbl = lnk_init(LINK_NHASH, &linkmask);
	AN(linktbl);
}

static void
LNK_remref(struct link *lk)
{

	LINK_LOCK();
	lk->refcnt--;
	assert(lk->refcnt >= 0);
	if (lk->refcnt != 0) {
		LINK_UNLOCK();
		return;
	}
	VTAILQ_REMOVE(lk->head, lk, list);
	if ((lk->flags & LINK_F_ONLINKCHAIN) != 0)
		VTAILQ_REMOVE(&linkchain, lk, chain);
	LINK_UNLOCK();
	VSB_delete(lk->body);
	free(lk->hdr_last_modified);
	free(lk->hdr_etag);
	free(lk->url);
	free(lk);
}

static struct link *
LNK_lookup(const char *url, int *created)
{
	struct link *lk;
	struct linkhead *lh;

	AN(url);
	if (created != NULL)
		*created = 0;
	LINK_LOCK();
	lh = LINK_HASH(url, strlen(url));
	VTAILQ_FOREACH(lk, lh, list) {
		if (!strcmp(lk->url, url)) {
			lk->refcnt++;
			lk->n_lookup++;
			LINK_UNLOCK();
			return (lk);
		}
	}
	AZ(lk);
	lk = calloc(sizeof(*lk), 1);
	AN(lk);
	lk->magic = LINK_MAGIC;
	/*
	 * Two reference counters; one for expire_linkchain and another for
	 * LNK_lookup().
	 */
	lk->refcnt = 2;
	lk->url = strdup(url);
	AN(lk->url);
	lk->head = lh;
	VTAILQ_INSERT_HEAD(lh, lk, list);
	VTAILQ_INSERT_TAIL(&expire_linkchain, lk, expire_chain);
	LINK_UNLOCK();
	n_links++;
	if (created != NULL)
		*created = 1;
	return (lk);
}

void
LNK_newhref(struct req *req, const char *url)
{
	struct link *lk;
	int created;
	int ret;
	char urlbuf[BUFSIZ];

	CHECK_OBJ_NOTNULL(req, REQ_MAGIC);

	ret = req_urlnorm(req, url, urlbuf, sizeof(urlbuf));
	if (ret == -1) {
		printf("Failed to normalize URL.\n");
		return;
	}
	if (strncasecmp(urlbuf, "http", 4))
		return;
	if (n_links > 100)
		return;

	lk = LNK_lookup(urlbuf, &created);
	AN(lk);
	if (created == 1) {
		printf("[INFO] NEW LINK= %s\n", urlbuf);
		LINK_LOCK();
		lk->flags |= LINK_F_ONLINKCHAIN;
		VTAILQ_INSERT_TAIL(&linkchain, lk, chain);
		LINK_UNLOCK();
	}
}

/*----------------------------------------------------------------------*/

static pthread_rwlock_t *rwlocks;

static void
lock_callback(int mode, int type, const char *file, int line)
{
	int ret;

	(void)file;
	(void)line;

	switch (mode) {
	case CRYPTO_LOCK | CRYPTO_READ:
		ret = pthread_rwlock_rdlock(&rwlocks[type]);
		AZ(ret);
		break;
	case CRYPTO_LOCK | CRYPTO_WRITE:
		ret = pthread_rwlock_wrlock(&rwlocks[type]);
		AZ(ret);
		break;
	case CRYPTO_UNLOCK | CRYPTO_READ:
	case CRYPTO_UNLOCK | CRYPTO_WRITE:
		ret = pthread_rwlock_unlock(&(rwlocks[type]));
		AZ(ret);
		break;
	default:
		assert(0 == 1);
	}
}

static unsigned long
thread_id(void)
{
	unsigned long ret;

	ret = (unsigned long)pthread_self();
	return (ret);
}

static void
init_locks(void)
{
	int i;

	rwlocks = (pthread_rwlock_t *)OPENSSL_malloc(CRYPTO_num_locks() *
	    sizeof(pthread_rwlock_t));
	AN(rwlocks);
	for (i = 0; i < CRYPTO_num_locks(); i++)
		pthread_rwlock_init(&(rwlocks[i]),NULL);
	CRYPTO_set_id_callback(thread_id);
	CRYPTO_set_locking_callback(lock_callback);
}

static void
on_timeout(void *arg)
{
	struct reqmulti *reqm = (struct reqmulti *)arg;
	struct worker *wrk;
	int running_handles;

	CHECK_OBJ_NOTNULL(reqm, REQMULTI_MAGIC);
	CAST_OBJ_NOTNULL(wrk, reqm->wrk, WORKER_MAGIC);

	curl_multi_socket_action(reqm->curlm, CURL_SOCKET_TIMEOUT, 0,
	    &running_handles);
}

static void
start_timeout(CURLM *cm, long timeout_ms, void *userp)
{
	struct reqmulti *reqm = (struct reqmulti *)userp;
	struct worker *wrk;

	(void)cm;
	CHECK_OBJ_NOTNULL(reqm, REQMULTI_MAGIC);
	CAST_OBJ_NOTNULL(wrk, reqm->wrk, WORKER_MAGIC);

	if (timeout_ms <= 0)
		timeout_ms = 1;
	callout_reset(&wrk->cb, &wrk->co_timo, CALLOUT_MSTOTICKS(timeout_ms),
	    on_timeout, reqm);
}

static void
SES_eventadd(struct sess *sp, int want)
{
	struct epoll_event ev;
	struct reqmulti *reqm;
	struct worker *wrk;
	int ret;

	CHECK_OBJ_NOTNULL(sp, SESS_MAGIC);
	CAST_OBJ_NOTNULL(reqm, sp->reqm, REQMULTI_MAGIC);
	CAST_OBJ_NOTNULL(wrk, reqm->wrk, WORKER_MAGIC);

	bzero(&ev, sizeof(ev));
	ev.events = EPOLLERR;
	if (want == 1)
		ev.events |= EPOLLIN | EPOLLPRI;
	else if (want == 2)
		ev.events |= EPOLLOUT;
	else if (want == 3)
		ev.events |= EPOLLIN | EPOLLOUT | EPOLLPRI;
	else
		assert(0 == 1);
	ev.data.ptr = sp;
	ret = epoll_ctl(wrk->efd, EPOLL_CTL_ADD, sp->fd, &ev);
	if (ret == -1) {
		if (errno == EEXIST)
			ret = epoll_ctl(wrk->efd, EPOLL_CTL_MOD, sp->fd, &ev);
	}
	AZ(ret);
}

static void
SES_eventdel(struct sess *sp)
{
	struct epoll_event ev = { 0 , { 0 } };
	struct reqmulti *reqm;
	struct worker *wrk;
	int ret;

	CHECK_OBJ_NOTNULL(sp, SESS_MAGIC);
	CAST_OBJ_NOTNULL(reqm, sp->reqm, REQMULTI_MAGIC);
	CAST_OBJ_NOTNULL(wrk, reqm->wrk, WORKER_MAGIC);

	ret = epoll_ctl(wrk->efd, EPOLL_CTL_DEL, sp->fd, &ev);
	if (ret != 0) {
		if (errno == EBADF)
			return;
		printf("eventdel %s\n", strerror(errno));
	}
	AZ(ret);
}

static struct sess *
SES_alloc(struct reqmulti *reqm, curl_socket_t fd)
{
	struct sess *sp;

	sp = calloc(1, sizeof(*sp));
	AN(sp);
	sp->magic = SESS_MAGIC;
	sp->fd = fd;
	sp->reqm = reqm;
	return (sp);
}

static void
SES_free(struct sess *sp)
{

	SES_eventdel(sp);
	sp->magic = 0;
	free(sp);
}

static int
handle_socket(CURL *c, curl_socket_t fd, int action, void *userp,
    void *socketp)
{
	struct sess *sp;
	struct reqmulti *reqm = (struct reqmulti *)userp;
	struct worker *wrk;

	CHECK_OBJ_NOTNULL(reqm, REQMULTI_MAGIC);
	CAST_OBJ_NOTNULL(wrk, reqm->wrk, WORKER_MAGIC);
	(void)c;

	if (action == CURL_POLL_IN || action == CURL_POLL_OUT ||
	    action == CURL_POLL_INOUT) {
		if (socketp != NULL) {
			sp = (struct sess *)socketp;
			CHECK_OBJ_NOTNULL(sp, SESS_MAGIC);
		} else {
			sp = SES_alloc(reqm, fd);
			AN(sp);
			curl_multi_assign(reqm->curlm, fd, (void *)sp);
		}
	}
	switch (action) {
	case CURL_POLL_IN:
		SES_eventadd(sp, 1);
		break;
	case CURL_POLL_OUT:
		SES_eventadd(sp, 2);
		break;
	case CURL_POLL_INOUT:
		SES_eventadd(sp, 3);
		break;
	case CURL_POLL_REMOVE:
		if (socketp != NULL) {
			curl_multi_assign(reqm->curlm, fd, NULL);
			sp = (struct sess *)socketp;
			SES_free(sp);
		}
		break;
	default:
		assert(0 == 1);
	}
	return (0);
}

static size_t
req_writeheader(void *contents, size_t size, size_t nmemb, void *userp)
{
	struct req *req = (struct req *)userp;
	size_t len = size * nmemb;
	int ret;

	ret = VSB_bcat(req->header, contents, len);
	AZ(ret);
	return (len);
}

static char *
req_findheader(struct req *req, const char *hdr)
{
	int n, l;
	char * const *hh = req->resp;
	char *r;

	l = strlen(hdr);

	for (n = 3; hh[n] != NULL; n++) {
		if (strncasecmp(hdr, hh[n], l) || hh[n][l] != ':')
			continue;
		for (r = hh[n] + l + 1; vct_issp(*r); r++)
			continue;
		return (r);
	}
	return (NULL);
}

static int
req_splitheader(struct req *req)
{
	char *p, *q, **hh;
	int n;

	VSB_finish(req->header);
	if (VSB_len(req->header) == 0)
		return (-1);

	memset(req->resp, 0, sizeof req->resp);
	hh = req->resp;

	n = 0;
	p = VSB_data(req->header);

	/* PROTO */
	while (vct_islws(*p))
		p++;
	hh[n++] = p;
	while (!vct_islws(*p))
		p++;
	assert(!vct_iscrlf(*p));
	*p++ = '\0';

	/* STATUS */
	while (vct_issp(*p))		/* XXX: H space only */
		p++;
	assert(!vct_iscrlf(*p));
	hh[n++] = p;
	while (!vct_islws(*p))
		p++;
	if (vct_iscrlf(*p)) {
		hh[n++] = NULL;
		q = p;
		p += vct_skipcrlf(p);
		*q = '\0';
	} else {
		*p++ = '\0';
		/* MSG */
		while (vct_issp(*p))		/* XXX: H space only */
			p++;
		hh[n++] = p;
		while (!vct_iscrlf(*p))
			p++;
		q = p;
		p += vct_skipcrlf(p);
		*q = '\0';
	}
	assert(n == 3);

	while (*p != '\0') {
		assert(n < MAX_HDR);
		if (vct_iscrlf(*p))
			break;
		hh[n++] = p++;
		while (*p != '\0' && !vct_iscrlf(*p))
			p++;
		q = p;
		p += vct_skipcrlf(p);
		*q = '\0';
	}
	p += vct_skipcrlf(p);
	assert(*p == '\0');
	return (0);
}

static int
req_handleheader(struct req *req)
{
	struct link *lk;
	int ret;
	char *etag, *hdr;
	char *last_modified;

	CAST_OBJ_NOTNULL(lk, req->link, LINK_MAGIC);

	ret = req_splitheader(req);
	if (ret == -1)
		return (-1);
	if (!strcmp(req->resp[1], "301") || !strcmp(req->resp[1], "302")) {
		hdr = req_findheader(req, "Location");
		if (hdr == NULL)
			return (0);
		LNK_newhref(req, hdr);
	}
	etag = req_findheader(req, "Etag");
	if (etag != NULL) {
		lk->hdr_etag = strdup(etag);
		AN(lk->hdr_etag);
	}
	last_modified = req_findheader(req, "Last-Modified");
	if (last_modified != NULL) {
		lk->hdr_last_modified = strdup(last_modified);
		AN(lk->hdr_last_modified);
	}
	return (0);
}

static size_t
req_writebody(void *contents, size_t size, size_t nmemb, void *userp)
{
	struct req *req = (struct req *)userp;
	size_t len = size * nmemb;
	int ret;

	if ((req->flags & REQ_F_PARSEHEADER) == 0) {
		req->flags |= REQ_F_PARSEHEADER;
		ret = req_handleheader(req);
		assert(ret == 0);
	}
	ret = VSB_bcat(req->body, contents, len);
	AZ(ret);
	req->bodylen += len;
	/*
	 * If the real content length is over 256 Kbytes then abort the
	 * connection.
	 */
	if (req->bodylen > 512 * 1024) {
		struct link *lk;

		lk = req->link;
		AN(lk);
		printf("[WARN] Too big.  Aborts URL %s\n", lk->url);
		return (-1);
	}
	return (len);
}

static void
SCR_newreq(struct req *req, struct req *newone)
{
	struct script *scr;

	CHECK_OBJ_NOTNULL(req, REQ_MAGIC);
	CHECK_OBJ_NOTNULL(newone, REQ_MAGIC);

	scr = calloc(sizeof(*scr), 1);
	AN(scr);
	scr->magic = SCRIPT_MAGIC;
	scr->type = SCRIPT_T_REQ;
	scr->priv = newone;

	VTAILQ_INSERT_TAIL(&req->scripthead, scr, list);
}

static void
SCR_newbuffer(struct req *req, const char *filename, unsigned int line,
    const char *buf)
{
	struct script *scr;

	CHECK_OBJ_NOTNULL(req, REQ_MAGIC);

	scr = calloc(sizeof(*scr), 1);
	AN(scr);
	scr->magic = SCRIPT_MAGIC;
	scr->type = SCRIPT_T_BUFFER;
	scr->priv = buf;
	scr->filename = filename;
	scr->line = line;

	VTAILQ_INSERT_TAIL(&req->scripthead, scr, list);
}

static void
SCR_newlink(struct req *req, struct link *lk)
{
	struct script *scr;

	CHECK_OBJ_NOTNULL(req, REQ_MAGIC);

	scr = calloc(sizeof(*scr), 1);
	AN(scr);
	scr->magic = SCRIPT_MAGIC;
	scr->type = SCRIPT_T_LINK;
	scr->priv = lk;

	VTAILQ_INSERT_TAIL(&req->scripthead, scr, list);
}

static void
SCR_free(struct script *scr)
{

	free(scr);
}

const char *
REQ_geturl(void *reqarg)
{
	struct req *req = reqarg;

	CHECK_OBJ_NOTNULL(req, REQ_MAGIC);
	return (req->link->url);
}

static struct req *
REQ_new(struct worker *wrk, struct req *parent, struct link *lk)
{
	struct req *req;
	struct reqmulti *reqm;
	CURLcode code;
	CURLMcode mcode;

	if (parent != NULL)
		CHECK_OBJ_NOTNULL(parent, REQ_MAGIC);
	AN(lk);
	printf("[INFO] Fetching %s (parent %p)\n", lk->url, parent);

	req = calloc(sizeof(*req), 1);
	AN(req);
	req->magic = REQ_MAGIC;
	req->link = lk;
	req->header = VSB_new_auto();
	AN(req->header);
	req->body = VSB_new_auto();
	AN(req->body);
	req->parent = parent;
	VTAILQ_INIT(&req->subreqs);
	VTAILQ_INIT(&req->scripthead);
	req->c = curl_easy_init();
	AN(req->c);
	code = curl_easy_setopt(req->c, CURLOPT_URL, lk->url);
	assert(code == CURLE_OK);
	code = curl_easy_setopt(req->c, CURLOPT_WRITEFUNCTION, req_writebody);
	assert(code == CURLE_OK);
	code = curl_easy_setopt(req->c, CURLOPT_WRITEDATA, (void *)req);
	assert(code == CURLE_OK);
	code = curl_easy_setopt(req->c, CURLOPT_HEADERFUNCTION,
	    req_writeheader);
	assert(code == CURLE_OK);
	code = curl_easy_setopt(req->c, CURLOPT_WRITEHEADER, (void *)req);
	assert(code == CURLE_OK);
	code = curl_easy_setopt(req->c, CURLOPT_ACCEPT_ENCODING, "deflate");
	assert(code == CURLE_OK);
	code = curl_easy_setopt(req->c, CURLOPT_PRIVATE, req);
	assert(code == CURLE_OK);
	if ((lk->flags & LINK_F_DONE) != 0 &&
	    (lk->flags & LINK_F_JAVASCRIPT) != 0 &&
	    (lk->flags & LINK_F_BODY) != 0 &&
	    (lk->hdr_etag != NULL || lk->hdr_last_modified != NULL)) {
		int len;
		char buf[BUFSIZ];

		AN(lk->body);
		if (lk->hdr_etag != NULL) {
			len = snprintf(buf, sizeof(buf), "If-None-Match: %s",
			    lk->hdr_etag);
			assert(len < sizeof(buf));
			req->slist = curl_slist_append(req->slist, buf);
		}
		if (lk->hdr_last_modified != NULL) {
			len = snprintf(buf, sizeof(buf),
			    "If-Modified-Since: %s", lk->hdr_last_modified);
			assert(len < sizeof(buf));
			req->slist = curl_slist_append(req->slist, buf);
		}
		code = curl_easy_setopt(req->c, CURLOPT_HTTPHEADER, req->slist);
		assert(code == CURLE_OK);
	}

	req->reqm = reqm = RQM_get(wrk);
	AN(req->reqm);
	VTAILQ_INSERT_TAIL(&reqm->reqhead, req, list);
	mcode = curl_multi_add_handle(reqm->curlm, req->c);
	assert(mcode == CURLM_OK);
	wrk->n_conns++;

	LINK_LOCK();
	if ((lk->flags & LINK_F_ONLINKCHAIN) != 0) {
		lk->flags &= ~LINK_F_ONLINKCHAIN;
		VTAILQ_REMOVE(&linkchain, lk, chain);
	}
	LINK_UNLOCK();

	JCL_fetch(wrk, req);

	return (req);
}

static void
REQ_newroot(struct worker *wrk, const char *url)
{
	struct link *lk;
	struct req *req;
	int created;

	lk = LNK_lookup(url, &created);
	AN(lk);
	if (created == 0) {
		LNK_remref(lk);
		return;
	}
	req = REQ_new(wrk, NULL, lk);
	if (req == NULL)
		return;
}

static void
REQ_new_jssrc(struct req *parent, const char *url)
{
	struct link *lk;
	struct req *req;
	struct reqmulti *reqm = parent->reqm;
	int created;

	CHECK_OBJ_NOTNULL(parent, REQ_MAGIC);

	lk = LNK_lookup(url, &created);
	AN(lk);
	if (created == 0) {
		/*
		 * Please note that the reference counter of `lk'
		 * variable would be released REQ_final().
		 */
		assert((lk->flags & LINK_F_JAVASCRIPT) != 0);
		SCR_newlink(parent, lk);
		return;
	}
	lk->flags |= LINK_F_JAVASCRIPT;
	req = REQ_new(reqm->wrk, parent, lk);
	AN(req);
	SCR_newreq(parent, req);
	VTAILQ_INSERT_TAIL(&parent->subreqs, req, subreqs_list);
	parent->subreqs_onqueue++;
	parent->subreqs_count++;
}

static void
REQ_free(struct req *req)
{
	struct reqmulti *reqm = req->reqm;
	struct script *scr;
	struct worker *wrk;

	CHECK_OBJ_NOTNULL(req, REQ_MAGIC);
	assert(req->subreqs_onqueue == 0);
	CHECK_OBJ_NOTNULL(reqm, REQMULTI_MAGIC);
	CAST_OBJ_NOTNULL(wrk, reqm->wrk, WORKER_MAGIC);
	wrk->n_conns--;

	if (req->goutput != NULL)
		gumbo_destroy_output(req->goptions, req->goutput);
	if (req->scriptpriv != NULL)
		EJS_free(req->scriptpriv);
	VTAILQ_FOREACH(scr, &req->scripthead, list)
		SCR_free(scr);

	curl_multi_remove_handle(reqm->curlm, req->c);
	VTAILQ_REMOVE(&reqm->reqhead, req, list);
	RQM_release(reqm);

	if (req->slist != NULL)
		curl_slist_free_all(req->slist);
	curl_easy_cleanup(req->c);
	VSB_delete(req->body);
	VSB_delete(req->header);
	LNK_remref(req->link);
	free(req);
}

static int
req_urlnorm(struct req *req, const char *value, char *urlbuf, size_t urlbuflen)
{
	struct link *lk = req->link;
	UriParserStateA state;
	UriUriA absoluteBase;
	UriUriA absoluteDest;
	UriUriA relativeSource;
	int charsRequired;
	int error = 0;
	char *anchor;
	const char *target = value;
	char *newvalue;

	AN(lk);
	/*
	 * Removes '#' anchor marker because it doesn't be pointing the new
	 * URL.
	 */
	anchor = strrchr(value, '#');
	if (anchor != NULL) {
		newvalue = strdup(value);
		AN(newvalue);
		anchor = strrchr(newvalue, '#');
		AN(anchor);
		*anchor = '\0';
		target = newvalue;
	}

	/*
	 * XXX Don't need to parse everytime.
	 */
	state.uri = &absoluteBase;
	if (uriParseUriA(&state, lk->url) != URI_SUCCESS) {
		printf("Failed to parse URL %s\n", lk->url);
		error = -1;
		goto fail0;
	}
	state.uri = &relativeSource;
	if (uriParseUriA(&state, target) != URI_SUCCESS) {
		printf("Failed to parse URL %s\n", target);
		error = -1;
		goto fail1;
	}
	if (uriAddBaseUriA(&absoluteDest, &relativeSource, &absoluteBase) !=
	    URI_SUCCESS) {
		printf("Failed to call uriAddBaseUriA().\n");
		error = -1;
		goto fail2;
	}
	if (uriNormalizeSyntaxA(&absoluteDest) != URI_SUCCESS) {
		printf("Failed to call uriNormalizeSyntaxA().\n");
		error = -1;
		goto fail2;
	}
	charsRequired = -1;
	if (uriToStringCharsRequiredA(&absoluteDest, &charsRequired) !=
	    URI_SUCCESS) {
		printf("Failed to call uriToStringCharsRequiredA().\n");
		error = -1;
		goto fail2;
	}
	{
		assert(charsRequired + 1 <= urlbuflen);

		if (uriToStringA(urlbuf, &absoluteDest, urlbuflen, NULL) !=
		    URI_SUCCESS) {
			printf("Failed to call uriToStringA().\n");
			error = -1;
			goto fail2;
		}
	}
fail2:
	uriFreeUriMembersA(&absoluteDest);
fail1:
	uriFreeUriMembersA(&relativeSource);
fail0:
	uriFreeUriMembersA(&absoluteBase);
	if (target != value)
		free(newvalue);
	return (error);
}

static void
req_walktree(struct req *req, GumboNode* node)
{
	struct link *lk = req->link;
	GumboAttribute *href, *onclick, *src, *type;
	GumboNode *text;
	GumboVector *children;
	int i, ret;
	char urlbuf[BUFSIZ];

	AN(lk);
	if (node->type != GUMBO_NODE_ELEMENT)
		return;
	onclick = gumbo_get_attribute(&node->v.element.attributes, "onclick");
	if (onclick != NULL)
		printf("[INFO] ONCLICK = %s\n", onclick->value);
	switch (node->v.element.tag) {
	case GUMBO_TAG_A:
		href = gumbo_get_attribute(&node->v.element.attributes, "href");
		if (href != NULL) {
			LNK_newhref(req, href->value);
			break;
		}
		break;
	case GUMBO_TAG_SCRIPT:
		type = gumbo_get_attribute(&node->v.element.attributes, "type");
		if (type != NULL &&
		    strcasecmp(type->value, "text/javascript"))
			break;
		src = gumbo_get_attribute(&node->v.element.attributes, "src");
		if (src != NULL) {
			ret = req_urlnorm(req, src->value, urlbuf,
			    sizeof(urlbuf));
			if (ret == -1) {
				printf("Failed to normalize URL.\n");
				break;
			}
			REQ_new_jssrc(req, urlbuf);
			break;
		}
		if (node->v.element.children.length != 1) {
			printf("SCRIPT EMPTY\n");
			break;
		}
		text = node->v.element.children.data[0];
		switch (text->type) {
		case GUMBO_NODE_TEXT:
			SCR_newbuffer(req, lk->url,
			    text->v.text.start_pos.line, text->v.text.text);
			break;
		case GUMBO_NODE_WHITESPACE:
			break;
		default:
			printf("Unexpected type %d\n", text->type);
			assert(0 == 1);
		}
		break;
	default:
		break;
	}

	children = &node->v.element.children;
	for (i = 0; i < children->length; ++i)
		req_walktree(req, (GumboNode *)children->data[i]);
}

static void
REQ_main(struct req *req)
{
	struct link *lk;
	struct vsb *vsb;
	CURLcode code;
	int ret;
	char *content_type;

	CHECK_OBJ_NOTNULL(req, REQ_MAGIC);
	vsb = req->body;
	VSB_finish(vsb);
	CAST_OBJ_NOTNULL(lk, req->link, LINK_MAGIC);

	if ((req->flags & REQ_F_PARSEHEADER) == 0) {
		req->flags |= REQ_F_PARSEHEADER;
		ret = req_handleheader(req);
		if (ret == -1)
			return;
	}
	lk->flags |= LINK_F_DONE;
	if ((lk->flags & LINK_F_JAVASCRIPT) != 0) {
		if ((lk->flags & LINK_F_BODY) == 0) {
			if (!strcmp(req->resp[1], "200")) {
				/*
				 * XXX We don't handle HTTP cache headers here.
				 * e.g. Cache-Control: no-store,
				 *      Pragma: no-cache,
				 *      Expires: 0
				 */
				AZ(lk->body);
				lk->body = VSB_new_auto();
				AN(lk->body);
				VSB_bcpy(lk->body, VSB_data(vsb), VSB_len(vsb));
				VSB_finish(lk->body);
				lk->flags |= LINK_F_BODY;
			}
		} else {
			if (!strcmp(req->resp[1], "304")) {
				assert(VSB_len(vsb) == 0);
				VSB_clear(vsb);
				assert(VSB_len(lk->body) > 0);
				VSB_bcpy(vsb, VSB_data(lk->body),
				    VSB_len(lk->body));
				VSB_finish(vsb);
			}
		}
	}
	lk->t_fetched = TIM_mono();

	code = curl_easy_getinfo(req->c, CURLINFO_CONTENT_TYPE, &content_type);
	assert(code == CURLE_OK);

	if (content_type == NULL || strcasestr(content_type, "text/html")) {
		/*
		 * Don't need to parse the content if the link flags point
		 * it's javascript assumed.
		 */
		if ((lk->flags & LINK_F_JAVASCRIPT) != 0)
			return;
		AZ(req->scriptpriv);
		req->scriptpriv = EJS_newreq(lk->url, req);
		AN(req->scriptpriv);
		req->goptions = &kGumboDefaultOptions;
		req->goutput = gumbo_parse_with_options(req->goptions,
		    VSB_data(vsb), VSB_len(vsb));
		AN(req->goutput);
		req_walktree(req, req->goutput->root);
	}
}

static void
REQ_final(struct req *req)
{
	struct link *lk;
	struct req *subreq;
	const struct req *tmp;
	struct script *scr;
	const char *ptr;

	CHECK_OBJ_NOTNULL(req, REQ_MAGIC);
	assert(req->subreqs_onqueue == 0);

	if (!VTAILQ_EMPTY(&req->scripthead))
		AN(req->scriptpriv);

	VTAILQ_FOREACH(scr, &req->scripthead, list) {
		CHECK_OBJ_NOTNULL(scr, SCRIPT_MAGIC);
		switch (scr->type) {
		case SCRIPT_T_REQ:
			tmp = (const struct req *)scr->priv;
			CHECK_OBJ_NOTNULL(tmp, REQ_MAGIC);
			lk = tmp->link;
			CHECK_OBJ_NOTNULL(lk, LINK_MAGIC);
			EJS_eval(req->scriptpriv, lk->url, 1,
			    VSB_data(tmp->body), VSB_len(tmp->body));
			break;
		case SCRIPT_T_BUFFER:
			ptr = (const char *)scr->priv;
			EJS_eval(req->scriptpriv, scr->filename, scr->line,
			    ptr, strlen(ptr));
			break;
		case SCRIPT_T_LINK:
			lk = (struct link *)TRUST_ME(scr->priv);
			CHECK_OBJ_NOTNULL(lk, LINK_MAGIC);
			assert((lk->flags & LINK_F_JAVASCRIPT) != 0);
			if ((lk->flags & LINK_F_DONE) != 0 &&
			    (lk->flags & LINK_F_BODY) != 0)
				EJS_eval(req->scriptpriv, lk->url, 1,
				    VSB_data(lk->body), VSB_len(lk->body));
			LNK_remref(lk);
			break;
		default:
			assert(0 == 1);
		}
	}

	VTAILQ_FOREACH(subreq, &req->subreqs, subreqs_list) {
		CHECK_OBJ_NOTNULL(subreq, REQ_MAGIC);
		REQ_free(subreq);
	}
	REQ_free(req);
}

static void
REQ_fire(void *arg)
{
	struct link *lk;
	struct worker *wrk = (struct worker *)arg;
	int i;

	printf("[INFO] REQFIRE n_links %d n_conns %d\n", n_links, wrk->n_conns);

	if (wrk->n_conns < 10) {
		for (i = 0; i < 10; i++) {
			LINK_LOCK();
			lk = VTAILQ_FIRST(&linkchain);
			if (lk == NULL) {
				LINK_UNLOCK();
				break;
			}
			lk->flags &= ~LINK_F_ONLINKCHAIN;
			VTAILQ_REMOVE(&linkchain, lk, chain);
			LINK_UNLOCK();
			REQ_new(wrk, NULL, lk);
		}
	}

	callout_reset(&wrk->cb, &wrk->co_reqfire, CALLOUT_SECTOTICKS(1),
	    REQ_fire, wrk);
}

/*----------------------------------------------------------------------*/

static void
RQM_new(struct worker *wrk)
{
	struct reqmulti *reqm;
	CURLMcode mcode;

	reqm = calloc(sizeof(*reqm), 1);
	AN(reqm);
	reqm->magic = REQMULTI_MAGIC;
	reqm->curlm = curl_multi_init();
	AN(reqm->curlm);
	reqm->wrk = wrk;
	mcode = curl_multi_setopt(reqm->curlm, CURLMOPT_SOCKETFUNCTION,
	    handle_socket);
	assert(mcode == CURLM_OK);
	mcode = curl_multi_setopt(reqm->curlm, CURLMOPT_SOCKETDATA, reqm);
	assert(mcode == CURLM_OK);
	mcode = curl_multi_setopt(reqm->curlm, CURLMOPT_TIMERFUNCTION,
	    start_timeout);
	assert(mcode == CURLM_OK);
	mcode = curl_multi_setopt(reqm->curlm, CURLMOPT_TIMERDATA, reqm);
	assert(mcode == CURLM_OK);
	VTAILQ_INIT(&reqm->reqhead);

	VTAILQ_INSERT_TAIL(&wrk->reqmultihead, reqm, list);
	wrk->reqmulti_active = reqm;
}

static void
RQM_free(struct reqmulti *reqm)
{
	struct worker *wrk;

	CHECK_OBJ_NOTNULL(reqm, REQMULTI_MAGIC);
	CAST_OBJ_NOTNULL(wrk, reqm->wrk, WORKER_MAGIC);

	VTAILQ_REMOVE(&wrk->reqmultihead, reqm, list);
	curl_multi_cleanup(reqm->curlm);
	free(reqm);
}

static struct reqmulti *
RQM_get(struct worker *wrk)
{
	struct reqmulti *reqm;

	reqm = wrk->reqmulti_active;
	AN(reqm);
	reqm->busy++;
	reqm->n_reqs++;
	if (reqm->n_reqs > 512)
		RQM_new(wrk);
	return (reqm);
}

static void
RQM_release(struct reqmulti *reqm)
{

	AN(reqm);
	reqm->busy--;
}

static void
RQM_calllout(void *arg)
{
	struct reqmulti *reqm, *reqmtmp;
	struct worker *wrk = (struct worker *)arg;

	VTAILQ_FOREACH_SAFE(reqm, &wrk->reqmultihead, list, reqmtmp) {
		if (reqm == wrk->reqmulti_active)
			continue;
		if (reqm->busy > 0)
			continue;
		RQM_free(reqm);
	}

	callout_reset(&wrk->cb, &wrk->co_reqmulti, CALLOUT_SECTOTICKS(30),
	    RQM_calllout, wrk);
}

/*----------------------------------------------------------------------*/

static void
core_fetch(struct worker *wrk, int n)
{
	struct req *parent, *req;
	struct reqmulti *reqm;
	CURLcode code;
	CURLMsg *msg;
	int pending;
	int running_handles;

	VTAILQ_FOREACH(reqm, &wrk->reqmultihead, list) {
		if (n == 0)
			curl_multi_socket_all(reqm->curlm, &running_handles);
		while ((msg = curl_multi_info_read(reqm->curlm, &pending))) {
			char *done_url;

			switch (msg->msg) {
			case CURLMSG_DONE:
				code = curl_easy_getinfo(msg->easy_handle,
				    CURLINFO_EFFECTIVE_URL, &done_url);
				assert(code == CURLE_OK);
				code = curl_easy_getinfo(msg->easy_handle,
				    CURLINFO_PRIVATE, &req);
				assert(code == CURLE_OK);
				assert(msg->easy_handle == req->c);
				REQ_main(req);
				if (req->parent != NULL) {
					parent = req->parent;
					CHECK_OBJ_NOTNULL(parent, REQ_MAGIC);
					parent->subreqs_onqueue--;
					assert(parent->subreqs_onqueue >= 0);
					if (parent->subreqs_onqueue == 0)
						REQ_final(parent);
				} else {
					if (req->subreqs_onqueue == 0)
						REQ_final(req);
				}
				break;
			default:
				assert(0 == 1);
				break;
			}
		}
	}
}

static const char *starturl = "http://www.test.com/";

static void *
core_main(void *arg)
{
	struct epoll_event ev[EPOLLEVENT_MAX], *ep;
	struct sess *sp;
	struct worker wrk;
	CURLMcode mcode;
	int i, n;
	int running_handles;

	(void)arg;

	bzero(&wrk, sizeof(wrk));
	wrk.magic = WORKER_MAGIC;
	VTAILQ_INIT(&wrk.reqmultihead);
	wrk.efd = epoll_create(1);
	assert(wrk.efd >= 0);
	COT_init(&wrk.cb);
	callout_init(&wrk.co_reqmulti, 0);
	callout_init(&wrk.co_reqfire, 0);
	callout_init(&wrk.co_timo, 0);
	wrk.confpriv = EJS_newwrk(&wrk);

	callout_reset(&wrk.cb, &wrk.co_reqfire, CALLOUT_SECTOTICKS(1),
	    REQ_fire, &wrk);
	callout_reset(&wrk.cb, &wrk.co_reqmulti, CALLOUT_SECTOTICKS(30),
	    RQM_calllout, &wrk);

	RQM_new(&wrk);
	REQ_newroot(&wrk, starturl);

	while (1) {
		COT_ticks(&wrk.cb);
		COT_clock(&wrk.cb);
		n = epoll_wait(wrk.efd, ev, EPOLLEVENT_MAX, 1000);
		for (ep = ev, i = 0; i < n; i++, ep++) {
			sp = (struct sess *)ep->data.ptr;
			AN(sp);
			if (sp->magic != SESS_MAGIC) {
				/*
				 * It looks some code of curl missed to call
				 * the callback to close the socket.
				 */
				continue;
			}

			mcode = curl_multi_socket_action(sp->reqm->curlm,
			    sp->fd, 0, &running_handles);
			assert(mcode == CURLM_OK);
		}
		core_fetch(&wrk, n);
	}
	return (NULL);
}

int
main(int argc, char *argv[])
{
	pthread_t tid;
	int i, ret;

	if (argc > 1)
		starturl = argv[1];

	curl_global_init(CURL_GLOBAL_ALL);
	init_locks();
	EJS_init();
	LNK_start();

	for (i = 0; i < 1; i++) {
		ret = pthread_create(&tid, NULL, core_main, NULL);
		AZ(ret);
	}
	while (1)
		sleep(1);
	return (0);
}
