#include <sys/epoll.h>
#include <assert.h>
#include <errno.h>
#include <pthread.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include <curl/curl.h>
#include <openssl/crypto.h>
#include <openssl/err.h>

#include "callout.h"
#include "vsb.h"

#define	EPOLLEVENT_MAX	(4 * 1024)
#define	AZ(foo)		do { assert((foo) == 0); } while (0)
#define	AN(foo)		do { assert((foo) != 0); } while (0)

struct worker;

struct sess {
	unsigned		magic;
#define	SESS_MAGIC		0xb733fc97
	curl_socket_t		fd;
	struct worker		*wrk;
};

struct req {
	unsigned		magic;
#define	REQ_MAGIC		0x9ba52f21
	CURL			*c;
	struct vsb		*vsb;
	struct worker		*wrk;
	VTAILQ_ENTRY(req)	list;
};

struct worker {
	unsigned		magic;
#define	WORKER_MAGIC		0x44505226
	int			efd;
	CURLM			*curlm;
	VTAILQ_HEAD(, req)	reqhead;
	struct callout		co_timo;
	struct callout_block	cb;
};

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
	struct worker *wrk = (struct worker *)arg;
	int running_handles;

	assert(wrk->magic == WORKER_MAGIC);

	curl_multi_socket_action(wrk->curlm, CURL_SOCKET_TIMEOUT, 0,
	    &running_handles);
}

static void
start_timeout(CURLM *cm, long timeout_ms, void *userp)
{
	struct worker *wrk = (struct worker *)userp;

	(void)cm;
	assert(wrk->magic == WORKER_MAGIC);

	if (timeout_ms <= 0)
		timeout_ms = 1;
	callout_reset(&wrk->cb, &wrk->co_timo, CALLOUT_MSTOTICKS(timeout_ms),
	    on_timeout, wrk);
}

static void
SES_eventadd(struct sess *sp, int want)
{
	struct epoll_event ev;
	int ret;

	bzero(&ev, sizeof(ev));
	ev.events = EPOLLERR;
	if (want == 1)
		ev.events |= EPOLLIN | EPOLLPRI;
	else if (want == 2)
		ev.events |= EPOLLOUT;
	else
		assert(0 == 1);
	ev.data.ptr = sp;
	ret = epoll_ctl(sp->wrk->efd, EPOLL_CTL_ADD, sp->fd, &ev);
	if (ret == -1) {
		if (errno == EEXIST)
			ret = epoll_ctl(sp->wrk->efd, EPOLL_CTL_MOD, sp->fd,
			    &ev);
	}
	assert(ret == 0);
}

static struct sess *
SES_alloc(struct worker *wrk, CURL *c, curl_socket_t fd)
{
	struct sess *sp;

	(void)c;

	sp = calloc(1, sizeof(*sp));
	assert(sp != NULL);
	sp->magic = SESS_MAGIC;
	sp->fd = fd;
	sp->wrk = wrk;
	return (sp);
}

static void
SES_free(struct sess *sp)
{

	free(sp);
}

static int
handle_socket(CURL *c, curl_socket_t fd, int action, void *userp,
    void *socketp)
{
	struct sess *sp;
	struct worker *wrk = (struct worker *)userp;

	if (action == CURL_POLL_IN || action == CURL_POLL_OUT) {
		if (socketp != NULL)
			sp = (struct sess *)socketp;
		else {
			sp = SES_alloc(wrk, c, fd);
			AN(sp);
			curl_multi_assign(wrk->curlm, fd, (void *)sp);
		}
	}
	switch (action) {
	case CURL_POLL_IN:
		SES_eventadd(sp, 1);
		break;
	case CURL_POLL_OUT:
		SES_eventadd(sp, 2);
		break;
	case CURL_POLL_REMOVE:
		if (socketp != NULL) {
			sp = (struct sess *)socketp;
			SES_free(sp);
			curl_multi_assign(wrk->curlm, fd, NULL);
		}
		break;
	default:
		assert(0 == 1);
	}
	return (0);
}

static size_t
writebody(void *contents, size_t size, size_t nmemb, void *userp)
{
	struct req *req = (struct req *)userp;
	size_t len = size * nmemb;
	int ret;

	ret = VSB_bcat(req->vsb, contents, len);
	AZ(ret);
	return (len);
}

static void
REQ_new(struct worker *wrk, const char *url)
{
	struct req *req;
	CURLcode code;
	CURLMcode mcode;

	req = calloc(sizeof(*req), 1);
	AN(req);
	req->magic = REQ_MAGIC;
	req->wrk = wrk;
	req->vsb = VSB_new_auto();
	req->c = curl_easy_init();
	AN(req->c);
	code = curl_easy_setopt(req->c, CURLOPT_URL, url);
	assert(code == CURLE_OK);
	code = curl_easy_setopt(req->c, CURLOPT_WRITEFUNCTION, writebody);
	assert(code == CURLE_OK);
	code = curl_easy_setopt(req->c, CURLOPT_WRITEDATA, (void *)req);
	assert(code == CURLE_OK);
	code = curl_easy_setopt(req->c, CURLOPT_ACCEPT_ENCODING, "deflate");
	assert(code == CURLE_OK);
	code = curl_easy_setopt(req->c, CURLOPT_PRIVATE, req);
	assert(code == CURLE_OK);

	VTAILQ_INSERT_TAIL(&wrk->reqhead, req, list);
	mcode = curl_multi_add_handle(wrk->curlm, req->c);
	assert(mcode == CURLM_OK);
}

static void
REQ_free(struct req *req)
{
	struct worker *wrk = req->wrk;

	assert(wrk->magic == WORKER_MAGIC);

	curl_multi_remove_handle(wrk->curlm, req->c);
	VTAILQ_REMOVE(&wrk->reqhead, req, list);

	curl_easy_cleanup(req->c);
	VSB_delete(req->vsb);
	free(req);
}

static void *
core_main(void *arg)
{
	struct epoll_event ev[EPOLLEVENT_MAX], *ep;
	struct req *req;
	struct sess *sp;
	struct worker wrk;
	CURLM *cm;
	CURLMcode mcode;
	CURLMsg *msg;
	int i, n;
	int pending;
	int running_handles;

	(void)arg;

	bzero(&wrk, sizeof(wrk));
	wrk.magic = WORKER_MAGIC;
	wrk.efd = epoll_create(1);
	assert(wrk.efd >= 0);
	VTAILQ_INIT(&wrk.reqhead);
	COT_init(&wrk.cb);
	callout_init(&wrk.co_timo, 0);

	cm = curl_multi_init();
	AN(cm);
	mcode = curl_multi_setopt(cm, CURLMOPT_SOCKETFUNCTION, handle_socket);
	assert(mcode == CURLM_OK);
	mcode = curl_multi_setopt(cm, CURLMOPT_SOCKETDATA, &wrk);
	assert(mcode == CURLM_OK);
	mcode = curl_multi_setopt(cm, CURLMOPT_TIMERFUNCTION, start_timeout);
	assert(mcode == CURLM_OK);
	mcode = curl_multi_setopt(cm, CURLMOPT_TIMERDATA, &wrk);
	assert(mcode == CURLM_OK);
	wrk.curlm = cm;

	REQ_new(&wrk, "https://www.google.coms");

	while (1) {
		COT_ticks(&wrk.cb);
		COT_clock(&wrk.cb);
		n = epoll_wait(wrk.efd, ev, EPOLLEVENT_MAX, 1000);
		for (ep = ev, i = 0; i < n; i++, ep++) {
			sp = (struct sess *)ep->data.ptr;
			AN(sp);

			mcode = curl_multi_socket_action(wrk.curlm, sp->fd,
			    0, &running_handles);
			assert(mcode == CURLM_OK);
		}
		while ((msg = curl_multi_info_read(wrk.curlm, &pending))) {
			char *done_url;

			switch (msg->msg) {
			case CURLMSG_DONE:
				curl_easy_getinfo(msg->easy_handle,
				    CURLINFO_EFFECTIVE_URL, &done_url);
				curl_easy_getinfo(msg->easy_handle,
				    CURLINFO_PRIVATE, &req);
				assert(msg->easy_handle == req->c);
				printf("%s DONE (req %p)\n", done_url, req);
				REQ_free(req);
				break;
			default:
				assert(0 == 1);
				break;
			}
		}
	}
	return (NULL);
}

int
main(void)
{
	pthread_t tid;
	int i, ret;

	curl_global_init(CURL_GLOBAL_ALL);
	init_locks();

	for (i = 0; i < 1; i++) {
		ret = pthread_create(&tid, NULL, core_main, NULL);
		AZ(ret);
	}
	while (1)
		sleep(1);
	return (0);
}
