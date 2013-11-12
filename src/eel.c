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

#define	EPOLLEVENT_MAX	(4 * 1024)
#define	AZ(foo)		do { assert((foo) == 0); } while (0)
#define	AN(foo)		do { assert((foo) != 0); } while (0)

struct worker;

struct sess {
	unsigned		magic;
#define	SESS_MAGIC		0xb733fc97
	unsigned		flags;
#define	SESS_F_ONEPOLL		(1 << 0)	/* On epoll */
	curl_socket_t		fd;
	struct worker		*wrk;
};

struct worker {
	unsigned		magic;
#define	WORKER_MAGIC		0x44505226
	int			efd;
	CURLM			*curlm;
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
SES_eventadd(struct sess *sp)
{
	struct epoll_event ev;
	int ret;

	bzero(&ev, sizeof(ev));
	ev.events = EPOLLERR | EPOLLET | EPOLLIN | EPOLLPRI | EPOLLOUT;
	ev.data.ptr = sp;
	ret = epoll_ctl(sp->wrk->efd, EPOLL_CTL_ADD, sp->fd, &ev);
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
	case CURL_POLL_OUT:
		if ((sp->flags & SESS_F_ONEPOLL) == 0) {
			SES_eventadd(sp);
			sp->flags |= SESS_F_ONEPOLL;
		}
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

static void *
core_main(void *arg)
{
	struct epoll_event ev[EPOLLEVENT_MAX], *ep;
	struct sess *sp;
	struct worker wrk;
	CURL *c;
	CURLM *cm;
	CURLMcode mcode;
	CURLMsg *msg;
	FILE *fp;
	int i, n;
	int pending;
	int running_handles;

	(void)arg;

	bzero(&wrk, sizeof(wrk));
	wrk.magic = WORKER_MAGIC;
	wrk.efd = epoll_create(1);
	assert(wrk.efd >= 0);
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

	c = curl_easy_init();
	AN(c);
	fp = fopen("/dev/null", "w");
	AN(fp);
	curl_easy_setopt(c, CURLOPT_WRITEDATA, fp);
	curl_easy_setopt(c, CURLOPT_URL, "https://www.google.com");
	curl_multi_add_handle(cm, c);

	c = curl_easy_init();
	AN(c);
	fp = fopen("/dev/null", "w");
	AN(fp);
	curl_easy_setopt(c, CURLOPT_WRITEDATA, fp);
	curl_easy_setopt(c, CURLOPT_URL, "http://www.yahoo.com");
	curl_multi_add_handle(cm, c);

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
				printf("%s DONE\n", done_url);
				curl_multi_remove_handle(wrk.curlm,
				    msg->easy_handle);
				curl_easy_cleanup(msg->easy_handle);
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
