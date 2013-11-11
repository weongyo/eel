#include <assert.h>
#include <pthread.h>
#include <stdio.h>
#include <strings.h>
#include <unistd.h>

#include <curl/curl.h>
#include <openssl/crypto.h>
#include <openssl/err.h>

#include "callout.h"

#define	AZ(foo)		do { assert((foo) == 0); } while (0)
#define	AN(foo)		do { assert((foo) != 0); } while (0)

struct worker {
	unsigned		magic;
#define	WORKER_MAGIC		0x44505226
	CURLM			*curlm;
	long			curlm_maxtimo;
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
	wrk->curlm_maxtimo = timeout_ms;
	callout_reset(&wrk->cb, &wrk->co_timo,
	    CALLOUT_MSTOTICKS(wrk->curlm_maxtimo), on_timeout, wrk);
}

static int
handle_socket(CURL *c, curl_socket_t s, int action, void *userp,
    void *socketp)
{

	(void)c;
	(void)s;
	(void)action;
	(void)userp;
	(void)socketp;
	assert(0 == 1);
	return (-1);
}

static void *
core_main(void *arg)
{
	struct worker wrk;
	CURL *c;
	CURLM *cm;
	CURLMcode code;

	(void)arg;

	bzero(&wrk, sizeof(wrk));
	wrk.magic = WORKER_MAGIC;
	COT_init(&wrk.cb);
	callout_init(&wrk.co_timo, 0);

	cm = curl_multi_init();
	AN(cm);
	code = curl_multi_setopt(cm, CURLMOPT_SOCKETFUNCTION, handle_socket);
	assert(code == CURLM_OK);
	code = curl_multi_setopt(cm, CURLMOPT_TIMERFUNCTION, start_timeout);
	assert(code == CURLM_OK);
	code = curl_multi_setopt(cm, CURLMOPT_TIMERDATA, &wrk);
	assert(code == CURLM_OK);
	wrk.curlm = cm;

	c = curl_easy_init();
	AN(c);
	curl_easy_setopt(c, CURLOPT_URL, "http://www.test.com");
	curl_multi_add_handle(cm, c);

	while (1) {
		COT_ticks(&wrk.cb);
		COT_clock(&wrk.cb);
		usleep(wrk.curlm_maxtimo * 1000);
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
