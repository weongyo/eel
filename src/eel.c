#include <assert.h>
#include <pthread.h>
#include <stdio.h>

#include <curl/curl.h>
#include <openssl/crypto.h>
#include <openssl/err.h>

#define	AZ(foo)		do { assert((foo) == 0); } while (0)
#define	AN(foo)		do { assert((foo) != 0); } while (0)

static pthread_rwlock_t *rwlocks;

static void
lock_callback(int mode, int type, char *file, int line)
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
	CRYPTO_set_id_callback((unsigned long (*)())thread_id);
	CRYPTO_set_locking_callback((void (*)())lock_callback);
}

static void *
core_main(void *arg)
{

	while (1)
		sleep(1);
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
}
