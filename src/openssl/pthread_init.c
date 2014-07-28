/* OpenCA LibPKI - src/openssl/pthread_init.c
 * ====================================================================
 * Threads help function for OpenSSL - both static and dynamic locks.
 * Many thanks for the support and the help go primarly to:
 * - Przemek Michalski
 * - Sander Temme
 * - Geoff Thorpe
 *
 */

#include <libpki/pki.h>

#ifndef CRYPTO_LOCK
#define CRYPTO_LOCK     0x01
#define CRYPTO_UNLOCK   0x02
#define CRYPTO_READ     0x04
#define CRYPTO_WRITE    0x08
#endif

#if (LIBPKI_OS_CLASS == LIBPKI_OS_WIN)
struct CRYPTO_dynlock_value {
	SRWLOCK lock;
}

static SRWLOCK *lock_cs;
#else
struct CRYPTO_dynlock_value {
	PKI_RWLOCK lock;
};

static pthread_mutex_t *lock_cs;
#endif

static long *lock_count;

/* Local Function Declaration */
void _dyn_lock_callback(int mode, struct CRYPTO_dynlock_value *l, 
						const char *file, int line);
struct CRYPTO_dynlock_value *_dyn_create_callback(const char *file, int line);
void _dyn_destroy_callback(struct CRYPTO_dynlock_value *l, 
						const char *file, int line);
void thread_cleanup(void);

#if (LIBPKI_OS_CLASS == LIBPKI_OS_WIN )
void win32_locking_callback(int mode, int type, char *file, int line) {
#else
void pthreads_locking_callback(int mode, int type, char *file, int line);
unsigned long pthreads_thread_id(void);
#endif

/* Functions */

void _dyn_lock_callback(int mode, struct CRYPTO_dynlock_value *l, 
						const char *file, int line) {

#if (LIBPKI_OS_CLASS == LIBPKI_OS_WIN )

	if(mode==(CRYPTO_LOCK|CRYPTO_READ))
		AcquireSRWLockShared(&l->lock); // pthread_rwlock_rdlock(&l->lock);
	else if(mode==(CRYPTO_LOCK|CRYPTO_WRITE)) 
		AcquireSRWLockExclusive(&l->lock); // pthread_rwlock_wrlock(&l->lock);
	else if(mode==(CRYPTO_UNLOCK|CRYPTO_READ))
		ReleaseSRWLockShared(&l->lock); // pthread_rwlock_unlock(&l->lock);
	else if(mode==(CRYPTO_UNLOCK|CRYPTO_WRITE))
		ReleaseSRWLockExclusive(&l->lock); // pthread_rwlock_unlock(&l->lock);

#else

	     if(mode==(CRYPTO_LOCK|CRYPTO_READ))
	    	 PKI_RWLOCK_read_lock(&l->lock);
	     else if(mode==(CRYPTO_LOCK|CRYPTO_WRITE))
	    	 PKI_RWLOCK_write_lock(&l->lock);
	     else if(mode==(CRYPTO_UNLOCK|CRYPTO_READ))
	    	 PKI_RWLOCK_release_read(&l->lock);
	     else if(mode==(CRYPTO_UNLOCK|CRYPTO_WRITE))
	    	 PKI_RWLOCK_release_write(&l->lock);

#endif

	return;
}
 
struct CRYPTO_dynlock_value *_dyn_create_callback(const char *file, int line) {
	struct CRYPTO_dynlock_value *l = NULL;

	l = (struct CRYPTO_dynlock_value *) 
				malloc(sizeof(struct CRYPTO_dynlock_value));
#if (LIBPKI_OS_CLASS == LIBPKI_OS_WIN )
	InitializeSRWLock(&l->lock);
#else
	// pthread_rwlock_init(&l->lock, NULL);
	PKI_RWLOCK_init(&l->lock);
#endif

	return l;
}

void _dyn_destroy_callback(struct CRYPTO_dynlock_value *l, 
						const char *file, int line) {
#if (LIBPKI_OS_CLASS == LIBPKI_OS_WIN )
	// Nothing to do here
#else
	PKI_RWLOCK_destroy(&l->lock);
	// pthread_rwlock_destroy(&l->lock);
#endif
	free(l);
}
                                  
void OpenSSL_pthread_init(void)
{
	int i;

#if (LIBPKI_OS_CLASS == LIBPKI_OS_WIN )
	lock_cs=OPENSSL_malloc((size_t) (((size_t)CRYPTO_num_locks()) * 
						sizeof(HANDLE)));
#else
	lock_cs=OPENSSL_malloc((size_t) (((size_t)CRYPTO_num_locks()) * 
						sizeof(pthread_mutex_t)));
#endif
	lock_count=OPENSSL_malloc(((size_t) (CRYPTO_num_locks()) * 
						sizeof(long)));
	for (i=0; i<CRYPTO_num_locks(); i++)
		{
		lock_count[i]=0;
		pthread_mutex_init(&(lock_cs[i]),NULL);
		}

#if (LIBPKI_OS_CLASS == LIBPKI_OS_WIN )
	CRYPTO_set_id_callback((unsigned long (*)())win32_thread_id);
	CRYPTO_set_locking_callback((void (*)(int,int,char *,int))win32_locking_callback);
#else
	CRYPTO_set_id_callback((unsigned long (*)())pthreads_thread_id);
	CRYPTO_set_locking_callback((void (*)())pthreads_locking_callback);
#endif
	/* Initializing the OpenSSL dynamic callbacks as well,
           needed by the nCipher driver */
	CRYPTO_set_dynlock_create_callback(_dyn_create_callback);
	CRYPTO_set_dynlock_lock_callback(_dyn_lock_callback);
	CRYPTO_set_dynlock_destroy_callback(_dyn_destroy_callback);

	return;
}

void OpenSSL_pthread_cleanup(void)
{
	thread_cleanup();
}

void thread_cleanup(void) {
	int i;

	CRYPTO_set_locking_callback(NULL);

	for ( i = 0; i < CRYPTO_num_locks(); i++) {
#if (LIBPKI_OS_CLASS == LIBPKI_OS_WIN )
		CloseHandle(lock_cs[i]);
#else
		pthread_mutex_destroy(&(lock_cs[i]));
#endif
	}

	OPENSSL_free(lock_cs);
	OPENSSL_free(lock_count);

	return;
}

#if (LIBPKI_OS_CLASS == LIBPKI_OS_WIN )
void win32_locking_callback(int mode, int type, char *file, int line) {
    if (mode & CRYPTO_LOCK) {
        WaitForSingleObject(lock_cs[type],INFINITE);
	} else {
        ReleaseMutex(lock_cs[type]);
	}
}
#else
void pthreads_locking_callback(int mode, int type, char *file, int line) {

	if (mode & CRYPTO_LOCK) {
		pthread_mutex_lock(&(lock_cs[type]));
		lock_count[type]++;
	} else {
		pthread_mutex_unlock(&(lock_cs[type]));
	}

	return;
}

unsigned long pthreads_thread_id(void) {
	unsigned long ret;

	ret=(unsigned long)pthread_self();
	return(ret);
}

#endif
