/* Platform Independed Threads Management
 * (c) 2010 by Massimiliano Pala and OpenCA Labs
 * All Rights Reserved
 */

#include <libpki/pki.h>

/*! \brief Spawns a new Thread */
int PKI_THREAD_create ( PKI_THREAD *th, PKI_THREAD_ATTR *attr,
		void *(*func)(void *), void *arg ) {

#if (LIBPKI_OS_CLASS == WIN)
	struct _thread_v *tv = PKI_Malloc(sizeof(struct _thread_v));
	unsigned ssize = 0;
	
	if (!tv) return PKI_ERR;
	
	*th = tv;
	
	/* Save data in pthread_t */
	tv->ret_arg = arg;
	tv->func = func;
	tv->clean = NULL;
	tv->cancelled = 0;
	tv->p_state = PTHREAD_DEFAULT_ATTR;
	tv->keymax = 0;
	tv->keyval = NULL;
	tv->h = (HANDLE) -1;
	
	if (attr)
	{
		tv->p_state = attr->p_state;
		ssize = attr->s_size;
	}
	
	/* Make sure tv->h has value of -1 */
	_ReadWriteBarrier();

	tv->h = (HANDLE) _beginthreadex(NULL, ssize, pthread_create_wrapper, tv, 0, NULL);
	
	/* Failed */
	if (!tv->h) return 1;
	
	
	if (tv->p_state & PTHREAD_CREATE_DETACHED)
	{
		CloseHandle(tv->h);
		_ReadWriteBarrier();
		tv->h = 0;
	}

	return PKI_OK;

#else
	return pthread_create ( th, attr, func, arg );
#endif

}

/*! \brief Creates and Spawns a new thread */
PKI_THREAD *PKI_THREAD_new ( void * (*func)(void *arg), void *arg ) {

	PKI_THREAD *th = NULL;
	pthread_attr_t attr;

	int rc = 0;

	if ( !func ) {
		PKI_log_err("Missing Thread Main Function.");
		return NULL;
	}

	if(( th = PKI_Malloc ( sizeof( PKI_THREAD ))) == NULL ) {
		PKI_log_err("Memory Error");
		return NULL;
	}

	if((pthread_attr_init(&attr)) != 0 ) {
		PKI_log_debug("pthread_attr_init");
		PKI_Free ( th );
		return NULL;
	}

	if( (rc = PKI_THREAD_create( th, &attr, func, arg )) != 0 ) {
		PKI_log_err("Thread Create Error (%d)!", rc);
		PKI_Free ( th );
        return ( NULL );
    }

	pthread_attr_destroy(&attr);

	return th;
}

/*! \brief Returns the identifier for current thread */

PKI_THREAD_ID PKI_THREAD_self ( void ) {
#if (LIBPKI_OS_CLASS == WIN)
	return 1;
#else
	return pthread_self();
#endif
}
