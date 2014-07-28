/* Platform Independed Threads Management
 * (c) 2010 by Massimiliano Pala and OpenCA Labs
 * All Rights Reserved
 */

#include <libpki/pki.h>

/*
#ifndef REALTIME_CLOCK
#include <linux/time.h>
#endif
*/

/* ----------------------- R/W Locs Variables ---------------------------- */

/*! \brief Allocates a new R/W Lock and Initializes it */
PKI_RWLOCK * PKI_RWLOCK_new () {
	PKI_RWLOCK *l = NULL;

	if (( l = PKI_Malloc ( sizeof(PKI_RWLOCK))) == NULL ) {
		return NULL;
	}

	PKI_RWLOCK_init ( l );

	return l;
}

/*! \brief Initializes a R/W Lock */
int PKI_RWLOCK_init ( PKI_RWLOCK *l ) {

	if ( !l ) return PKI_ERR;

#if (LIBPKI_OS_CLASS == LIBPKI_OS_WIN)
	InizializeSRWLock(l);
#else
# ifdef HAVE_PTHREAD_RWLOCK
	pthread_rwlock_init(l, NULL );
# else
  pthread_mutex_init(&l->lock_mutex, NULL);
  pthread_mutex_init(&l->data_mutex, NULL);
  pthread_cond_init(&l->cond_var, NULL);

  l->n_readers = 0;
	l->n_writers = 0;
  l->n_writers_waiting = 0;
# endif /* HAVE_PTHREAD_RWLOCK */
#endif

	return PKI_OK;
}

/*! \brief Destroys a R/W Lock (needed before re-initialization) */
int PKI_RWLOCK_destroy ( PKI_RWLOCK *l ) {
	if( !l ) return PKI_ERR;
#if (LIBPKI_OS_CLASS == LIBPKI_OS_WIN)
	// NOP
#else
# ifdef HAVE_PTHREAD_RWLOCK
	pthread_rwlock_destroy ( l );
# else
  // TODO: Figure out what is needed here
# endif
#endif

	return PKI_OK;
}

/*! \brief Desroys a R/W lock and Frees its memory */
void PKI_RWLOCK_free ( PKI_RWLOCK *l ) {
	if ((!l) || PKI_RWLOCK_destroy(l) == PKI_ERR ) return;
	PKI_Free ( l );
	return;
}

/*! \brief Locks a R/W lock in READ mode (SHARED) */
int PKI_RWLOCK_read_lock ( PKI_RWLOCK *l ) {
	if (!l) return PKI_ERR;
#if (LIBPKI_OS_CLASS == LIBPKI_OS_WIN)
	AcquireSRWLockShared( l );
#else
# ifdef HAVE_PTHREAD_RWLOCK
	pthread_rwlock_rdlock( l );
# else
  pthread_mutex_lock(&l->lock_mutex);
  while (l->n_writers != 0)
	{
		pthread_cond_wait(&l->cond_var, &l->lock_mutex);
	}

  if (l->n_readers == 0)
  {
    pthread_mutex_unlock(&l->lock_mutex);
    pthread_mutex_lock(&l->data_mutex);
    pthread_mutex_lock(&l->lock_mutex);
    l->n_readers++;
    pthread_mutex_unlock(&l->lock_mutex);
  }
  else if (l->n_readers > 0)
  {
    l->n_readers++;
    pthread_mutex_unlock(&l->lock_mutex);
  }
# endif /* HAVE_PTHREAD_RWLOCK */
#endif
	return PKI_OK;
};

/*! \brief Locks a R/W lock in WRITE mode (Exclusive) */
int PKI_RWLOCK_write_lock ( PKI_RWLOCK *l ) {
	if (!l) return PKI_ERR;
#if (LIBPKI_OS_CLASS == LIBPKI_OS_WIN)
	AcquireSRWLockExclusive( l );
#else
# ifdef HAVE_PTHREAD_RWLOCK
	pthread_rwlock_wrlock ( l );
# else
  pthread_mutex_lock(&l->lock_mutex);
  l->n_writers_waiting++;
  while (l->n_readers != 0 && l->n_writers != 0)
  {
    pthread_cond_wait(&l->cond_var, &l->lock_mutex);
  }
  pthread_mutex_unlock(&l->lock_mutex);

  pthread_mutex_lock(&l->data_mutex);
  pthread_mutex_lock(&l->lock_mutex);
  l->n_writers_waiting--;
  l->n_writers--;
  pthread_mutex_unlock(&l->lock_mutex);

# endif /* HAVE_PTHREAD_RWLOCK */

#endif
	return PKI_OK;
};

int PKI_RWLOCK_try_read_lock ( PKI_RWLOCK *l ) {
	if ( !l ) return PKI_ERR;
#if (LIBPKI_OS_CLASS == LIBPKI_OS_WIN)
	/* Get the current state of the lock */
	void *state = *(void **) l;
	
	if (!state) {
		/* Unlocked to locked */
		if (!_InterlockedCompareExchangePointer((void *) l, 
			(void *)0x11, NULL)) return 0;
		return EBUSY;
	}
	
	/* A single writer exists */
	if (state == (void *) 1) return EBUSY;
	
	/* Multiple writers exist? */
	if ((uintptr_t) state & 14) return EBUSY;
	
	if (_InterlockedCompareExchangePointer((void *) l, 
			(void *) ((uintptr_t)state + 16), state) == state) return PKI_OK;
	
	return EBUSY;
#else
#ifdef HAVE_PTHREAD_RWLOCK
	return pthread_rwlock_tryrdlock( l );
#else
	return PKI_ERR;
#endif /* HAVE_PTHREAD_RWLOCK */

#endif
}

int PKI_RWLOCK_try_write_lock ( PKI_RWLOCK *l ) {
	if ( !l ) return PKI_ERR;
#if (LIBPKI_OS_CLASS == LIBPKI_OS_WIN)
	/* Try to grab lock if it has no users */
	if (!_InterlockedCompareExchangePointer((void *) l, 
		(void *)1, NULL)) return PKI_OK;
	
	return EBUSY;
#else
#ifdef HAVE_PTHREAD_RWLOCK
	return pthread_rwlock_trywrlock ( l );
#else
	return PKI_ERR;
#endif /* HAVE_PTHREAD_RWLOCK */

#endif
}


/*! \brief Release a PKI_RWLOCK */
int PKI_RWLOCK_release_read ( PKI_RWLOCK *l ) {
	if ( !l ) return PKI_ERR;
#if (LIBPKI_OS_CLASS == LIBPKI_OS_WIN)
	PKI_log_debug("PKI_RWLOCK_release()::TO BE DONE");
#else
# ifdef HAVE_PTHREAD_RWLOCK
	return pthread_rwlock_unlock ( l );
# else
  pthread_mutex_lock(&l->lock_mutex);
  l->n_readers--;
  if (l->n_readers == 0) pthread_mutex_unlock(&l->data_mutex);
  pthread_mutex_unlock(&l->lock_mutex);
  pthread_cond_signal(&l->cond_var);
# endif
#endif
  return PKI_OK;
}

/*! \brief Release a PKI_RWLOCK */
int PKI_RWLOCK_release_write ( PKI_RWLOCK *l ) {
	if ( !l ) return PKI_ERR;
#if (LIBPKI_OS_CLASS == LIBPKI_OS_WIN)
	PKI_log_debug("PKI_RWLOCK_release()::TO BE DONE");
#else
# ifdef HAVE_PTHREAD_RWLOCK
	return pthread_rwlock_unlock ( l );
# else
  pthread_mutex_lock(&l->lock_mutex);
  l->n_writers--;
  if (l->n_writers == 0) pthread_mutex_unlock(&l->data_mutex);
  pthread_mutex_unlock(&l->lock_mutex);
  pthread_cond_signal(&l->cond_var);
# endif

  return PKI_OK;
#endif
}

/* ------------------------- COND Variables ------------------------------ */

/*! \brief Creates a new Condition Variable used for thread management */
PKI_COND *PKI_COND_new () {
	PKI_COND *cond = NULL;

	if (( cond = PKI_Malloc ( sizeof ( PKI_COND ))) == NULL ) {
		return NULL;
	}

	PKI_COND_init ( cond );

	return cond;
};

/*! \brief Inizializes an already allocated (or destroyed) condition variable */
int PKI_COND_init ( PKI_COND *var ) {
	if(!var) return PKI_ERR;
#if (LIBPKI_OS_CLASS == LIBPKI_OS_WIN)
	return InitializeConditionVariable( var )
#else
	return pthread_cond_init( var, NULL );
#endif

	return PKI_OK;
}

/*! \brief Destroys (but do not free memory) a condition variable */
int PKI_COND_destroy ( PKI_COND *var ) {
	if(!var) return PKI_ERR;
#if (LIBPKI_OS_CLASS == LIBPKI_OS_WIN)
	// Nop
	return PKI_OK;
#else
	return pthread_cond_destroy( var );
#endif

}

/*! \brief Frees the memory associated with a Condition Variable */
void PKI_COND_free ( PKI_COND *var ) {
	if ( !var ) return;
#if (LIBPKI_OS_CLASS == LIBPKI_OS_WIN)
	// Nop
#else
	pthread_cond_destroy ( var );
#endif
	PKI_Free ( var );
	return;
};

/*! \brief Signal on a condition variable (wakes up the first waiting thread) */
int PKI_COND_signal ( PKI_COND *var ) {

	if ( !var ) return ( PKI_ERR );

#if (LIBPKI_OS_CLASS == LIBPKI_OS_WIN)
	return WakeConditionVariable ( var );
#else
	return pthread_cond_signal ( var );
#endif
};

/*! \brief Broadcasts on a condition variable (wakes up all waiting threads ) */
int PKI_COND_broadcast ( PKI_COND *var ) {
	if ( !var ) return ( PKI_ERR );
#if (LIBPKI_OS_CLASS == LIBPKI_OS_WIN)
	return WakeAllConditionVariable ( var );
#else
	return pthread_cond_broadcast ( var );
#endif
};

/*! \brief Waits on a condition variable */
int PKI_COND_wait ( PKI_COND *var, PKI_MUTEX *mutex ) {
	if ( !var || !mutex ) return PKI_ERR;
#if (LIBPKI_OS_CLASS == LIBPKI_OS_WIN)
	return SleepConditionVariableCS ( var, mutex, INFINITE );
#else
	return pthread_cond_wait ( var, mutex );
#endif
}

/*! \brief Waits on a condition variable for timespec time only */
int PKI_COND_timedwait ( PKI_COND *var, PKI_MUTEX *mutex, struct timespec *t ){
#if (LIBPKI_OS_CLASS == LIBPKI_OS_WIN)
	unsigned long long tm;

	tm = t->tv_sec * 1000 + t->tv_nsec / 1000000;

	if (!SleepConditionVariableCS( var, mutex, tm )) {
		return PKI_ERR;
	}
	if ( !_pthread_rel_time_in_ms(t)) {
		// Spourious Timeout
		return PKI_ERR;
	}
#else
	return pthread_cond_timedwait ( var, mutex, t );
#endif
}

/*! \brief Returns the current time in a timespec structure */

struct timespec * PKI_clock_gettime ( void ) {
	struct timespec *ts = NULL;

	if (( ts = PKI_Malloc ( sizeof( struct timespec ))) == NULL ) {
		return NULL;
	}
#if (LIBPKI_OS_CLASS == LIBPKI_OS_WIN)
	struct __timeb64 t;

	_ftime64(&t);

	ts->tv_sec = t.time; // secs
	ts->tv_nsec = t.millitm * 1000000; // nsecs

#elif (LIBPKI_OS_VENDOR == LIBPKI_OS_MACOS)
	// Needs to be Fixed!
	PKI_Free ( ts );
	return NULL;
#elif (IPHONE == 1)
	PKI_Free ( ts );
	return NULL;
#else
	clock_gettime(CLOCK_REALTIME, ts);
#endif

	return ts;
}

/* ------------------------------ MUTEXES  ------------------------------ */

/*! \brief Creates a mutex variable to be used for critical sections */
PKI_MUTEX * PKI_MUTEX_new () {
	PKI_MUTEX *var = NULL;

	if(( var = PKI_Malloc ( sizeof (PKI_MUTEX))) == NULL ) {
		return NULL;
	}

	PKI_MUTEX_init ( var );

	return (var);
};

/*! \brief Frees the memory associated with a PKI_MUTEX variable */
void PKI_MUTEX_free ( PKI_MUTEX *var ) {
	if (!var) return;

#if (LIBPKI_OS_CLASS == LIBPKI_OS_WIN)
	DeleteCriticalSection(var)
#else
	pthread_mutex_destroy( var );
#endif

	PKI_Free ( var );

	return;
};

/*! \brief Initializes an already allocated mutex structure */
int PKI_MUTEX_init ( PKI_MUTEX *var ) {
	if ( !var ) return PKI_ERR;
#if (LIBPKI_OS_CLASS == LIBPKI_OS_WIN)
	InitializeCriticalSection(var)
#else
	pthread_mutex_init( var, NULL );
#endif

	return PKI_OK;
};

/*! \brief Destroyes (but does not free the memory) a mutex structure */
int PKI_MUTEX_destroy ( PKI_MUTEX *var ) {
	if ( !var ) return PKI_ERR;
#if (LIBPKI_OS_CLASS == LIBPKI_OS_WIN)
	DeleteCriticalSection ( var );
#else
	pthread_mutex_destroy ( var );
#endif

	return PKI_OK;
};

/*! \brief Acquires access for a mutex */
int PKI_MUTEX_acquire ( PKI_MUTEX *var ) {
#if (LIBPKI_OS_CLASS == LIBPKI_OS_WIN)
	EnterCriticalSection(var);
#else
	pthread_mutex_lock( var );
#endif
	return PKI_OK;
};

/*! \brief Releases a mutex */
int PKI_MUTEX_release ( PKI_MUTEX *var ) {
#if (LIBPKI_OS_CLASS == LIBPKI_OS_WIN)
	LeaveCriticalSection(var);
#else
	pthread_mutex_unlock ( var );
#endif
	return PKI_OK;
};

