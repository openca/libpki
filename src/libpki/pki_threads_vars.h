
#ifndef _LIBPKI_THREADS_VARS_
#define _LIBPKI_THREADS_VARS_

#include <libpki/os.h>

/* ------------------------ Generic Functions ---------------------- */

struct timespec * PKI_clock_gettime ( void );

/* ----------------------- R/W Locs Variables ---------------------------- */

PKI_RWLOCK * PKI_RWLOCK_new ();
void PKI_RWLOCK_free ( PKI_RWLOCK *l );

int PKI_RWLOCK_init ( PKI_RWLOCK *l );
int PKI_RWLOCK_destroy ( PKI_RWLOCK *l );

int PKI_RWLOCK_read_lock ( PKI_RWLOCK *l );
int PKI_RWLOCK_write_lock ( PKI_RWLOCK *l );
#ifdef HAVE_PTHREAD_RWLOCK
int PKI_RWLOCK_try_read_lock ( PKI_RWLOCK *l );
int PKI_RWLOCK_try_write_lock ( PKI_RWLOCK *l );
#endif

int PKI_RWLOCK_release_read ( PKI_RWLOCK *l );
int PKI_RWLOCK_release_write ( PKI_RWLOCK *l );

/* --------------------- CONDITION VARIABLES ----------------------- */

PKI_COND *PKI_COND_new ();
void PKI_COND_free ( PKI_COND *var );

int PKI_COND_init ( PKI_COND *var );
int PKI_COND_destroy ( PKI_COND *var );

int PKI_COND_signal ( PKI_COND *var );
int PKI_COND_broadcast ( PKI_COND *var );
int PKI_COND_wait ( PKI_COND *var, PKI_MUTEX *mutex );

/* --------------------------- MUTEXES ------------------------------ */

PKI_MUTEX * PKI_MUTEX_new ();
void PKI_MUTEX_free ( PKI_MUTEX *var );

int PKI_MUTEX_init ( PKI_MUTEX *var );
int PKI_MUTEX_destroy ( PKI_MUTEX *var );

int PKI_MUTEX_acquire ( PKI_MUTEX *var );
int PKI_MUTEX_release ( PKI_MUTEX *var );

#endif
