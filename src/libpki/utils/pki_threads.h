
#ifndef _LIBPKI_THREADS_
#define _LIBPKI_THREADS_

/* ------------------------ Generic Functions ---------------------- */

int PKI_THREAD_create ( PKI_THREAD *th, PKI_THREAD_ATTR *attr,
		void *(*func)(void *), void *arg );

PKI_THREAD *PKI_THREAD_new ( void * (*func)(void *arg), void *arg );

PKI_THREAD_ID PKI_THREAD_self ( void );

int PKI_THREAD_join(PKI_THREAD *th, void **retval);
int PKI_THREAD_terminate(PKI_THREAD *th);

void PKI_THREAD_exit(void *retval);

#endif
