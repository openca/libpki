/* src/stack.c */
/*
 * ====================================================================
 * 
 * General STACK routines
 * by Massimiliano Pala (madwolf@openca.org)
 * OpenCA Licensed Software
 *
 * Copyright (c) 2001-2013 by Massimiliano Pala and OpenCA Labs.
 * All rights reserved.
 *
 * ====================================================================
 *
 */

#include <stdlib.h>
#include <compat.h>
#include <libpki/stack.h>
#include <pki.h>

static PKI_STACK_NODE * _PKI_STACK_NODE_new( void *data )
{
	PKI_STACK_NODE *ret = NULL;

	if ((ret = (PKI_STACK_NODE *) PKI_Malloc(sizeof(PKI_STACK))) == NULL)
	{
		PKI_ERROR(PKI_ERR_MEMORY_ALLOC, NULL);
		return(NULL);
	}

	ret->next = NULL;
	ret->prev = NULL;
	ret->data = data;

	return (ret);
}

static int _PKI_STACK_NODE_free(PKI_STACK_NODE *n)
{
	if (!n) return (PKI_STACK_ERR);

	PKI_Free(n);

	return(0);
}

/*!
 * \brief PKI_STACK initialization function
 *
 * This function allocates the memory for a PKI_STACK structure. It also
 * initializes the internal fields. It returns the pointer to the allocated
 * data structure. In case of error the returned value is NULL.
*/

PKI_STACK * PKI_STACK_new( void (*free)())
{
	PKI_STACK *ret = NULL;

	if((ret = (PKI_STACK *) PKI_Malloc (sizeof(PKI_STACK))) == NULL)
	{
		return(NULL);
	}

	ret->head = NULL;
	ret->tail = NULL;
	ret->elements = 0;

	if (ret->free) ret->free = free;
	else ret->free = PKI_Free;

	return(ret);
}

PKI_STACK *PKI_STACK_new_type ( PKI_DATATYPE type ) {

	const PKI_X509_CALLBACKS *cb = NULL;

	if ((cb = PKI_X509_CALLBACKS_get(type, NULL)) == NULL)
	{
		return PKI_STACK_new( NULL );
	}

	return PKI_STACK_new(cb->free);
}

PKI_STACK * PKI_STACK_new_null( void ) {
	
	return ( PKI_STACK_new( NULL ));
}

/*!
 * \brief PKI_STACK free all function
 *
 * This function frees the memory used by a PKI_STACK structure.
 * If the structure is not empty, the pointers to every node are freed,
 * but the pointers to the actualy DATA are not freed. If you want to
 * completely clean up memorty, use the PKI_STACK_free_all().
 *
 * You can also use the PKI_STACK_pop() function and free the elements
 * by using the appropriate function (e.g., PKI_X509_CERT_free() if it
 * is a stack of certificates).
*/
int PKI_STACK_free (PKI_STACK * st)
{
	void * data = NULL;

	if (st == NULL)
	{
		PKI_ERROR(PKI_ERR_PARAM_NULL, NULL);
		return(PKI_STACK_ERR);
	}

	data = PKI_STACK_pop(st);
	while (data != NULL)
	{
		data = PKI_STACK_pop(st);
	}

	PKI_Free ( st );

	return PKI_OK;
}

/*!
 * \brief Frees memory associated with a PKI_STACK
 *
 * This function frees the memory used by a PKI_STACK structure.
 * If the structure is not empty, the pointers to every node are freed,
 * If the type of data within the STACK is not known to the
 * stack itself, it is suggested that you use the PKI_STACK_pop() function
 * and free the elements by using the appropriate function.
*/

int PKI_STACK_free_all (PKI_STACK * st)
{
	PKI_STACK_NODE *n = NULL;
	PKI_STACK_NODE *nn = NULL;

	// Input check
	if (!st) return PKI_ERR;

	// Let's start from the head
	n = st->head;

	// Checks we have the free function
	// set. If not, report the possible
	// memory loss
	if (st->free == NULL) {
		PKI_log_debug("Missing free function for the stack!");
	}

	// Cycle until we process all nodes
	while (n != NULL)
	{
		// Let's free the current node's data
		if (n->data && st->free)
		{
			(st->free) (n->data);
			n->data = NULL; // Safety
		}

		// Let's get the pointer to the next node
		nn = n->next;

		// Now we free the current node's structure
		PKI_Free( n );

		// Move to the next node
		n = nn;
	}

	// Let's free the PKI_STACK data structure's memory
	PKI_Free(st);

	return PKI_OK;
}

/*!
 * \brief Pops the last element in PKI_STACK
 *
 * This function returns the data pointed by the last element of a PKI_STACK
 * and frees the internal memory. The calling program will have to free the
 * memory related to the returned pointer.
 */

void * PKI_STACK_pop ( PKI_STACK *st ) {

	PKI_STACK_NODE *n = NULL;
	void *data = NULL;

	// Checks the input
	if((st == NULL) || ( st->tail == NULL)) return NULL;

	// Get the last node of the structure
	n = st->tail;

	// Let's update the tail pointers
	st->tail = n->prev;

	// Let's check if the node we popped was also the head
	if (st->head == n)
	{
		// We are actually emptying the list
		st->elements = 0;
		st->head = NULL;
	}
	else
	{
		// Updates the number of elements
		st->elements--;
	}

	// Let's save the data pointer (we will return that)
	data = n->data;
	n->data = NULL; // Safety

	// Now let's free the node data structure
	PKI_Free(n);

	// We return the data from the freed node
	return data;
}

/*!
 * \brief Pops the last element in PKI_STACK and frees the object data
          (when the free function pointer is provided).
 *
 * This function returns the data pointed by the last element of a PKI_STACK
 * and frees the internal memory. If the PKI_STACK->free function pointer is
 * provided when created (PKI_STACK_new) the associated object is automatically
 * freed, otherwise the calling program will have to free the memory related
 * to the returned pointer.
*/

int PKI_STACK_pop_free ( PKI_STACK *st )
{
	void * data = NULL;

	// Gets the data
	data = PKI_STACK_pop(st);

	// If we retrieved the data, let's free
	// its content
	if (data != NULL && st->free != NULL)
	{
		// Use the function pointer to free the memory
		(st->free)(data);
	}

	return PKI_STACK_OK;
}


/*!
 * \brief Adds a new element to a PKI_STACK

 * It adds a general pointer to an already initialized PKI_STACK structure.
 * In case of success it returns the number of elements in the stack after
 * the new insertion. Otherwise it returns PKI_STACK_ERR.
 */
int PKI_STACK_push(PKI_STACK *st, void *obj)
{
	PKI_STACK_NODE *n = NULL;

	if (st == NULL || obj == NULL)
	{
		PKI_ERROR(PKI_ERR_PARAM_NULL, NULL);
		return(PKI_STACK_ERR);
	}

	if((n = _PKI_STACK_NODE_new(obj)) == NULL)
	{
		PKI_ERROR(PKI_ERR_MEMORY_ALLOC, NULL);
		return(PKI_STACK_ERR);
	}

	if (st->tail)
	{
		n->prev = st->tail;
		n->next = NULL;

		st->tail->next = n;
		st->tail = n;
	}
	else
	{
		st->tail = n;
		st->head = n;
	}

	st->elements++;

	return(st->elements);
}

/*!
 * \brief Returns the number of elements in a PKI_STACK
 *
 * This function returns the number of elements stored in a PKI_STACK.
 */
int PKI_STACK_elements(PKI_STACK *st)
{
	if (st == NULL) return -1;

	return st->elements;
}

/*!
 * \brief Returns data stored in the n-th element of the PKI_STACK
 *
 * Use this function to retrieve data from a specific element of the PKI_STACK.
 * The returned pointer points to the data stored in the PKI_STACK node,
 * therefore it is not advisable to free the returned memory. You should use
 * the PKI_STACK_del_num() function to detatch the data from the PKI_STACK.
 * The function returns the pointer to the requested data, in case of error
 * it returns NULL.
 */
void * PKI_STACK_get_num(PKI_STACK *st, int num)
{
	PKI_STACK_NODE *n;
	int i;

	if ((st == NULL) || (st->elements < num)) return NULL;

	i = 0;
	n = st->head;

	while (n)
	{
		if (i == num) return n->data;
		n=n->next;
		i++;
	}

	return NULL;
}

/*!
 * \brief Inserts a new element in a PKI_STACK at a specific position
 *
 * Use this function to insert an element into a PKI_STACK at a specific
 * position.
 *
 * If successful the function returns PKI_STACK_OK, otherwise it returns
 * PKI_STACK_ERR in case of error.
 */

int PKI_STACK_ins_num ( PKI_STACK *st, int num, void *obj )
{
	PKI_STACK_NODE *n = NULL;
	PKI_STACK_NODE *new_n = NULL;

	int i;

	if ((st == NULL) || (num > st->elements) || (obj == NULL ))
	{
		PKI_ERROR(PKI_ERR_PARAM_NULL, NULL);
		return PKI_STACK_ERR;
	}

	n = st->head;
	i = 0;
	while (n)
	{
		if (i == num) break;
		if (i > num) return PKI_STACK_ERR;

		n = n->next;
		i++;
	}

	if ((new_n = _PKI_STACK_NODE_new ( obj )) == NULL)
	{
		return PKI_STACK_ERR;
	}

	new_n->next = n;

	if (n) {
		new_n->prev = n->prev;
		n->prev = new_n;
	} 


	if (num == 0)
	{
		st->head = new_n;
	}
	else
	{
		new_n->prev->next = new_n;
	}

	st->elements++;
	
	return PKI_STACK_OK;
}

/*!
 * \brief Pops a specific data element from a PKI_STACK
 *
 * This function detatches a specific element of a PKI_STACK and returns the
 * pointer to the associated data. The data is now no more linked in the
 * PKI_STACK and memory management is up to the calling application (i.e., the
 * calling application can now free the memory by calling the appropriate
 * function depending on the type of data structure).
 *
 * The function returns the pointer to the data. In case of error, it returns
 * NULL.
 */
void * PKI_STACK_del_num ( PKI_STACK *st, int num ) {
	PKI_STACK_NODE *tmp_n = NULL;
	PKI_STACK_NODE *n = NULL;

	int i;
	void *obj = NULL;

	if( st == NULL ) return (NULL);

	tmp_n = st->head; i = 0;
	while ( tmp_n ) {
		if ( i == num ) {
			n = tmp_n;
			break;
		}
		i++;
		tmp_n = tmp_n->next;
	}
	if( n == NULL) return( NULL);

	if( n->prev != NULL ) {
		n->prev->next = n->next;
	}

	if( n->next ) {
		n->next->prev = n->prev;
	}

	if( num == 0 ) {
		st->head = n->next;
	}

	if( num == PKI_STACK_elements( st ) ) {
		st->tail = n->prev;
	}

	obj = n->data;

	_PKI_STACK_NODE_free( n );
	st->elements--;
	
	return(obj);
}


