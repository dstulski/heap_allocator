#ifndef HEAP_ALLOCATOR_H
#define HEAP_ALLOCATOR_H

#include <stddef.h>

/*	Initializes the heap allocator
 */
void heap_init(void);

/*	Allocates memory to the heap
 *
 *	Args:
 *		size_t size:
 *			size of the allocated memory in byts
 *
 *	Returns:
 *		void *:
 *			pointer to the allocated memory
 */
void *heap_alloc(size_t size);

/*	Frees previously allocated memory
 *	
 *	Args:
 *		void *ptr:
 *			pointer to the allocated memory to be freed
 */
void heap_free(void *ptr);

#endif
