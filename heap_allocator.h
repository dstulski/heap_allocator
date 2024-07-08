#ifndef HEAP_ALLOCATOR_H
#define HEAP_ALLOCATOR_H

#include <stddef.h>

void heap_init();

void *heap_alloc(size_t size);

void heap_free(void *ptr);

void *heap_realloc(void *ptr);

#endif 
