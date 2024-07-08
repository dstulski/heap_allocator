#include <assert.h>
#include <unistd.h>

#include "heap_allocator.h"

#define NUM_SIZE_CLASSES 8
#define WORD_SIZE_BYTES 4

// defines a linked list node used for size class lookup
typedef struct size_class {
	int max_val; // upper bound for number of words in the size class
	void *first_block; // first block in the size class
} size_class;

// added at the beginning of each block to store metadata
typedef struct block_metadata {
	size_t size;
	int free;
	block_metadata *prev, *next;
} block_metadata;

#define METADATA_SIZE sizeof(block_metadata);

// segmented free list will be used for searching for free blocks
static size_class seg_free_list[NUM_SIZE_CLASSES];

void heap_init()
{
	// size classes based on number of bytes
	size_t size_buckets[NUM_SIZE_CLASSES] = {2, 3, 4, 8, 16, 32, 64, 128};

	for (size_t i = 0; i < NUM_SIZE_CLASSES; i++) {
		seg_free_list[i].max_val = size_buckets[i];
		seg_free_list[i].first_block = NULL;
	}
}

/*	Finds the smallest size class with a free block for the given size
 *
 *	Args:
 *		size_t size:
 *			size in bytes of the block to be allocated
 *
 *	Returns:
 *		block_metadata *:
 *			pointer to the block metadata if a candidate block is found,
 *			NULL otherwise
 */
static block_metadata *find_free_block(size_t size)
{
	for (size_t i = 0; i < NUM_SIZE_CLASSES; i++) {
		if (seg_free_list.max_val >= size && seg_free_list.first_block != NULL) {
			return &(seg_free_list[i].first_block);
		}
	}
	return NULL;
}

/*	Inserts a newly freed block into the segregated free list
 *
 *	Args:
 *		block_metadata *block:
 *			metadata of the block to be inserted
 */
static void insert_newly_freed(block_metadata* block)
{
	size_class *class = NULL;
	for (size_t i = 0; i < NUM_SIZE_CLASSES; i++) {
		if (seg_free_list.max_val >= block->size) {
			class = &seg_free_list[i];
			break;
		}
	}
	assert(class != NULL);
	
	block_metadata *curr = class->first_block;
	if (curr == NULL) {
		class->first_block = block;
		block->free = 1;
		block->prev = NULL;
		block->next = NULL;
		return;
	}
	while (curr != NULL && block_metadata < curr) {
		curr = curr->next;
	}
}

/*	Splits a block and adjusts size classes accordingly
 *
 *	Args:
 *		block_metadata *block:
 *			block to be split
 *		size_t size_alloced:
 *			size in bytes of the allocated part of the split
 */
static void split_block(block_metadata *block, size_t size_alloced)
{
	// TODO: split the block
	// TODO: put the free part of the block in the correct size class
}

/*	Allocates a free block
 *
 *	Args:
 *		block_metadata *block:
 *			metadata of the free block to be allocated
 *		size_t size_alloced:
 *			size in bytes of the data being allocated to the free block
 *
 *	Returns:
 *		block_metadata *:
 *			metadata of thenewly allocated block
 */
static block_metadata *allocate_block(block_metadata *block, size_t size_alloced)
{
	split_block(block, size_alloced);
	block->free = 0;
	block->size = size_alloced;
	return block;
}

/*	Gets more memory from the operating and allocates a block
 *	
 *	Args:
 *		size_t size_alloced:
 *			size in bytes of the new block to be allocated
 *
 *	Returns:
 *		block_metadata *:
 *			metadata of the newly allocated block
 */
static block_metadata *request_space(size_t size_alloced)
{
	struct block_meta *block;
	block = sbrk(0);
	void *request = sbrk(size + METADATA_SIZE);
	assert((void *)block == request);
	if (request == (void *) -1) {
		return NULL; // sbrk failed
	}
	block->size = size;
	block->free = 0;
	block->next = NULL;
	block->prev = NULL;
	return block;
}

void *heap_alloc(size_t size)
{
	assert(size <= size_buckets[NUM_SIZE_CLASSES - 1] * WORD_SIZE_BYTES);
	if (size == 0) {
		return NULL;
	}

	block_metadata *block = find_free_block(size);

	if (block_metadata == NULL) {
		return (void *)(request_space(size) + 1);
	}

	return (void *)allocate_block(block, size);
}

/*	Checks a block to see if it can be coalesced with adjacent blocks
 *
 *	Args:
 *		block_metadata* block:
 *			metadata of the block to be checked
 */
block_metadata *coalesce(block_metadata* block)
{
	// TODO: check metadata of blocks before and after and merge
}

void heap_free()
{
}
