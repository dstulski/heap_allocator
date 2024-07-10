#include <assert.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

/* MACROS AND STRUCTS */

#define WORD_SIZE_BYTES 4
#define NUM_SIZE_CLASSES 8
#define WORDS_TO_BYTES(num_words) ((num_words) * WORD_SIZE_BYTES)

/* Doubly linked list node representing the head of a block */
typedef struct BlockMetadata {
	size_t num_words;
	int is_free;
	struct BlockMetadata *next,
				  *prev;
} BlockMetadata;

#define METADATA_SIZE sizeof(BlockMetadata)

/* Tail of an allocated block, used for merging */
typedef struct BlockTail {
	size_t num_words;
} BlockTail;

#define TAIL_SIZE sizeof(BlockTail)

/* Linked list node in the segmented free list */
typedef struct SizeClass {
	size_t max_words;
	BlockMetadata *first_block;
} SizeClass;

#define SIZE_CLASS_SIZE sizeof(SizeClass)

/* This will be used to search for nodes of a particular size */
SizeClass *size_classes[NUM_SIZE_CLASSES] = {NULL};

/* STATIC FUNCTION PROTOTYPES */

/*	Gets the metadata of a block from its tail
 *	
 *	Args:
 *		BlockTail *tail:
 *			tail of the block
 *
 *	Returns:
 *		BlockMetadata *:
 *			metadata of the block
 */
static inline BlockMetadata *get_meta_from_tail(BlockTail *tail);


/*	Gets the metadata of a block from its tail
 *	
 *	Args:
 *		BlockMetadata *meta:
 *			metadata of the block
 *
 *	Returns:
 *		BlockTail *:
 *			tail of the block
 */
static inline BlockTail *get_tail_from_meta(BlockMetadata *meta);

/*	Finds a sufficiently large size class for the query
 *	
 *	Args:
 *		size_t num_words:
 *			number of words in the block to be allocated
 *
 *	Returns:
 *		SizeClass *:
 *			size class that best matches the requested allocation
 */
static SizeClass *find_size_class(size_t num_words);

/*	Finds a free block with a sufficient
 *	
 *	Args:
 *		size_t num_words:
 *			number of words in the block to be allocated
 *
 *	Returns:
 *		BlockMetadata *:
 *			block matching the query
 */
static BlockMetadata *find_free_block(size_t num_words);

/*	Requests memory from the kernel in the event there are no available free blocks
 *	
 *	Args:
 *		size_t num_words:
 *			number of words in the block to be allocated
 *
 *	Returns:
 *		BlockMetadata *:
 *			pointer to the metadata of the newly allocated block
 */
static BlockMetadata *request_new_block(size_t num_words);

/*	Splits an allocated block such that the allocated portion is in the left part of the
 *	split and the unused (freed) portion of the block is in the right part of the split
 *
 *	Args:
 *		BlockMetadata *block:
 *			pointer to the block metadata of the block to be split
 *		size_t words_alloced:
 *			number of words allocated
 *
 *	Returns:
 *		BlockMetadata *:
 *			pointer to the allocated part (left) of the split
 */
static BlockMetadata *split_left(BlockMetadata *block, size_t words_alloced);

/*	Splits an allocated block such that the allocated portion is in the right part of the
 *	split and the unused (freed) portion of the block is in the left part of the split
 *
 *	Args:
 *		BlockMetadata *block:
 *			pointer to the block metadata of the block to be split
 *		size_t words_alloced:
 *			number of words allocated
 *
 *	Returns:
 *		BlockMetadata *:
 *			pointer to the allocated part (right) of the split
 */
static BlockMetadata *split_right(BlockMetadata *block, size_t words_alloced);

/*	Splits an allocated block and frees unneeded memory
 *
 *	Args:
 *		BlockMetadata *block:
 *			pointer to the block metadata of the block to be split
 *		size_t words_alloced:
 *			number of words allocated
 *
 *	Returns:
 *		BlockMetadata *:
 *			pointer to the allocated part of the split
 */
static BlockMetadata *split(BlockMetadata *block, size_t words_alloced);

/*	Coalesces (joins) a freed block to any adjacent free blocks
 *
 *	Args:
 *		BlockMetadata *block:
 *			block metadata of the block to be potentially joined to neighbors
 *
 *	Returns:
 *		BlockMetadata *:
 *			block metadata of the newly joined block
 */
static BlockMetadata *coalesce(BlockMetadata *block);

/* IMPLEMENTATION */

static inline BlockMetadata *get_meta_from_tail(BlockTail *tail)
{
	return (BlockMetadata *)((char *)tail - WORDS_TO_BYTES(tail->num_words) - METADATA_SIZE);
}

static inline BlockTail *get_tail_from_meta(BlockMetadata *meta)
{
	return (BlockTail *)((char *)meta + METADATA_SIZE + WORDS_TO_BYTES(meta->num_words));
}

static SizeClass *find_size_class(size_t num_words)
{
	assert(num_words <= size_classes[NUM_SIZE_CLASSES - 1]->max_words);

	SizeClass *class = NULL;
	for (size_t i = 0; i < NUM_SIZE_CLASSES; i++) {
		if (size_classes[i]->max_words >= num_words) {
			class = size_classes[i];
			break;
		}
	}

	assert(class != NULL);
	return class;
}

static BlockMetadata* find_free_block(size_t num_words)
{
	if (num_words > size_classes[NUM_SIZE_CLASSES - 1]->max_words) {
		fprintf(stderr, "Allocated block is too large!");
		exit(1);
	}

	for (size_t i = 0; i < NUM_SIZE_CLASSES; i++) {
		if (size_classes[i]->max_words >= num_words &&
				size_classes[i]->first_block != NULL) {
			return size_classes[i]->first_block;
		}
	}
	return NULL;
}

static BlockMetadata *request_new_block(size_t num_words)
{
	BlockMetadata *block = sbrk(0);
	void *request = sbrk(METADATA_SIZE + WORDS_TO_BYTES(num_words) + TAIL_SIZE);
	assert((void *)block == request);
	if (request == (void *)-1) {
		perror("sbrk failed");
		exit(1);
	}

	block->num_words = num_words;
	block->is_free = 0;
	block->next = NULL;
	block->prev = NULL;
	return block;
}

void heap_init(void)
{
	if (size_classes[0] != NULL) {
		fprintf(stderr,	"A heap allocator has already been initialized, doing nothing");
		return;
	}

	SizeClass *class = sbrk(0);
	void *request = sbrk(NUM_SIZE_CLASSES * SIZE_CLASS_SIZE);
	assert((void *)class == request);
	if (request == (void *)-1) {
		perror("sbrk failed");
		exit(1);
	}

	size_t size_buckets[NUM_SIZE_CLASSES] = {2, 3, 4, 8, 16, 32, 64, 128};

	for (size_t i = 0; i < NUM_SIZE_CLASSES; i++) {
		size_classes[i] = &class[i];
		size_classes[i]->max_words = size_buckets[i];
		size_classes[i]->first_block = NULL;
	}
}

void *heap_alloc(size_t size)
{
}

void heap_free(void *ptr)
{
	BlockMetadata *block = (BlockMetadata *)ptr - 1;

	SizeClass *class = find_size_class(block->num_words);
	block->is_free = 1;

	BlockMetadata *curr = class->first_block;
	if (curr == NULL) {
		class->first_block = block;
		block->next = NULL;
		block->prev = NULL;
		return;
	}

	/* iterate until a block with a larger address is found */
	while (curr->next != NULL && curr < block) {
		curr = curr->next;
	}

	/* modify pointers accordingly */
	if (curr > block) {
		block->next = curr;
		block->prev = curr->prev;
		curr->prev->next = block;
		curr->prev = block;
	} else {
		/* if free block has the largest address in the size class,
		 * we must be at the end of the list
		 */
		block->next = curr->next;
		block->prev = curr;
		curr->next = block;
	}
}
