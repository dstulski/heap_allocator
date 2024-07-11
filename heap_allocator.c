#include <assert.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

/* MACROS AND STRUCTS */

#define SQUARE(x) (x * x)

#define WORD_SIZE_BYTES 4
#define NUM_SIZE_CLASSES 11
#define WORDS_TO_BYTES(num_words) ((num_words) * WORD_SIZE_BYTES)
#define BYTES_TO_WORDS(size) (size / WORD_SIZE_BYTES + (size % WORD_SIZE_BYTES != 0))

/* Doubly linked list node representing the head of a block */
typedef struct BlockMetadata {
	size_t num_words;
	int is_free;
	struct BlockMetadata *next,
				  *prev;
} BlockMetadata;

#define METADATA_SIZE sizeof(BlockMetadata)
#define METADATA_WORDS BYTES_TO_WORDS(METADATA_SIZE)

/* Tail of an allocated block, used for merging */
typedef struct BlockTail {
	size_t num_words;
} BlockTail;

#define TAIL_SIZE sizeof(BlockTail)
#define TAIL_WORDS BYTES_TO_WORDS(TAIL_SIZE)

#define BLOCK_SIZE_WORDS(block) METADATA_SIZE + block->num_words + TAIL_SIZE

#define CAN_BLOCK_DATA_FIT(num_words) (num_words >= METADATA_WORDS + TAIL_WORDS)

/* Linked list node in the segmented free list */
typedef struct SizeClass {
	size_t max_words;
	BlockMetadata *first_block;
} SizeClass;

#define SIZE_CLASS_SIZE sizeof(SizeClass)

/* This will be used to search for nodes of a particular size */
SizeClass *size_classes[NUM_SIZE_CLASSES] = {NULL};

#define MAX_WORDS size_classes[NUM_SIZE_CLASSES - 1]->max_words
#define HEAP_BOTTOM size_classes[NUM_SIZE_CLASSES - 1] + 1
#define HEAP_TOP sbrk(0)

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

/*	Removes a block with given address from the free list
 *
 *	Args:
 *		BlockMetadata *block:
 *			address of the block to be removed
 *
 */
static void free_list_remove(BlockMetadata *block);

/* IMPLEMENTATION */

static inline BlockMetadata *get_meta_from_tail(BlockTail *tail)
{
	return (BlockMetadata *)((char *)tail - WORDS_TO_BYTES(tail->num_words) - METADATA_SIZE);
}

static inline BlockTail *get_tail_from_meta(BlockMetadata *meta)
{
	return (BlockTail *)((char *)meta + METADATA_SIZE + WORDS_TO_BYTES(meta->num_words));
}

#define NEXT_BLOCK(block) (BlockMetadata *)(get_tail_from_meta(block) + 1)
#define PREV_BLOCK(block) get_meta_from_tail((BlockTail *)block - 1)

static SizeClass *find_size_class(size_t num_words)
{
	assert(num_words <= MAX_WORDS);

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

void heap_free(void *ptr) {
    if (ptr == NULL) {
        return;
    }

    BlockMetadata *block = (BlockMetadata *)ptr - 1;

    if (block->is_free) {
        fprintf(stderr, "Double free detected\n");
        return;
    }

    SizeClass *class = find_size_class(block->num_words);
    block->is_free = 1;

    BlockMetadata *curr = class->first_block;

    if (curr == NULL) {
        class->first_block = block;
        block->next = NULL;
        block->prev = NULL;
        return;
    }

	BlockMetadata *prev = curr->prev;
    while (curr != NULL && curr < block) {
		prev = curr;
        curr = curr->next;
    }

	if (curr != NULL) {
		block->next = curr;
		block->prev = curr->prev;
		curr->prev = block;
		if (curr->prev != NULL) {
			curr->prev->next = block;
		} else {
			class->first_block = block;
		}
	} else {
		prev->next = block;
		block->prev = prev;
	}
}

static BlockMetadata* find_free_block(size_t num_words)
{
	if (num_words > MAX_WORDS) {
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

static BlockMetadata *split_left(BlockMetadata *block, size_t words_alloced)
{
	size_t extra_words = block->num_words - words_alloced;
	if (CAN_BLOCK_DATA_FIT(extra_words)) {
		block->num_words = words_alloced;
		BlockTail *new_alloced_tail = get_tail_from_meta(block);
		new_alloced_tail->num_words = words_alloced;

		size_t free_words = extra_words - METADATA_WORDS - TAIL_WORDS;

		BlockMetadata *free_block_metadata = (BlockMetadata *)(new_alloced_tail + 1);
		free_block_metadata->num_words = free_words;

		BlockTail *free_block_tail = get_tail_from_meta(free_block_metadata);
		free_block_tail->num_words = free_words;

		if (free_block_metadata->num_words != 0) {
			heap_free(free_block_metadata + 1);
		} else {
			free_block_metadata->is_free = 1;
		}
	}
	return block;
}

static BlockMetadata *split_right(BlockMetadata *block, size_t words_alloced)
{
	size_t extra_words = block->num_words - words_alloced;
	if (CAN_BLOCK_DATA_FIT(extra_words)) {
		size_t free_words = extra_words - METADATA_WORDS - TAIL_WORDS;

		BlockTail *alloced_tail = get_tail_from_meta(block);
		alloced_tail->num_words = words_alloced;

		BlockMetadata *free_block_metadata = block;
		free_block_metadata->num_words = free_words;

		BlockTail *free_block_tail = get_tail_from_meta(free_block_metadata);
		free_block_tail->num_words = free_words;

		BlockMetadata *new_alloced_head = (BlockMetadata *)(free_block_tail + 1);
		new_alloced_head->num_words = words_alloced;
		new_alloced_head->is_free = 0;

		if (free_block_metadata->num_words != 0) {
			heap_free(free_block_metadata + 1);
		} else {
			free_block_metadata->is_free = 1;
		}
		// coalesce(free_block_metadata);
		return new_alloced_head;
	}
	return block;
}

static BlockMetadata *split(BlockMetadata *block, size_t words_alloced)
{

	if (block == HEAP_BOTTOM) {
		return split_left(block, words_alloced);
	}

	BlockMetadata *next_block = NEXT_BLOCK(block);

	if (next_block == HEAP_TOP) {
		return split_right(block, words_alloced);
	}

	BlockMetadata *prev_block = PREV_BLOCK(block);

	int left_is_larger_than_right = !next_block->is_free ||
		(prev_block->is_free &&
		 next_block->is_free &&
		 prev_block->num_words >= next_block->num_words);

	/* we want the free block in the left part of the split if there is a free block
	 * to the left of the current block that is larger than a free block to the right
	 * of the current block.
	 *
	 * this pattern ensures that if our split creates an opportunity for a merge, it will
	 * lead to a merge that is better for minimizing fragmentation
	 */
	if (left_is_larger_than_right) {
		return split_right(block, words_alloced);
	}
	return split_left(block, words_alloced);
}

static void free_list_remove(BlockMetadata *block)
{
	if (block->prev != NULL) {
		block->prev->next = block->next;
	} else {
		SizeClass *class = find_size_class(block->num_words);
		class->first_block = block->next;
	}
	if (block->next != NULL) {
		block->next->prev = block->prev;
	}
}

static BlockMetadata *coalesce(BlockMetadata *block)
{
	BlockMetadata *meta = block;
	BlockMetadata *next_block = NULL;
	BlockMetadata *prev_block = NULL;

	if (block != HEAP_BOTTOM) {
		prev_block = PREV_BLOCK(meta);
		if (prev_block->is_free) {
			BlockTail *tail = get_tail_from_meta(meta);
			meta = prev_block;

			size_t prev_block_num_words = BLOCK_SIZE_WORDS(prev_block);

			meta->num_words += prev_block_num_words;
			tail->num_words += prev_block_num_words;
		} else {
			prev_block = NULL;
		}
	}

	if (next_block != HEAP_TOP) {
		BlockMetadata *next_block = NEXT_BLOCK(meta);
		if (next_block->is_free) {
			BlockTail *tail = get_tail_from_meta(next_block);

			size_t block_num_words = BLOCK_SIZE_WORDS(meta);
			size_t next_block_num_words = BLOCK_SIZE_WORDS(next_block);

			meta->num_words += next_block_num_words;
			tail->num_words += block_num_words;
		} else {
			next_block = NULL;
		}
	}

	if (prev_block != NULL || next_block != NULL) {
		free_list_remove(block);
		if (prev_block != NULL) {
			free_list_remove(prev_block);
		}
		if (next_block != NULL) {
			free_list_remove(next_block);
		}
	}

	heap_free(meta + 1);
	return meta;
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

	size_t size_buckets[NUM_SIZE_CLASSES] = {2, 3, 4, 8, 16, 32, 64, 128, 256, 512, 1024};

	for (size_t i = 0; i < NUM_SIZE_CLASSES; i++) {
		size_classes[i] = &class[i];
		size_classes[i]->max_words = size_buckets[i];
		size_classes[i]->first_block = NULL;
	}
}

void *heap_alloc(size_t size)
{
	if (size == 0) {
		return NULL;
	}

	size_t num_words = BYTES_TO_WORDS(size);
	if (num_words > MAX_WORDS) {
		fprintf(stderr, "Allocation too large!");
		exit(1);
	}

	BlockMetadata *candidate_block = find_free_block(num_words);
	if (candidate_block == NULL) {
		return request_new_block(num_words) + 1;
	}

	assert(candidate_block->is_free == 1);
	free_list_remove(candidate_block);
	candidate_block->is_free = 0;
	return split(candidate_block, num_words) + 1;
}

void print_heap(void)
{
	for (size_t i = 0; i < NUM_SIZE_CLASSES; i++) {
		BlockMetadata *curr = size_classes[i]->first_block;
		printf("Size Class [%ld]", size_classes[i]->max_words);
		if (curr != NULL) {
			while (curr != NULL) {
				printf("| Words: %ld, Bytes: %ld, Address %p, Free %d | ", curr->num_words, WORDS_TO_BYTES(curr->num_words), curr, curr->is_free);
				curr = curr->next;
			}
		}
		printf("\n");
	}
	printf("-------------------------------------\n");
}
