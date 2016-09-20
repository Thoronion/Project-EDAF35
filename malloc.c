#include <unistd.h>
#include <string.h>

#include "malloc.h"

#define MIN_BLOCK_ORDER (6) //Minimum block size (2^MIN_BLOCK_ORDER) should not be smaller than 6
#define MAX_BLOCK_ORDER (25) //Maximum buffer size (2^MAX_BLOCK_ORDER)

#define MAX_BLOCK_SIZE (1 << MAX_BLOCK_ORDER)
#define MAX_BLOCK_LEVEL (MAX_BLOCK_ORDER - MIN_BLOCK_ORDER)

static char init = 0; //Indicates whether or not malloc has been called before
static void* start;   //Start of heap
static struct block_meta* freelist[MAX_BLOCK_LEVEL + 1];

struct block_meta{
  unsigned reserved:1;
  char kval;
  struct block_meta *next;
  struct block_meta *prev;
};

#define BLOCK_META_SIZE sizeof(struct block_meta)

/*
 * Calculates the block level nedded to store the requested data (n) allong with any block meta info
 */
static char calc_block_order(size_t n){
  
  n += BLOCK_META_SIZE;
  
  if ((n & (n-1))) {
    while(n & (n-1)) {
      n = n & (n-1);
    }
    n <<= 1;
  }  
  
  char kval = 1;
  
  while((n >>= 1) > 1)
    ++kval;
  
  return kval < MIN_BLOCK_ORDER ? 0 : kval - MIN_BLOCK_ORDER;
}

/*
 * Splits a block into two new blocks and puts them in the freelist
 * block must be removed from freelist before splitting
 */
static void split_block(struct block_meta* block){
  
  --block->kval;
  
  //Calculate buddy address
  size_t block_size = 1 << (MIN_BLOCK_ORDER + block->kval);
  char* buddy_address = ((char*) block) + block_size;
  struct block_meta* buddy = (struct block_meta*) buddy_address;
  
  //Set buddy attributes
  buddy->reserved = 0;
  buddy->kval = block->kval;
  
  block->reserved = 0;
  
  //Add block and buddy to freelist
  buddy->next = freelist[block->kval];
  buddy->prev = block; 
  block->next = buddy;
  block->prev = NULL;
  freelist[block->kval] = block;
  if(buddy->next)
    buddy->next->prev = buddy;
  
}

/*
 * Returns a free block of size kval
 * and removes it from the freelist
 * Returns NULL if no one is available
 */
static struct block_meta* get_block(char kval){
  
  struct block_meta* block = freelist[kval];
  
  if(!block)
    return NULL;
  
  freelist[kval] = block->next;
  
  if(block->next)
    freelist[kval]->prev = NULL;
  
  block->reserved = 1;
  
  return block;
}

/*
 * Finds a free block of size kval
 * If none is available it tries to split a larger block
 * to the requested size
 * Returns NULL if no block is available
 */
static struct block_meta* find_free_block(char kval){
  
  char temp_kval = kval;
  struct block_meta* block;
  
  //Go thorugh freelist until a suitable block is found
  while(!(block = get_block(temp_kval)) && temp_kval <= MAX_BLOCK_LEVEL)
    ++temp_kval;
  
  //If no suitable block was found return NULL
  if(temp_kval > MAX_BLOCK_LEVEL)
    return NULL;
  
  //Split the block as many times necessary
  while(block->kval > kval){
    split_block(block);
    block = get_block(block->kval);
  }
  
  return block;  
}

/*
 * Extends the heap
 */
int get_more_space(void){
  
  struct block_meta* block_meta = sbrk(0);
  
  if(sbrk(MAX_BLOCK_SIZE) == (void*) -1)
    return 0;
  
  block_meta->reserved = 0;
  block_meta->kval = MAX_BLOCK_LEVEL;
  block_meta->next = NULL;
  block_meta->prev = NULL;
  
  freelist[MAX_BLOCK_LEVEL] = block_meta;
  
  return 1;
}

/*
 * Malloc implementation using buddy system
 */
void* malloc(size_t size){
  
  //Check that size is between 0 and the maximum allowed size to allocate
  if(size == 0 || (size + BLOCK_META_SIZE) > MAX_BLOCK_SIZE)
    return NULL;
  
  //If malloc is called for the first time, store the starting point of the heap
  if(!init){
    start = sbrk(0);
    init = 1;
  }
  
  //Get the size of block needed to cover (size + block meta size)
  char kval = calc_block_order(size);
  
  //Check for an available block
  struct block_meta* block = find_free_block(kval);
  
  if(!block){
    //If no block was found, request more space from OS
    if(!get_more_space())
      return NULL;
    
    //Check again for an available block
    block = find_free_block(kval); 
  }
  
  return (block + 1);
}

/*
 * Get buddy. If there is no buddy,
 * or buddy is reserved or not the same size,
 * NULL is returned 
 */
static struct block_meta* get_buddy(struct block_meta* block){
  
  if(block->kval >= MAX_BLOCK_LEVEL)
    return NULL;
  
  //Get buddy
  size_t block_size = 1 << (MIN_BLOCK_ORDER + block->kval);
  char* buddy_address = ((char*) start) + (((char*) block) - ((char*) start) ^ block_size);
  struct block_meta* buddy = (struct block_meta*) buddy_address;
  
  //If buddy is reserved or not the same size return NULL  
  if(buddy->reserved || block->kval != buddy->kval)
    return NULL;
  
  return buddy;
}

/*
 * Removes a block from the freelist
 */
static void remove_block(struct block_meta* block){
  
  if(block->prev){
    block->prev->next = block->next; 
  }
  else{
    freelist[block->kval] = block->next;
  }
  
  if(block->next){
    block->next->prev = block->prev;    
  }
  
}

/*
 * Puts the block on the freelist
 */
static void put_block(struct block_meta* block){

  block->reserved = 0;
  block->next = freelist[block->kval];
  block->prev = NULL;
  if(block->next)
    block->next->prev = block;
  
  freelist[block->kval] = block;
}

/*
 * Merges two block together
 * It removes the buddy from freelist
 * Returns a reference to the merged block
 */
static struct block_meta* merge_blocks(struct block_meta* block, struct block_meta* buddy){
  
  remove_block(buddy);
  
  struct block_meta* merged_block = block < buddy ? block : buddy;

  ++merged_block->kval;
  
  return merged_block;
  
}

/*
 * Dealocates a block, i.e puts it on the freelist and merges if nessecary
 */
static void deallocate(struct block_meta* block){

  struct block_meta* buddy;
  if(!(buddy = get_buddy(block))){
    put_block(block);
    return;
  }
  block = merge_blocks(block, buddy);
  
  deallocate(block);
}

/*
 * Free implementation using buddy system
 */
void free(void* ptr){
  
  //If nullptr do nothing
  if(!ptr)
    return;
  
  //Get meta info
  struct block_meta* block = ((struct block_meta*) ptr) - 1;
  
  deallocate(block);
}

/*
 * Calloc implementation using buddy system
 */
void* calloc(size_t num, size_t size){
  
  if(size == 0 || num == 0)
    return NULL;
  
  size_t total_size = num * size;
  if(num != 0 && total_size / num != size) 
    return NULL;
  
  void* ptr = malloc(total_size);
  
  if(!ptr)
    return NULL;
  
  memset(ptr, 0, total_size);
  return ptr;
}

/*
 * Realloc implementation using buddy system
 */
void* realloc(void *ptr, size_t size) {
  
  if(!ptr) 
    return malloc(size);
  
  if(size == 0){
    free(ptr);
    return NULL;
  }
  
  struct block_meta* block = ((struct block_meta*) ptr) - 1;
  size_t block_size = 1 << (MIN_BLOCK_ORDER + block->kval);
  
  if((size + BLOCK_META_SIZE) <= block_size)
    return ptr; 
  
  void* new_ptr = malloc(size);
  if(!new_ptr)
    return NULL;
  
  memcpy(new_ptr, ptr, block_size);
  free(ptr);
  
  return new_ptr; 
}


