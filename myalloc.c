#include <stdio.h>
#include <stdlib.h>
#include "myalloc.h"
#include <pthread.h>

/* change me to 1 for more debugging information
 * change me to 0 for time testing and to clear your mind
 */
#define DEBUG 1
void *__heap = NULL;
node_t *__head = NULL;
pthread_mutex_t lock = PTHREAD_MUTEX_INITIALIZER;

header_t *get_header(void *ptr) {
  return (header_t *) (ptr - sizeof(header_t));
}

void print_header(header_t *header) {
  printf("[header_t @ %p | buffer @ %p size: %lu magic: %08lx]\n",
         header,
         ((void *) header + sizeof(header_t)),
         header->size,
         header->magic);
}

void print_node(node_t *node) {
  printf("[node @ %p | free region @ %p size: %lu next: %p]\n",
         node,
         ((void *) node + sizeof(node_t)),
         node->size,
         node->next);
}

void print_freelist_from(node_t *node) {
  printf("\nPrinting freelist from %p\n", node);
  while (node != NULL) {
    print_node(node);
    node = node->next;
  }
}

void sort_freelist() {

  if (!__head || !__head->next) {
        return;  
  }

  int swapped;
  node_t *ptr;
  node_t *lptr = NULL;


 do {
  swapped = 0;
  ptr = __head;

  while (ptr->next != lptr) {
    if (ptr > ptr->next) {
      // Swap the nodes (not the actual memory, just the nodes in our list)
      node_t *temp = ptr->next;
      ptr->next = ptr->next->next;
      temp->next = ptr;

      // Fix the previous node's next pointer
      if (ptr == __head) {
        __head = temp;
      } 
      else
      {
        node_t *prev = __head;
        while (prev->next != ptr) {
          prev = prev->next;
        }
        prev->next = temp;
        }

        swapped = 1;
        } else {
          ptr = ptr->next;
          }
        }

        lptr = ptr;
    } 
    while (swapped);
}

void coalesce_freelist() 
{
  node_t *current = __head;

  while (current != NULL && current->next != NULL) {
    char *current_end = (char *)current + sizeof(node_t) + current->size;
    print_node(current);
    if (current_end == (char *)current->next) {
      // Merge the current block with the previous one
      current->size += sizeof(node_t) + current->next->size; 
      current->next = current->next->next; 
      printf("Merge was successful\n");
      continue;
    } 
    current = current->next;
  }
}

void destroy_heap() {
  /* after calling this the heap and free list will be wiped
   * and you can make new allocations and frees on a "blank slate"
   */
  free(__heap);
  __heap = NULL;
  __head = NULL;
}

/* In reality, the kernel or memory allocator sets up the initial heap. But in
 * our memory allocator, we have to allocate our heap manually, using malloc().
 * YOU MUST NOT ADD MALLOC CALLS TO YOUR FINAL PROGRAM!
 */
void init_heap() {
  /* FOR OFFICE USE ONLY */

  if ((__heap = malloc(HEAPSIZE)) == NULL) {
    printf("Couldn't initialize heap!\n");
    exit(1);
  }

  __head = (node_t *) __heap;
  __head->size = HEAPSIZE - sizeof(header_t);
  __head->next = NULL;

  if (DEBUG) printf("heap: %p\n", __heap);
  if (DEBUG) print_node(__head);

}

void *first_fit(size_t size_req) {
  
    node_t *prev = NULL;
    node_t *listitem = __head;

    node_t *new_node;

    while (listitem != NULL) 
    {
      printf("[node @ %p | free region @ %p size: %lu next: %p]\n", listitem, (char *)listitem + sizeof(node_t), listitem->size, listitem->next);
      if (listitem->size >= size_req) {
                
        size_t orig_size = listitem->size; 
        if (listitem->size - size_req >= sizeof(header_t) ) {
          // Splitting Logic
          new_node = (node_t *)((char *)listitem + size_req + sizeof(header_t));
          new_node->size = orig_size - size_req - sizeof(header_t); 
          new_node->next = listitem->next; 
          listitem->size = size_req; 
          printf("[node @ %p | free region @ %p size: %lu next: %p]\n", listitem, (char *)listitem + sizeof(node_t), listitem->size, listitem->next);
          printf("Splitting block. New block size: %lu\n", new_node->size);
        }
          else 
        {
          size_req = orig_size;  // Don't split the block (use whole block)
                
          printf("Not splitting block. Size after allocation: %lu\n", listitem->size);
        }

        // update pointers
        if (prev) {
          prev->next = (orig_size == size_req) ? listitem->next : new_node;
        } else {
          __head = (orig_size == size_req) ? listitem->next : new_node;
        }

        // create and fill a new header
        header_t *alloc_header = (header_t *)listitem;
        alloc_header->size = size_req;
        alloc_header->magic = HEAPMAGIC; // Set the magic number for the allocated block
        printf("Allocation header filled with magic: %08lx\n", alloc_header->magic);

        printf("Returning allocated block @ %p\n", (char *)alloc_header + sizeof(header_t));

        print_freelist_from(__head);
        return (char *)alloc_header + sizeof(header_t);
      }

        prev = listitem;
        listitem = listitem->next;
    }

    printf("No block fits.\n");
    return NULL;
}

void *myalloc(size_t size) {
  if (DEBUG) printf("\nIn myalloc:\n");
  void *ptr = NULL;

  /* initialize the heap if it hasn't been */
  if (__heap == NULL) {
    if (DEBUG) printf("*** Heap is NULL: Initializing ***\n");
    init_heap();
  }

  /* perform allocation */
  /* search __head for first fit */
  if (DEBUG) printf("Going to do allocation.\n");

  ptr = first_fit(size); /* all the work really happens in first_fit */

  if (DEBUG) printf("__head is now @ %p\n", __head);

  return ptr;

}

/* myfree takes in a pointer _that was allocated by myfree_ and deallocates it,
 * returning it to the free list (__head) like free(), myfree() returns
 * nothing.  If a user tries to myfree() a buffer that was already freed, was
 * allocated by malloc(), or basically any other use, the behavior is
 * undefined.
 */
void myfree(void *ptr) {
  if (DEBUG) printf("\nIn myfree with pointer %p\n", ptr);

  header_t *header = get_header(ptr);

  if (DEBUG) { print_header(header); }

  if (header->magic != HEAPMAGIC) {
    printf("Header is missing its magic number!!\n");
    printf("It should be '%08lx'\n", HEAPMAGIC);
    printf("But it is '%08lx'\n", header->magic);
    printf("The heap is corrupt!\n");
    return;
  }

    // Convert the allocated block to a node_t so it can be added to the free list
    node_t *freed_block = (node_t *)header;

    // Adjust the size for the free block to include the header's size
    freed_block->size = header->size;

    // Attach the freed block to the beginning of the list
    freed_block->next = __head;
    __head = freed_block;

    sort_freelist();
    //coalesce_freelist();
}