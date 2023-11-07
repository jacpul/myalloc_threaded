#include <stdio.h>
#include <stdlib.h>
#include "myalloc.h"

/* change me to 1 for more debugging information
 * change me to 0 for time testing and to clear your mind
 */
#define DEBUG 1
void *__heap = NULL;
node_t *__head = NULL;

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
  node_t *cur = __head;
  node_t *sorted = NULL;

  while (cur != NULL) {
    node_t *next = cur->next;
    if (sorted == NULL || (char*)cur < (char*)sorted) {
      cur->next = sorted;
      sorted = cur;
    } else {
      node_t *sortedCur = sorted;
      while (sortedCur->next != NULL && (char*)sortedCur->next < (char*)cur) {
        sortedCur = sortedCur->next;
      }
      cur->next = sortedCur->next;
      sortedCur->next = cur;
    }
    cur = next;
  }

  __head = sorted; // Update the head of the free list
}

void coalesce_freelist() 
{
  node_t *current = __head;
  node_t *previous = NULL;

  sort_freelist();

  while (current != NULL) 
  {      
    if (previous != NULL && (char *)previous + previous->size + sizeof(header_t) == (char *)current)
    {
      // Merge the current block with the previous one
      previous->size += current->size + sizeof(node_t);
      previous->next = current->next;
      printf("Merge was successful\n");
    } 
    else 
    {
      // No coalescing occurred, move to the next block
      printf("Merge was unsuccessful\n");
      previous = current;

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

    while (listitem != NULL) 
    {
        // total size required
        size_t total_size_req = size_req + sizeof(header_t);

        if (listitem->size >= total_size_req) 
        { 
            size_t orig_size = listitem->size;

            printf("Block of right size found. Original size is: %lu\n", orig_size);

            // check if there is enough room for another allocation
            if (orig_size - total_size_req >= sizeof(node_t) - 16)
            {
                // split
                node_t *new_node = (node_t *)((char *)listitem + total_size_req);
                new_node->size = orig_size - total_size_req;
                new_node->next = listitem->next; // update the next pointer
                listitem->next = new_node; // update the next pointer 
                listitem->size = total_size_req - sizeof(node_t); // update the size 

                printf("New block size after split: %lu\n", new_node->size);
            } 
            else 
            {
              // no split occurs
              total_size_req = orig_size;  
              printf("Size after allocation: %lu\n", listitem->size);
            }

            // update pointers
            if (prev) 
            {
              prev->next = (orig_size == total_size_req) ? listitem->next : (node_t *)((char *)listitem + total_size_req);
            } 
            else 
            {
              __head = (orig_size == total_size_req) ? listitem->next : (node_t *)((char *)listitem + total_size_req);
            }

            // create and fill a new header
            header_t *alloc_header = (header_t *)listitem;
            alloc_header->size = size_req;
            alloc_header->magic = HEAPMAGIC; // Set the magic number for the allocated block

            printf("Returning allocated block @ %p\n", (char *)alloc_header + sizeof(header_t));

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

  size_t total_size = header->size + sizeof(header_t);
  node_t *new_node = (node_t *)header;
  new_node->size = total_size - sizeof(header_t);
  new_node->next = __head;

  // Update __head to point to the new free region
  __head = new_node;

  coalesce_freelist();

  if (DEBUG) printf("Freed and coalesced. __head is now @ %p\n", __head);
}