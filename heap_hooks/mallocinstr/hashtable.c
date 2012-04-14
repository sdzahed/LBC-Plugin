#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "hashtable.h"
#include "common.h"

#define _1K 1024
#define _4K 4096

#define MASKUPPER10 0xFFC00000
#define UPPER10(addr)((addr & MASKUPPER10) >> 22)
#define MASKMIDDLE10 0x003FF000
#define MIDDLE10(addr)((addr & MASKMIDDLE10) >> 12)
#define MASKLOWER9 0x00000FF8
#define LOWER9(addr)((addr & MASKLOWER9) >> 3)

/*
  Hash table design
  =================
      
      -----------                                    NODE
    0 | NODE** --|--------->   --------------      --------    --------
      ------------           0 |  NODE *    | ---> | addr |--->| addr |--->NULL
    1 |          |             --------------      | size |    | size |    
      ------------           1 |  NODE *    |      --------    --------
    2 |          |             --------------
      ------------           2 |  NODE *    |
   .. |          |             --------------
      ------------          .. |  ...       |
   1K |          |             --------------
      ------------          1K |  ...       |
                               --------------

				1st table:                 2nd table:
		 statically allocated     dynamically allocated,
			                             on-demand

	Address division
	================

	------------------------------------------------------------
	| index into 1st table | index into 2nd table | Remaining  |
	------------------------------------------------------------
  31                     21                    11            0

	|<----- 10 bits ------->|<----- 10 bits ----->|<-12 bits -->|

	
	Design evaluation
	=================
	This design requires a static allocation of 4KB only. Rest of the memory is
	dynamically allocated.

*/

typedef struct node {
	size_t addr;
	size_t size;
	struct node *next;
} NODE;

NODE** allocSizeTbl[_1K];

void init_hashtable()
{
		memset(allocSizeTbl, 0, _1K * sizeof(NODE**));
}

static NODE* get_new_node(const void* addr, size_t size)
{
	NODE* ptr = (NODE*)LIBC_MALLOC(sizeof(NODE));
	ptr->addr = (size_t)addr;
	ptr->size = size;
	ptr->next = NULL;
	return ptr;
}

int insert_addr(const void* addr, size_t size)
{
	// get the index of first table
	unsigned int findex = UPPER10((unsigned int) addr);

	if(allocSizeTbl[findex] == NULL) {
			allocSizeTbl[findex] = (NODE**)LIBC_MALLOC(_1K*sizeof(NODE*));
			memset(allocSizeTbl[findex], 0, _1K*sizeof(NODE*));
	}

	// get the index of second table
	unsigned int sindex = MIDDLE10((unsigned int) addr);

	if(allocSizeTbl[findex][sindex] != NULL) {
		NODE* head = allocSizeTbl[findex][sindex];
		NODE* ptr = head;
		NODE* prev = NULL;
		
		while(ptr != NULL) {
			if(ptr->addr == (size_t) addr) {
				MY_PRINTF(fprintf(stderr, "Address %x already exists in hashtable.", (unsigned int) addr))
				return -1;
			}

			prev = ptr;
			ptr = ptr->next;
		}

		NODE* new = get_new_node(addr, size);
		prev->next = new;
	} else {
		NODE* ptr = get_new_node(addr, size);
		allocSizeTbl[findex][sindex] = ptr;
	}

	return 0;
}

size_t get_size(const void* addr)
{
	// get the index of first table
	unsigned int findex = UPPER10((unsigned int) addr);

	// get the index of second table
	unsigned int sindex = MIDDLE10((unsigned int) addr);

	if((allocSizeTbl[findex] == NULL) ||
		 (allocSizeTbl[findex][sindex] == NULL)) {
		MY_PRINTF(fprintf(stderr, "Address %x points to unallocated block.", (unsigned int) addr))
		return -1;
	}

	NODE* ptr = allocSizeTbl[findex][sindex];
	for(; ptr != NULL; ptr = ptr->next)
		if(ptr->addr == (size_t) addr)
			return ptr->size;

	MY_PRINTF(fprintf(stderr, "Address %x not found in the table.", (unsigned int) addr));
	return -1;
}

int update_addr(void* oldaddr, const void* newaddr, size_t newsize)
{
	if((unsigned int) oldaddr == (unsigned int) newaddr) {
		// get the index of first table
		unsigned int findex = UPPER10((unsigned int) oldaddr);

		// get the index of second table
		unsigned int sindex = MIDDLE10((unsigned int) oldaddr);

		if((allocSizeTbl[findex] == NULL) ||
		 	(allocSizeTbl[findex][sindex] == NULL)) {
			MY_PRINTF(fprintf(stderr, "Address %x points to unallocated block.", (unsigned int) oldaddr))
			return -1;
		}

		NODE* ptr = allocSizeTbl[findex][sindex];
		for(; ptr != NULL; ptr = ptr->next)
			if(ptr->addr == (size_t) oldaddr) {
				ptr->size = newsize;
				return 0;
			}

		MY_PRINTF(fprintf(stderr, "Address %x not found in the table.", (unsigned int) oldaddr));
		return -1;
	} else {
		free_addr(oldaddr);
		return insert_addr(newaddr, newsize);
	}

}

int free_addr(void* addr)
{
	// get the index of first table
	unsigned int findex = UPPER10((unsigned int) addr);

	// get the index of second table
	unsigned int sindex = MIDDLE10((unsigned int) addr);

	if((allocSizeTbl[findex] == NULL) ||
		 (allocSizeTbl[findex][sindex] == NULL)) {
		MY_PRINTF(fprintf(stderr, "Address %x points to unallocated block.", (unsigned int) addr))
		return -1;
	}

	NODE* ptr = allocSizeTbl[findex][sindex];
	NODE* prev = NULL;
	while(ptr != NULL) {
		if(ptr->addr == (size_t) addr) {
			// if ptr is the first node in the list
			if(ptr == allocSizeTbl[findex][sindex]) {
				allocSizeTbl[findex][sindex] = ptr->next;
				LIBC_FREE(ptr);
			} else {
				prev->next = ptr->next;
				LIBC_FREE(ptr);
			}
			return 0;
		}
		
		prev = ptr;
		ptr = ptr->next;
	}

	MY_PRINTF(fprintf(stderr, "Address %x not found in the table.", (unsigned int) addr));
	return -1;
}

static void free_list(NODE* head)
{
	NODE* ptr = head;
	NODE* next = NULL;

	while(ptr != NULL) {
		next = ptr->next;
		LIBC_FREE(ptr);
		ptr = next;
	}
}

void free_table()
{
	unsigned int i = 0;
	unsigned int j = 0;

	for(i = 0; i < _1K; i++) {
		if(allocSizeTbl[i] != NULL) {
			for(j = 0; j < _1K; j++) {
				if(allocSizeTbl[i][j] != NULL) {
					free_list(allocSizeTbl[i][j]);
					allocSizeTbl[i][j] = NULL;
				}
			}
			LIBC_FREE(allocSizeTbl[i]);
			allocSizeTbl[i] = NULL;
		}
	}
}
