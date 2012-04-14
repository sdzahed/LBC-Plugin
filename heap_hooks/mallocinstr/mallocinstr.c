#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <malloc.h>
#include <fcntl.h>
#include <string.h>
#include <sys/stat.h>
#include <pthread.h>

#include "common.h"
#include "hashtable.h"
#include "mallocinstr.h"

void *(*__orig_malloc_hook) (size_t, const void*);
void (*__orig_free_hook) (void *, const void*);
void *(*__orig_realloc_hook) (void*, size_t, const void*);
void *(*__orig_memalign_hook) (size_t, size_t, const void*);

unsigned long total_malloc_size;
unsigned long total_free_size;
unsigned long max_allocated_size;

pthread_mutex_t mutex;

#define FILE_STR "FILE_MALLOC_INSTR"
char* filename = NULL;
int fd = 0;

//unsigned int count[10000];

#define SAVE_HOOKS() { \
		__orig_malloc_hook = __malloc_hook; \
		__orig_free_hook = __free_hook; \
		__orig_realloc_hook = __realloc_hook; \
		__orig_memalign_hook = __memalign_hook; \
}

#define UNSET_HOOKS() { \
		__malloc_hook = __orig_malloc_hook; \
		__free_hook = __orig_free_hook; \
		__realloc_hook = __orig_realloc_hook; \
		__memalign_hook = __orig_memalign_hook; \
}

#define SET_HOOKS() { \
		__malloc_hook = &mymalloc; \
		__free_hook = &myfree; \
		__realloc_hook = &myrealloc; \
		__memalign_hook = &mymemalign; \
}

#define GRAB_LOCK() {\
		if(pthread_mutex_lock(&mutex)) \
      MY_PRINTF(perror("\n Error: Grabbing a lock failed:")) \
}


#define RELEASE_LOCK() {\
		if(pthread_mutex_unlock(&mutex)) \
      MY_PRINTF(perror("\n Error: Releasing a lock failed:")) \
}

void __attribute__ ((constructor)) myinit(void)
{
		debug = (NULL != getenv(DEBUG_STR)) ? 1 : 0;
		filename = getenv(FILE_STR);

		init_hashtable();
		
		MY_PRINTF(printf("\n Initialising hooks...\n"))
		
		SAVE_HOOKS()
				
		SET_HOOKS()

		total_malloc_size = total_free_size = max_allocated_size = 0;

		if(pthread_mutex_init(&mutex, NULL))
				MY_PRINTF(perror("\n Error: Mutex initialization failed:"))
}

void* mymalloc(size_t size, const void* caller)
{
		GRAB_LOCK()

		UNSET_HOOKS()

		MY_PRINTF(printf("\n In mymalloc %u\n", size))
		
		void* res = LIBC_MALLOC(size);

		int ret = insert_addr(res, size);
		if(ret == -1)
				MY_PRINTF(fprintf(stderr, "\nError: Pointer to already allocated block allocated again.\n"))
		else {
				total_malloc_size += size;
				max_allocated_size = ((total_malloc_size - total_free_size) > max_allocated_size) ? 
						(total_malloc_size - total_free_size) : max_allocated_size;
		}

		SET_HOOKS()

		RELEASE_LOCK()

		return res;
}

void myfree(void* ptr, const void* caller)
{
		GRAB_LOCK()

		UNSET_HOOKS()

		MY_PRINTF(printf("\n In myfree\n"))

		LIBC_FREE(ptr);

		size_t size = get_size(ptr);
		if(size == (size_t) -1)	
			MY_PRINTF(fprintf(stderr, "\nError: Unallocated memory is being freed.\n"))
		else {
				total_free_size += size;
				max_allocated_size = ((total_malloc_size - total_free_size) > max_allocated_size) ? 
						(total_malloc_size - total_free_size) : max_allocated_size;

				free_addr(ptr);
		}

		SET_HOOKS()

		RELEASE_LOCK()
}

void* myrealloc(void* ptr, size_t size, const void* caller)
{
		GRAB_LOCK()

		UNSET_HOOKS()

		MY_PRINTF(printf("\n In myrealloc\n"))

		size_t orig_size = get_size(ptr);

		void* res = LIBC_REALLOC(ptr, size);

		int ret = update_addr(ptr, res, size);

		if(orig_size == (size_t) -1)	
			MY_PRINTF(fprintf(stderr, "\nError: Unallocated memory is being realloced.\n"))
		else if(ret == -1)
			MY_PRINTF(fprintf(stderr, "\nError: Updating the address %x in hashtable failed.\n", 
									(unsigned int) ptr))
		else {
				total_malloc_size += size;
				total_malloc_size -= orig_size;

				max_allocated_size = ((total_malloc_size - total_free_size) > max_allocated_size) ? 
						(total_malloc_size - total_free_size) : max_allocated_size;
		}

		SET_HOOKS()

		RELEASE_LOCK()

		return res;
}

void* mymemalign(size_t blksize, size_t size, const void* caller)
{
		GRAB_LOCK()

		UNSET_HOOKS()

		MY_PRINTF(printf("\n In mymemalign\n"))

		void* res = LIBC_MEMALIGN(blksize, size);

		int ret = insert_addr(res, size);
		if(ret == -1)
				MY_PRINTF(fprintf(stderr, "\nError: Pointer to already allocated block allocated again.\n"))
		else {
				total_malloc_size += size;
				max_allocated_size = ((total_malloc_size - total_free_size) > max_allocated_size) ? 
						(total_malloc_size - total_free_size) : max_allocated_size;
		}

		SET_HOOKS()

		RELEASE_LOCK()

		return res;
}

void __attribute__ ((destructor)) myfini(void)
{
		UNSET_HOOKS()

		MY_PRINTF(printf("\n Uninitialising hooks...\n"))

		free_table();

		if(filename) {
			if((fd = open(filename, O_WRONLY | O_CREAT | O_APPEND, 
											S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH)) == -1)
				MY_PRINTF(perror("\n Error opening file:"))
			else {
				char buf[256];
				memset(buf, 0, 256);
				sprintf(buf, "\n Total malloc size  : %ld" \
								     "\n Total free size    : %ld" \
										 "\n Max allocated size : %ld\n", 
										 total_malloc_size, total_free_size, 
										 max_allocated_size);
				if(write(fd, buf, strlen(buf)) == -1)
						MY_PRINTF(perror("\n Error: Write to the file failed:"))
				close(fd);
			}
		}

		if(pthread_mutex_destroy(&mutex))
				MY_PRINTF(perror("\n Error: Mutex destruction failed:"))
}
