#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <malloc.h>
#include <fcntl.h>
#include <string.h>
#include <sys/stat.h>
#include <pthread.h>

#include "mallocinstr.h"

void *(*__orig_malloc_hook) (size_t, const void*);
void (*__orig_free_hook) (void *, const void*);
void *(*__orig_realloc_hook) (void*, size_t, const void*);
void *(*__orig_memalign_hook) (size_t, size_t, const void*);

pthread_mutex_t mutex;

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
		__malloc_hook = &LBC_MALLOC; \
		__free_hook = &LBC_FREE; \
		__realloc_hook = &LBC_REALLOC; \
		__memalign_hook = &LBC_MEMALIGN; \
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
		
		MY_PRINTF(printf("\n Initialising hooks...\n"))
		
		SAVE_HOOKS()

		if(pthread_mutex_init(&mutex, NULL))
				MY_PRINTF(perror("\n Error: Mutex initialization failed:"))
				
		GRAB_LOCK()
		SET_HOOKS()
		RELEASE_LOCK()
		MY_PRINTF(printf("\n Done setting the hooks...\n"))
}

void __attribute__ ((destructor)) myfini(void)
{
		UNSET_HOOKS()

		MY_PRINTF(printf("\n Uninitialising hooks...\n"))

		if(pthread_mutex_destroy(&mutex))
				MY_PRINTF(perror("\n Error: Mutex destruction failed:"))

		MY_PRINTF(printf("\n Done Uninitialising hooks...\n"))
}



void* mymalloc(size_t size, const void* caller)
{
		MY_PRINTF(printf("\n In mymalloc %u\n", size))
		
		void* res = LBC_MALLOC(size);

		return res;
}

void myfree(void* ptr, const void* caller)
{
		MY_PRINTF(printf("\n In myfree\n"))

		LBC_FREE(ptr);
}

void* myrealloc(void* ptr, size_t size, const void* caller)
{
		MY_PRINTF(printf("\n In myrealloc\n"))

		void* res = LIBC_REALLOC(ptr, size);

		return res;
}

void* mymemalign(size_t blksize, size_t size, const void* caller)
{
		MY_PRINTF(printf("\n In mymemalign\n"))

		void* res = LIBC_MEMALIGN(blksize, size);

		return res;
}

