#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <malloc.h>
#include <fcntl.h>
#include <string.h>
#include <sys/stat.h>
#include <pthread.h>
#include <dlfcn.h>

unsigned int debug = 1;
#define DEBUG(stmt){if(debug) stmt;}

struct libc_calls
{
        void *(*malloc)(size_t size);
        void (*free)(void *ptr);
        void *(*realloc)(void *ptr, size_t size);
        void *(*memalign)(size_t boundary, size_t size);
}libc_call;

void __attribute__ ((constructor)) myinit(void)
{
	char *error;
	void *handle;
        DEBUG(printf("Initialising hooks ...\n"));

        *(void **) (&(libc_call.malloc)) = dlsym(RTLD_NEXT, "malloc");

        if ((error = dlerror()) != NULL)  {
                fprintf(stderr, "%s\n", error);
                exit(EXIT_FAILURE);
        }

        *(void **) (&(libc_call.free)) = dlsym(RTLD_NEXT, "free");

        if ((error = dlerror()) != NULL)  {
                fprintf(stderr, "%s\n", error);
                exit(EXIT_FAILURE);
        }
        *(void **) (&(libc_call.realloc)) = dlsym(RTLD_NEXT, "realloc");

        if ((error = dlerror()) != NULL)  {
                fprintf(stderr, "%s\n", error);
                exit(EXIT_FAILURE);
        }
        *(void **) (&(libc_call.memalign)) = dlsym(RTLD_NEXT, "memalign");

        if ((error = dlerror()) != NULL)  {
                fprintf(stderr, "%s\n", error);
                exit(EXIT_FAILURE);
        }

}

void* malloc(size_t size)
{
	DEBUG(printf("Wrapper malloc: calling libc malloc\n"));
	(*(libc_call.malloc))(size);
}
void free(void *ptr)
{

	DEBUG(printf("Wrapper free: calling libc free\n"));
	(*(libc_call.free))(ptr);
}

void *realloc(void *ptr, size_t size)
{
	DEBUG(printf("Wrapper realloc: calling libc realloc\n"));
	(*(libc_call.realloc))(ptr, size);
}


void *memalign(size_t boundary, size_t size)
{
	DEBUG(printf("Wrapper memalign: calling libc memalign\n"));
	(*(libc_call.memalign))(boundary, size);
}


