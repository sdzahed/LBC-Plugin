#ifndef COMMON_H
#define COMMON_H

unsigned int debug;

#define DEBUG_STR "DEBUG_MALLOC_INSTR"
#define MY_PRINTF(stmt){if(debug) stmt;}

#define LIBC_MALLOC malloc
#define LIBC_FREE free
#define LIBC_REALLOC realloc
#define LIBC_MEMALIGN memalign

#endif
