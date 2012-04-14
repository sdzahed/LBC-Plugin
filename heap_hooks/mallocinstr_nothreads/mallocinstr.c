#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <malloc.h>
#include <fcntl.h>
#include <string.h>
#include <sys/stat.h>
#include <pthread.h>

#include "common.h"
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


#ifndef INTERNAL_SIZE_T
#define INTERNAL_SIZE_T size_t
#endif

/* The corresponding word size */
#define SIZE_SZ                (sizeof(INTERNAL_SIZE_T))


/*
   MALLOC_ALIGNMENT is the minimum alignment for malloc'ed chunks.
   It must be a power of two at least 2 * SIZE_SZ, even on machines
   for which smaller alignments would suffice. It may be defined as
   larger than this though. Note however that code and data structures
   are optimized for the case of 8-byte alignment.
 */


#ifndef MALLOC_ALIGNMENT
/* XXX This is the correct definition.  It differs from 2*SIZE_SZ only on
   powerpc32.  For the time being, changing this is causing more
   compatibility problems due to malloc_get_state/malloc_set_state than
   will returning blocks not adequately aligned for long double objects
   under -mlong-double-128.

#define MALLOC_ALIGNMENT       (2 * SIZE_SZ < __alignof__ (long double) \
? __alignof__ (long double) : 2 * SIZE_SZ)
 */
#define MALLOC_ALIGNMENT       (2 * SIZE_SZ)
#endif

/*===========================================================================*/
/*				Implementation for heap management of LBC.												 */
/*===========================================================================*/
/* 
 * LBC is a light-weight bounds checking compiler that instruments 
 * C program with runtime checks to ensure that no out-of-bounds sequential 
 * access is performed.
 * 
 * The implementation for heap management of LBC is Copyright (C) 
 * 2008 - 2012 by Ashish Misra, Niranjan Hasabnis,
 * and R.Sekar in Secure Systems Lab, Stony Brook University, 
 * Stony Brook, NY 11794.
 * 
 * This program is free software; you can redistribute it and/or modify 
 * it under the terms of the GNU General Public License as published by 
 * the Free Software Foundation; either version 2 of the License, or 
 * (at your option) any later version. 
 * 
 * This program is distributed in the hope that it will be useful, 
 * but WITHOUT ANY WARRANTY; without even the implied warranty of 
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the 
 * GNU General Public License for more details. 
 * 
 * You should have received a copy of the GNU General Public License 
 * along with this program; if not, write to the Free Software 
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307 USA.
 */

/*===========================================================================*/
/*								File: zcheck.h								 */
/*===========================================================================*/

/*	The objective of this section is to include the function prototypes of the
 *	std c functions. Directly include the header files creates problems during
 *	transformation and should be avoided
*/

//	<stdlib.h>
void exit(int status);
void abort(void);

//=============================================================================
 
#define GZ_TRUE 	1
#define GZ_FALSE 	0
 
#define	GZ_HIGHER_ADDR_BITS 	16
#define GZ_LOWER_ADDR_BITS 		11
#define GZ_BIT_POSITION_BITS	5
#define	GZ_NUMBER_OF_BITS		3

#define GZ_LOWER_ADDR_MSK 		0x0000ffe0
#define GZ_BIT_POS_MSK			0x0000001f

//	If we want to consider the guardmap page as an array of characters, then
//	these are the values that we need to use as mask and lower index.
#define GZ_LOWER_CHAR_ADDR_BITS 	13
#define GZ_LOWER_CHAR_ADDR_MSK 	0x0000fff8

#define GZ_SIZE					(1 << GZ_HIGHER_ADDR_BITS)

/*	Note that this GZ_MAP_SIZE is the count of unsigned integers in the map
 *	and not bytes
 */
#define GZ_MAP_SIZE 			(1 << GZ_LOWER_ADDR_BITS)
#define GZ_BITS_PER_INT			(1 << GZ_BIT_POSITION_BITS)
#define	GZ_BITS_PER_BYTE		(1 << GZ_NUMBER_OF_BITS)

#define GZ_GUARD_ZONE				GZ_TRUE
#define GZ_NON_GUARD_ZONE			GZ_FALSE
 
/*	Taking a cue from Linux kernel's usage of GCC's branch prediction method.	*/
#define	likely(x)				__builtin_expect((x), 2)
#define	unlikely(x)				__builtin_expect((x), 0)

//=============================================================================

typedef struct {
 	
	char   *gz_front;
	size_t gz_front_size;
	void   *buffer;
	size_t buffer_size;
	char   *gz_rear;
	size_t gz_rear_size;
} guardzones;
 
/*	This value is thus dependent on the system but is guaranteed to be the
 *	word length of the system	*/
extern unsigned int min_zone_size;

// The default value is 8
unsigned int min_zone_size = 8;

/*
 * Max zone size for LBC.
 * It is defined as extern so that it can be set from
 * the main program.
 */
extern unsigned int max_zone_size;

// The default value is 1024
unsigned int max_zone_size = 1024;

const char zone_value = 23;

/*===========================================================================*/

/*===========================================================================*/
/*								File: zcheck.c								 */
/*===========================================================================*/	
 /*	The objective of this program is to provide the memory-checking routines.
  *	This file will be compiled in the form of a library.
 */
unsigned *guard_map[GZ_SIZE];

/*	Note that the mutex array size must be a prime number	*/
#define		MT_ARRAY_SIZE	79

pthread_mutex_t guard_map_acc_lock[MT_ARRAY_SIZE];

/*	Note that the array of locks must be initialized at the startup and NOT
 *	when malloc is used for the first time
 */

static void 
__attribute__((constructor))
init_guard_map_acc_lock(void)
{
    int count;
    for (count=0; count < MT_ARRAY_SIZE; ++count)
        if(pthread_mutex_init(&guard_map_acc_lock[count], NULL))
            MY_PRINTF(perror("\n Error: Mutex initialization failed:"))
}


//=============================================================================

/*	The basic objective of this function is to take an address and look in the
 *	guardmap and find if it belongs to a guard-zone.
 *
 *	Note that if the guard_map[higher_index] does not exist, then we simply
 *	raise our hands and say, go right ahead.	*/

static int
is_guardzone (void *address)
{
	u_int32_t index = (u_int32_t) address;

	u_int32_t higher_index = index >> GZ_HIGHER_ADDR_BITS;
	u_int32_t lower_index = (index & GZ_LOWER_ADDR_MSK) >> GZ_BIT_POSITION_BITS;
	u_int32_t bit_position = index & GZ_BIT_POS_MSK;

	if (guard_map[higher_index] == 0)
		return 0;

	return (guard_map[higher_index][lower_index] &  (unsigned)(1 << bit_position));
}

//=============================================================================

//	The objective of this macro is to allocate a new page in the guardzone
//	guardmap.
//	Performance reasons force us to keep this as a macro untill suitable
//	alternatives can be found.
#define alloc_guard_map_page(higher_index)	do {								\
																			\
	unsigned lock_index;													\
	lock_index = (higher_index) % MT_ARRAY_SIZE;							\
																			\
	(void) pthread_mutex_lock (& guard_map_acc_lock[lock_index]);						\
	if (guard_map[higher_index] == 0) 										\
		if ((guard_map[higher_index] = 										\
			orig_calloc (GZ_MAP_SIZE, sizeof(unsigned))) == 0)				\
			exit (1);														\
	(void) pthread_mutex_unlock (& guard_map_acc_lock[lock_index]);						\
																			\
} while(0)

//	The basic objective of this macro is to ensure that pages in the 
//	guardmap corrresponding to the specified address range have been allocated.
//	Do note that it's specifically a macro because function calls are incurring
//	huge costs in case of olden benchmarks.
#define ensure_addr_guard_map(start, end)	do{											\
																					\
		unsigned curr_higher_index, final_higher_index;								\
																					\
		curr_higher_index = ((unsigned)(start)) >> GZ_HIGHER_ADDR_BITS;				\
		final_higher_index = ((unsigned)(end)) >> GZ_HIGHER_ADDR_BITS;				\
																					\
		do {																		\
			if (likely ((unsigned) guard_map[curr_higher_index]))								\
				continue;															\
			else																	\
				alloc_guard_map_page (curr_higher_index);								\
																					\
		}																			\
		while (unlikely(++curr_higher_index <= final_higher_index));					\
																					\
} while(0)

/*	The basic objective of this function is to mark the bits in the guardmap
 *	with 0 from given address for given number of bytes.
 *	Note that now we will have three more invariants for these functions.
 *
 *	1.	The size of guardzones to be marked must be a multiple of 8 bytes.
 *	2.	The guardzones will be aligned on 8 byte boundaries.
 *	3.	The pages in guardmap will be allocated a-priori. Checking for that is
 *		NOT the responsibility of this function.
 *	*/
static void 
mark_guardzone(void *address, unsigned int bit_count)
{	
	char * curr_addr = address;
	unsigned index = (unsigned)address;
	
	//	The size of guardzones to be marked must be a multiple of 8 bytes.
	if ((bit_count % 8) != 0)
		abort();

 	//	The guardzones will be aligned on 8 byte boundaries.
	if ((index % 8) != 0)
		abort();

	//	Note that for malloc file mark_guardzone, we are forced to call this
	//	ourselves, while this is not the case for stack based mark_guardzone
	//	that exists in the library.
	ensure_addr_guard_map (curr_addr, (curr_addr + bit_count - 1));

	//	While we acknowledge that the guardmap page is actually maintained as an
	//	array of unsigned ints, we will be accessing it as an array of
	//	unsigned characters.
	u_int32_t higher_index = (index >> GZ_HIGHER_ADDR_BITS);
	u_int32_t lower_index = (index & GZ_LOWER_CHAR_ADDR_MSK) >> GZ_NUMBER_OF_BITS;

	while(bit_count) {
		
		char *next_page_boundary = (char *)((higher_index + 1) << GZ_HIGHER_ADDR_BITS);

		u_int32_t page_addr_remaining = (next_page_boundary - curr_addr);

		u_int32_t bits_to_set = (bit_count <= page_addr_remaining)? 
										bit_count : page_addr_remaining;

		//	Note that while we are measuring everything in terms of number of
		//	addresses that we will be setting, while supplying the value to
		//	memset, we must divide bits_to_set to get the number of bytes that
		//	memset will need to set.
		memset( (((char *)guard_map[higher_index]) + lower_index), 
				0xFF, (bits_to_set / 8));

		curr_addr = (char *)((++higher_index) << GZ_HIGHER_ADDR_BITS);
		lower_index = 0;
		bit_count -= bits_to_set;
	}
}


/*	The basic objective of this function is to unmark the bits in the guardmap
 *	with 0 from given address for given number of bytes.
 *	Note that now we will have three more invariants for these functions.
 *
 *	1.	The size of guardzones to be marked must be a multiple of 8 bytes.
 *	2.	The guardzones will be aligned on 8 byte boundaries.
 *	3.	The pages in guardmap will be allocated a-priori. Checking for that is
 *		NOT the responsibility of this function.
 *	*/
static void 
unmark_guardzone(void *address, unsigned int bit_count)
{	
	char * curr_addr = address;
	unsigned index = (unsigned)address;
	
 	//	The size of guardzones to be marked must be a multiple of 8 bytes.
	if ((bit_count % 8) != 0)
		abort();

 	//	The guardzones will be aligned on 8 byte boundaries.
	if ((index % 8) != 0)
		abort();

	//	While we acknowledge that the guardmap page is actually maintained as an
	//	array of unsigned ints, we will be accessing it as an array of
	//	unsigned characters.
	u_int32_t higher_index = (index >> GZ_HIGHER_ADDR_BITS);
	u_int32_t lower_index = (index & GZ_LOWER_CHAR_ADDR_MSK) >> GZ_NUMBER_OF_BITS;

	while(bit_count) {
		
		char *next_page_boundary = 
			(char *)((higher_index + 1) << GZ_HIGHER_ADDR_BITS);
		u_int32_t page_addr_remaining = (next_page_boundary - curr_addr);

		u_int32_t bits_to_set = (bit_count <= page_addr_remaining)? 
										bit_count : page_addr_remaining;

		//	Note that while we are measuring everything in terms of number of
		//	addresses that we will be setting, while supplying the value to
		//	memset, we must divide bits_to_set to get the number of bytes that
		//	memset will need to set.
		memset( (((char *)guard_map[higher_index]) + lower_index), 
				0, (bits_to_set / 8));

		curr_addr = (char *)((++higher_index) << GZ_HIGHER_ADDR_BITS);
		lower_index = 0;
		bit_count -= bits_to_set;
	}
}


/*===========================================================================*/
/*								File: zmem.c								 */
/*===========================================================================*/	
/*	Forward declaration.	*/
static int
get_guardzone(char *addr, guardzones *addr_gz);

/*	Thread-specific variable that stores the size of data-type whose pointer
 *	variable is assigned memory chunk returned by given memory-allocation
 *	function.
 *	Note that after the value is used by the memory-allocation function, it
 *	must be set to value 1 so as to be compatible with untransformed code that
 *	does not set the value of the variable.
 */
__thread size_t type_size = 1;

/*	Denotes the default ratio of the proposed size of one guardzone to the 
 *	memory chunk being guarded by it	
 */
#ifndef	GZ_SIZE_RATIO
#define	GZ_SIZE_RATIO	0.1
#endif

/*	The granularity refers to number of bytes represented by each bit in the
 *	guardzone guardmap.
 *	This can take the values 1,2,4,8.
 *	It cannot be more than 8 for the simple reason that dynamic memory is
 *	aligned on 8-byte boundaries and that can't be messed up.
 */
#ifndef	GZ_GRANULARITY 
#define	GZ_GRANULARITY	1
#endif

/*	The objective of this function is to round up num to be a multiple of
 *	rnd_factor. Note that this assumes that rnd_factor is non-zero. */
/*
size_t
__attribute__((always_inline))
round_up(size_t num, size_t rnd_factor) 
{
	return (num + rnd_factor - 1) / rnd_factor * rnd_factor;
}
*/
#define	round_up(arg1, arg2)	(((arg1) + (arg2) - 1)/(arg2) * (arg2))
#define	round_down(arg1)		(((arg1) >> GZ_NUMBER_OF_BITS) << GZ_NUMBER_OF_BITS)

/*	The objective of this function is to return a multiplying factor for the
 *	block size to be used in determing the guardzone size.
 *	The ratio to be returned will be a function of the block size.
 *	Currently for simplicity, we will keep it a constant.
 */
#define block_ratio(blk_size)	GZ_SIZE_RATIO

/*	Note that this value must be the LCM of MALLOC_ALIGNMENT AND the
 *	granularity. 
 *	However since Granularity is one of 1,2,4,8, the chunk alignment will
 *	again be ONLY MALLOC_ALIGNMENT.
 */
static const unsigned int chunk_alignment = MALLOC_ALIGNMENT;

/*
 * Macro to check for guard zone size limits.
 */
#define check_gz_size_limits(size) ({ \
	size_t pre_size = (size > max_zone_size) ? max_zone_size : size; \
	pre_size = (pre_size < min_zone_size) ? min_zone_size : pre_size; \
	pre_size; \
})

/*	Note that, due to performance reasons, we will code calc_gz_size as a macro.
 *	Ideally, it should have been a function. But alas. 
 *	We will using the statement expression feature offered by gcc which allows
 *	us to embed a sequence of statements as an expression.
 */
#define calc_gz_size(length) ({													\
																				\
	size_t pre_size, rnd_size;													\
	size_t obj_size = (length);													\
	double blk_ratio = block_ratio(obj_size);									\
																				\
	pre_size = ((obj_size * blk_ratio) > type_size) ? (obj_size * blk_ratio) 	\
														: type_size;			\
	pre_size = (pre_size > max_zone_size) ? max_zone_size : pre_size ;			\
	pre_size = (pre_size < min_zone_size) ? min_zone_size : pre_size ; \
	type_size = 1;																\
	rnd_size = round_up(pre_size, chunk_alignment);								\
	rnd_size;																	\
})

/*	The objective of this function is to get the size of the guardzone given a
 *	pointer that points to a memory chunk.
 *	Also note that we use the fact that guardzone must be aligned on an 8-byte
 *	boundary (rather on MALLOC_ALIGNMENT) to reduce the checking.
 *	Note that the method itself DOES NOT check whether the ptr supplied is
 *	aligned on MALLOC_ALIGNMENT.
 *	Note that this method also assumes that the ptr supplied is NON-NULL.
 *	If do not detect ANY guardzone, we will return the size as 0.
 */
static size_t
get_gz_size(void *ptr)
{
	u_int32_t size = 0;

	//	Note that we will need to start from the previous byte in the guardmap
	//	and not the current byte.
	//	Hence the data ptr should be subtracted by 8.
	u_int32_t index = (u_int32_t) ((char *)ptr - 8);
	
	//	Note that it is always the case that ptr will be assigned on an 8-byte
	//	boundary. Thus index must also be aligned on 8-byte boundary
	assert((index & 0x07) == 0);

	//	We will be accessing the guardmap again as a character array rather than
	//	an unsigned array.
	u_int32_t higher_index = index >> GZ_HIGHER_ADDR_BITS;
	u_int32_t lower_index = (index & GZ_LOWER_CHAR_ADDR_MSK) >> GZ_NUMBER_OF_BITS;
	
	char *curr_map_ptr;

	while (guard_map[higher_index]) {

		curr_map_ptr = ((char *)guard_map[higher_index] + lower_index);

		while (1) {
				
			//	We are detecting if the bit is set at the very start of the
			//	character.
			if (*curr_map_ptr & (0x01)) {
				++size;
				--curr_map_ptr;
				if (!lower_index)
					goto outer_loop;
				else --lower_index;
			}
			else
				goto ret ;
		}
		
		outer_loop:
		--higher_index;
		lower_index = ((1 << GZ_LOWER_CHAR_ADDR_BITS) - 1);
	}

	ret:
	return (size * 8);
}

size_t musable(void* mem)
{
    mchunkptr p;
    if (mem != 0) {
        p = mem2chunk(mem);
        if (chunk_is_mmapped(p))
            return chunksize(p) - 2*SIZE_SZ;
        else if (inuse(p))
            return chunksize(p) - SIZE_SZ;
    }
    return 0;
}


/*	The objective of this function is to do post-processing of the memory
 *	received from the library memory functions.
 *	This includes setting up the guardzones, computing the ptr to be returned.
 *	Note that size argument here refers to the original size and NOT the new
 *	size. However, this size is the one that has been rounded to the multiple of
 *	MALLOC_ALIGNMENT.
 *	We also need to pass zone_size since its variable and not fixed. Moreover,
 *	we also pass the flag "aligned" that indicates whether the invoking
 *	function was of the category of memalign, pvalloc, etc, or one of malloc,
 *	calloc, etc.
 */
/*	The layout of the memory is as follows:
 *	--------------------------------------------------------------------------
 *		| Front-guard-zone | Memory | Rear-guard-zone|
 *											
 *	--------------------------------------------------------------------------
 *	*/
#define		UNALIGNED 	1
#define		ALIGNED		0
/*	Note that the following assumptions hold:
 *	The expression supplied to these macros MUST NOT CONTAIN ANY SIDE-EFFECTS
 *		
 */
#define	unaligned_post_processing(var1, var2, var3)								\
({																				\
	char *rear_gz ;																\
	unsigned rear_gz_size;														\
																				\
	size_t alloc_size = musable((var1));										\
	size_t our_alloc_size = round_down(alloc_size);							\
																				\
	memset((var1), zone_value, (var3)); 										\
	mark_guardzone((var1), (var3));												\
																				\
	rear_gz = (var1) + (var3) + (var2); 										\
	rear_gz_size = our_alloc_size - ((var3) + (var2));							\
	memset(rear_gz, zone_value, rear_gz_size); 									\
	mark_guardzone(rear_gz, rear_gz_size);										\
																				\
	((var1) + (var3));															\
})

/*
 * Modified: Niranjan (9/2/2010)
 * 
 * The original macro was writing into the mUSABLe
 * area for rear guardzone. This is certainly correct
 * as per the meaning of mUSABLe, but glibc malloc
 * integrity checks were failing with the error
 * such as "free(): invalid pointer" when that
 * pointer is freed, since writing past the
 * actually-asked memory was corrupting the 
 * malloc metadata. 
 *
 * Hence now we write only to what we have asked malloc.
 * We don't need to deal with mUSABLe thing anymore.
 */
/*#define	unaligned_post_processing(var1, var2, var3)								\
({																				\
	char *rear_gz ;																\
																				\
	memset((var1), zone_value, (var3)); 										\
	mark_guardzone((var1), (var3));												\
																				\
	rear_gz = (var1) + (var3) + (var2); 										\
	memset(rear_gz, zone_value, (var3)); 									\
	mark_guardzone(rear_gz, (var3));										\
																				\
	((var1) + (var3));															\
})
*/
#define	aligned_post_processing(var1, var2)										\
{																				\
	char *rear_gz;																\
	unsigned rear_gz_size;														\
																				\
	size_t alloc_size = musable((var1));										\
	size_t our_alloc_size = round_down(alloc_size);								\
																				\
	rear_gz = (var1) + (var2); 													\
	rear_gz_size = our_alloc_size - (var2);										\
	memset(rear_gz, zone_value, rear_gz_size); 									\
																				\
	mark_guardzone(rear_gz, rear_gz_size);										\
}


/*  The basic idea in z_realloc is to just to malloc a new area of the
 *  relevant size, copy the old  */
void *
public_realloc (void *ptr, size_t size)
{
    void  *realloc_buffer;

    /*  This is the size argument that we will provide to memset to copy
     *  user-data from original buffer to newly allocated buffer    */
    size_t memset_size;

    guardzones gz_addr;

    /*  CASE - 01   */
    /*  If the size=0 is passed to realloc it returns either null or a pointer
     *  suitable to be passed to free() */
    if (!size) {   
        public_fREe(ptr);
        return 0;  
    }

    /*  From the ptr supplied as parameter, compute the addresses of the front
     *  guardzone and the rear guardzone.
     *  We need this because we need to calculate the size of current buffer
     *  when doing the reallocation */

#ifdef  ZDEBUG
    fprintf(stderr, "realloc :\naddress : %p\tsize : %d\n",ptr, size);
#endif

    /*  If this value is non-null, it implies that there was some corruption of
     *  metadata    */
    if (get_guardzone(ptr, &gz_addr)) {
#ifdef  ZDEBUG
        fprintf(stderr, "realloc : guardzone error\n");
        return ptr;
#endif
        abort();
    }
    /*  CASE - 02   */
    /*  Requested size is equivalent to current size    */
    if (gz_addr.buffer_size == size)
        return ptr;

    /*  CASE - 03   */
    /*  The requested size is different from the currently allocated size.
     *  Let's malloc a new memory area and set it up.   */

    /*  We can behave as if realloc failed and return the original pointer.
     *  Note that we use our malloc function that will automatically setup the
     *  guardzones.
     */
    if((realloc_buffer = public_mALLOc(size)) == 0)
        return ptr;

    /*  Note that the size provided to memset is to be the minimum of the two
     *  sizes: original buffer size and the buffer size requested   */
    memset_size = (gz_addr.buffer_size > size) ? size : gz_addr.buffer_size;

    /*  Copy the contents of the original buffer to the new buffer  */
    memcpy(realloc_buffer, gz_addr.buffer, memset_size);

    /*  Note that we repeat free's logic here because we do not want to call
     *  the get_gz_size function again. */
    /*  Reset the guardzones in our original buffer */
    unmark_guardzone(gz_addr.gz_rear, gz_addr.gz_rear_size);

    if (gz_addr.gz_front) {
        unmark_guardzone(gz_addr.gz_front, gz_addr.gz_front_size);
        /*  Free up the original buffer. */
        LIBC_FREE(gz_addr.gz_front);
    }
    else
        LIBC_FREE(ptr);

    return realloc_buffer;
}

void
public_free (void *ptr)
{
    guardzones addr_gz;

    /*  From the ptr supplied as parameter, compute the addresses of the front
     *  guardzone and the rear guardzone    */
    /*  If this value is null, it implies that there was either some corruption of
     *  metadata OR we did not allocate this memory.
     *  So just pass the original pointer because this is what the program
     *  "wanted"    */
    if(!ptr || get_guardzone(ptr, &addr_gz)) {
#ifdef ZDEBUG
        fprintf(stderr, "free : ptr : %p\naborting free.\n", ptr );
#endif
#ifdef  Z_STRICT_FREE
        abort();
#else
        LIBC_FREE(ptr);
#endif
        return;
    }

    /*  Reset the guardzones in our guardmap    */
    /*  Note that for the purposes of thread synchronization, it is imperative
     *  that unmarking of guardzones be done before the freeing of the memory
     *  area. 
     *  ON THE CONTRARY, in case of allocation of memory, the marking of
     *  guardzones must be done AFTER the memory has been allocated */
    unmark_guardzone(addr_gz.gz_rear, addr_gz.gz_rear_size);

    /*  Pass the pointer to the start of the buffer */
    if (addr_gz.gz_front) {
        unmark_guardzone(addr_gz.gz_front, addr_gz.gz_front_size);
        LIBC_FREE(addr_gz.gz_front);
    }
    else
        LIBC_FREE(addr_gz.buffer);
}

void *
public_memalign(size_t boundary, size_t size)
{   
    void *ptr;
    size_t rev_size = round_up(size, chunk_alignment);
    size_t zone_size = calc_gz_size(size);
    size_t new_size = rev_size + zone_size ;

    if((ptr = LIBC_MEMALIGN (boundary, new_size)) == 0)
        return 0;

    aligned_post_processing(ptr, rev_size);

#ifdef  ZDEBUG  
    guardzones guardzone;
    if (get_guardzone (addr, &guardzone))
        fprintf(stderr, "memalign : %p\nerror in allocating guardzones.\n", addr);
#endif

    return ptr;
}

void *
public_malloc (size_t size)
{
    void *ptr;
    size_t rev_size = round_up(size, chunk_alignment);
    size_t zone_size = calc_gz_size(size);

    //  Note that now all the sizes are multiples of chunk alignment. We need
    //  this because of the invariant used in mark_guardzone and unmark_guardzone
    //  functions.
    size_t new_size = rev_size + 2 * zone_size;

    if((ptr = LIBC_MALLOC (new_size)) == 0)
        return 0;

#ifdef  ZDEBUG  
    guardzones guardzone;
    void *addr = unaligned_post_processing (ptr, rev_size, zone_size);

    if (get_guardzone(addr, &guardzone))
        fprintf(stderr, "malloc : %p\nerror in allocating guardzones.\n", addr);

    return addr;
#else
    return unaligned_post_processing(ptr, rev_size, zone_size);
#endif
}



/*	This function is used by z_free function. The basic objective is to find
 *	the start and end guardzones for dynamically allocted memory. This uses the
 *	metadata written into the dynamically allocated memory when the allocation
 *	is done.	
 */

/*	The layout of the memory is as follows:
 *	--------------------------------------------------------------------------------------
 *	| Front-guard-zone | Buffer | Rear-guard-zone|
 *	
 *	The important invariant here is that all these zones are aligned on 8-byte
 *	boundary and thus have sizes as multiples of 8-bytes.
 *	Also is important the fact that malloc algorithms allocate data only in
 *	sizes of 8-bytes.
 *	Note that since the malloc-algorithms may allocate more memory to us than
 *	we requested, the rear-guardzone size may be greater than the front-guardzone
 *	size.
 *	The only thing that is guaranteed to us is that the rear-guardzone size is
 *	of multiple of 8 bytes, aligned on 8-byte boundary, and extends right
 *	uptil the end of the block allocated to us.
 *	This fact is used by us in while marking and unmarking guardzones.	
 *	-------------------------------------------------------------------------------------
 */

/*	The best case scenario is:
 *	1.	The address provided to us is not in guardzone.
 *	2.	The front and rear pointers point to a guardzone.
 *
 *	The above scenario indicates in high probability that the guardzone is
 *	been correctly formatted.
 *
 *	1.	First, check to see if the address provided to us is not in a guardzone. 
 *	If it is, then it is a clear case of error.
 *
 *	2.	Second check is to see if the area pointed to by first guardzone is
 *	recognized by guardmap as a guardzone. If it is, then we are looking at
 *	something that has been allocated by gz_malloc AND MAY BE at the
 *	beginning of the memory region.
 *		The "MAY BE" part is because we could have been given a pointer to
 *		middle of buffer allocated by gz_malloc but still could  locate the
 *		front guardzone.
 *
 *	3.	The Third check is that pointer to rear_guardzone is again recognized by the
 *	guardmap. If it is, then it means in high probability that we are on the
 *	right track.
 *		Note that, the rear_guardzone is computed using the meta-data. There is
 *		a low probability that even in case of a pointer provided to us
 *		pointing in the middle of a guardzone, and the computed rear_guardzone is
 *		pointing to some-other area's guardzone. Low probability BUT can happen.
 *
 * 		If it fails, then we were definitely given an area in the middle of a
 * 		valid buffer. AND that would have screwed up free().
 *
 *	4.	If all the checks are cleared, then in good probability we are looking at a
 *	memory area that has been allocated by us.
 *	
*/

/*	This function will return a non-zero value in case of an error. Else zero
 *	is returned.	*/
static int
get_guardzone(char *addr, guardzones *addr_gz) 
{
	size_t gz_front_size, gz_rear_size;
	size_t chunk_size, rnd_chunk_size;
	char *mem_start, *mem_end;

	gz_front_size = get_gz_size(addr);
	mem_start = addr - gz_front_size;

	//	Assigning front guardzone characteristics
	addr_gz->gz_front = gz_front_size ? mem_start : NULL;
	addr_gz->gz_front_size = gz_front_size;

	//	Determing the end of the rear guardzone and thus the end of our memory
	//	allocation unit.
	chunk_size = musable(mem_start);
	rnd_chunk_size = round_down(chunk_size);
	mem_end = mem_start + rnd_chunk_size;
	gz_rear_size = get_gz_size(mem_end);

	//	Assigning rear guardzone characteristics
	addr_gz->gz_rear = (mem_end - gz_rear_size);
	addr_gz->gz_rear_size = gz_rear_size;

	//	Assigning buffer characteristics
	addr_gz->buffer = addr;
	addr_gz->buffer_size = (rnd_chunk_size - gz_front_size - gz_rear_size);

#ifdef	Z_STRICT_FREE
	/*	Lets perform the error checks as specified out	 */
	if (!(is_guardzone(addr)) && 
			( addr_gz->gz_front && is_guardzone(addr_gz->gz_front)) && 
			is_guardzone(addr_gz->gz_rear)) {
		return 0;
	}
#else
	/*	No checks are performed	*/
	return 0;
#endif

#ifdef	ZDEBUG
		fprintf(stderr, "get_guardzone error for ptr : %p\n", addr);
#endif
	return -1;

}
//=============================================================================

void __attribute__ ((constructor)) myinit(void)
{
		MY_PRINTF(printf("\n Initialising hooks...\n"))
		
		SAVE_HOOKS()
				
		SET_HOOKS()

		if(pthread_mutex_init(&mutex, NULL))
				MY_PRINTF(perror("\n Error: Mutex initialization failed:"))
}

void* mymalloc(size_t size, const void* caller)
{
		GRAB_LOCK()

		UNSET_HOOKS()

		MY_PRINTF(printf("\n In mymalloc %u\n", size))
		
		void* res = public_malloc(size);

		SET_HOOKS()

		RELEASE_LOCK()

		return res;
}

void myfree(void* ptr, const void* caller)
{
		GRAB_LOCK()

		UNSET_HOOKS()

		MY_PRINTF(printf("\n In myfree\n"))

		public_free(ptr);

		SET_HOOKS()

		RELEASE_LOCK()
}

void* myrealloc(void* ptr, size_t size, const void* caller)
{
		GRAB_LOCK()

		UNSET_HOOKS()

		MY_PRINTF(printf("\n In myrealloc\n"))

		void* res = public_realloc(ptr, size);

		SET_HOOKS()

		RELEASE_LOCK()

		return res;
}

void* mymemalign(size_t blksize, size_t size, const void* caller)
{
		GRAB_LOCK()

		UNSET_HOOKS()

		MY_PRINTF(printf("\n In mymemalign\n"))

		void* res = public_memalign(blksize, size);

		SET_HOOKS()

		RELEASE_LOCK()

		return res;
}

void __attribute__ ((destructor)) myfini(void)
{
		UNSET_HOOKS()

		MY_PRINTF(printf("\n Uninitialising hooks...\n"))

        if(pthread_mutex_destroy(&mutex))
            MY_PRINTF(perror("\n Error: Mutex destruction failed:"))
}

