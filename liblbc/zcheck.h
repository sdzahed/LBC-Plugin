#ifndef	ZCHECK_H
#define	ZCHECK_H

//=============================================================================

/*	The objective of this section is to include the function prototypes of the
 *	std c functions. Directly include the header files creates problems during
 *	transformation and should be avoided
*/
#include	"red_consts.h"

//	Note that the size_t == unsigned long is for 64 bit systems.
//	<stdio.h>
static int printf(const char *format, ...);
void abort(void);

//=============================================================================
 
#define RZ_TRUE 	1
#define RZ_FALSE 	0
 
#define	RZ_HIGHER_ADDR_BITS 		16
#define RZ_LOWER_ADDR_BITS 			11
#define RZ_BIT_POSITION_BITS		5
#define	RZ_NUMBER_OF_BITS			3

#define RZ_LOWER_ADDR_MSK 		0x0000ffe0
#define RZ_BIT_POS_MSK			0x0000001f
 
//	If we want to consider the bitmap page as an array of characters, then
//	these are the values that we need to use as mask and lower index.
#define RZ_LOWER_CHAR_ADDR_BITS 	13
#define RZ_LOWER_CHAR_ADDR_MSK 	0x0000fff8

#define RZ_SIZE					(1 << RZ_HIGHER_ADDR_BITS)

/*	Note that this RZ_MAP_SIZE is the count of unsigned integers in the map
 *	and not bytes
 */
#define RZ_MAP_SIZE 			(1 << RZ_LOWER_ADDR_BITS)
#define RZ_BITS_PER_INT			(1 << RZ_BIT_POSITION_BITS)
#define	RZ_BITS_PER_BYTE		(1 << RZ_NUMBER_OF_BITS)

#define RZ_RED_ZONE				RZ_TRUE
#define RZ_NON_RED_ZONE			RZ_FALSE

/*	Taking a cue from Linux kernel's usage of GCC's branch prediction method.	*/
#define	likely(x)				__builtin_expect((x), RZ_TRUE)
#define	unlikely(x)				__builtin_expect((x), RZ_FALSE)

/*  Note that this value here must the value defined in the modified glibc
 *   * */
#define     MT_ARRAY_SIZE   79

//=============================================================================

typedef union {
	char bytes[4];
	float vl;
} custom_float;


static const custom_float redzone_float = {.bytes = {23,0,0,0}};

 
/*	This value is thus dependent on the system but is guaranteed to be the
 *	word length of the system	*/
static const int min_zone_size = sizeof(long double);

static const char zone_value = 23;

//=============================================================================

/*	Thread specific variable used in memory-allocation routines to determine
 *	the size of the type whose pointer is being assigned the memory chunk
 *	returned the memory-allocation routine	*/
/*	NOTE that this variable MUST NOT be initialized. 
 *	Hence each transformed file will have this declaration which will be
 *	considered by the compiler to be a "common" variable.
 *
 *	Note that this variable name MUST also be excluded from transformation.
 * */
extern __thread unsigned type_size;

extern unsigned *zone_map[RZ_SIZE];

//extern const unsigned zone_size;

/*	This variable is to be eventually used to limit the size of the
 *	redzone based on the size of the biggest type in the application. 
 *	For eg: We have a structure of size 100 then the size must be limited to
 *	say 200. This value will primarily be used for heap allocation.
 * */
extern unsigned max_zone_size;

//=============================================================================

/*
 * Note that the function has been attributed as "pure" because:
 * 	1.	It has no side-effects (on both the parameters and the global
 * 		variables)
 * 	2.	It depends on global variable (redzone bitmap)
*/
//void is_redzone() __attribute__((pure));
 
void is_redzone(void* ptr);
void mark_redzone (void *address, unsigned int count);
 
void unmark_redzone (void *address, unsigned int count);

void alloc_bitmap_page(unsigned higher_index);

//=============================================================================

/*	The basic objective of this section is to specify all the functions as
 *	inline so that cilly does not automatically delete them	*/
/*
 * Note that these functions have been attributed as "pure" because:
 * 	1.	It has no side-effects (on both the parameters and the global
 * 		variables)
 * 	2.	It depends on global variable (redzone bitmap)
*/
//	Commented by amisra: To be implemented later.
/*
static unsigned is_data_red(void *addr, unsigned size)__attribute__((always_inline, pure, hot));
static unsigned is_red(void *addr, unsigned size)__attribute__((always_inline, pure, hot));
*/

//[Hema: commented the below declarations]
//static unsigned is_array_acc_unsafe(unsigned int index, unsigned int array_size)__attribute__((always_inline, const));

//static void ensure_addr_bitmap(void *, void *) __attribute__((always_inline));

//static void ensure_sframe_bitmap() __attribute__((always_inline));

//=============================================================================
// Functions defined in zinit.c

/**
 * Initialize front and rear redzones of an object.
 * Also initializes bitmaps corresponding to front and rear redzones.
 *
 * @param (in) front_rz : pointer to the front redzone of the object
 * @param (in) front_rz_size: size of front redzone
 * @param (in) rear_rz: pointer to the rear redzone of the object
 * @param (in) rear_rz_size: size of rear redzone
 *
 * @return: none
 */
void init_both_redzones(void* front_rz, unsigned front_rz_size,
										 void* rear_rz, unsigned rear_rz_size);

/**
 * Uninitialize bitmaps corresponding to front and rear redzones of an object.
 *
 * @param (in) front_rz : pointer to the front redzone of the object
 * @param (in) front_rz_size: size of front redzone
 * @param (in) rear_rz: pointer to the rear redzone of the object
 * @param (in) rear_rz_size: size of rear redzone
 *
 * @return: none
 */
void uninit_both_redzones(void* front_rz, unsigned front_rz_size,
			 			 void* rear_rz, unsigned rear_rz_size);

/**
 * Initialize front redzone and bitmap of an object.
 *
 * @param (in) front_rz : pointer to the front redzone of the object
 * @param (in) front_rz_size: size of front redzone
 *
 * @return: none
 */
void init_front_redzone(void* front_rz, unsigned front_rz_size);

/**
 * Uninitialize bitmap corresponding to front redzone of an object.
 *
 * @param (in) front_rz : pointer to the front redzone of the object
 * @param (in) front_rz_size: size of front redzone
 *
 * @return: none
 */
void uninit_front_redzone (void* front_rz, unsigned front_rz_size);

/**
 * Initialize rear redzone and bitmap of an object.
 *
 * @param (in) rear_rz : pointer to the rear redzone of the object
 * @param (in) rear_rz_size: size of rear redzone
 *
 * @return: none
 */
void init_rear_redzone (void* rear_rz, unsigned rear_rz_size);

/**
 * Uninitialize bitmap corresponding to rear redzone of an object.
 *
 * @param (in) rear_rz : pointer to the rear redzone of the object
 * @param (in) rear_rz_size: size of rear redzone
 *
 * @return: none
 */
void uninit_rear_redzone (void* rear_rz, unsigned rear_rz_size);

/**
 * Check if pointer ptr is pointing to the redzone
 * If no, program continues execution, otherwise
 * is aborted.
 *
 * @param (in) value: unsigned int casted value to be dereferenced
 * @param (in) orig_value_size: size of original value to be
 *                              dereferenced
 * @param (in) ptr: pointer about to be dereferenced
 */
void is_char_red(unsigned int value,
				unsigned int orig_value_size,
				const void* ptr);

unsigned is_array_acc_unsafe(unsigned int index, unsigned int array_size);
void ensure_addr_bitmap(void *addr_start, void *addr_end);
//void ensure_sframe_bitmap(void* frame_start, void* frame_end);
void ensure_sframe_bitmap(void);
#endif
