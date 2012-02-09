#ifndef	RED_CONSTS_H
#define	RED_CONSTS_H

//	The trans_eight structure is going to be used of char, short, int, long,
//	float and double data types
typedef struct {
	unsigned redzone[2] __attribute__ ((aligned (8)));
} trans_8;

static const trans_8 red_8 = {	.redzone = {0x17171717, 0x17171717} };

//	The basic use of this variable is to reset the stack redzones back to null
//	values.
static const trans_8 null_8;

//	The trans_sixteen data structure is specfically for transformed variables
//	with long double as original data-type.
typedef struct {
	unsigned redzone[4] __attribute__ ((aligned (8)));
} trans_16;

static const trans_16 red_16 =  {	.redzone = {0x17171717, 0x17171717, 0x17171717, 0x17171717} };

//	The basic use of this variable is to reset the stack redzones back to null
//	values.
static const trans_16 null_16;

//	We define the embedded struct below so that we could accomplish struct to
//	struct assignments. We do this because we do not want to call memset as
//	that is proving very costly.
typedef	struct {
	
	unsigned redzone[6] __attribute__((aligned(8)));
} trans_24;

static const trans_24 red_24 =  {.redzone = {0x17171717, 0x17171717, 0x17171717, 0x17171717, 0x17171717, 0x17171717}};
//	The basic use of this variable is to reset the stack redzones back to null
//	values.
static const trans_24 null_24;

#endif
