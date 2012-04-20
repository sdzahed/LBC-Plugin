#include "zcheck.h"

#include	<pthread.h>
#include <assert.h>
#include <stdlib.h>
#include <string.h>

#define 	NULL_PTR	((void *)0)
/*	The original calloc defined in glibc.
 * */
void * glibc_calloc(size_t nmemb, size_t size);
void *memset(void *s, int c, size_t n);
//=============================================================================


//=============================================================================

/*	The objective of this program is to provide the memory-checking routines.
  *	This file will be compiled in the form of a library.
 */

unsigned *(zone_map[RZ_SIZE]);
pthread_mutex_t zonemap_acc_lock[MT_ARRAY_SIZE];

//	If this variable is set to 0, then it implies that there is no limit on
//	the size of the redzone.
unsigned max_zone_size;

//	commented by amisra. There is already one in libc/malloc.c. Uncomment this
//	after due thought.
 __thread unsigned type_size = 1;

/************************************************
 *  Guard zone initialization routines
 ************************************************/

void init_both_redzones (void* front_rz, unsigned front_rz_size,
										 void* rear_rz, unsigned rear_rz_size)
{
	assert (front_rz != NULL);
	assert (front_rz_size != 0);
	assert (rear_rz != NULL);
	assert (rear_rz_size != 0);
	
	unsigned redzone_size = rear_rz_size;

	if (redzone_size == 8) {
				
		trans_8 *trans_ptr = (trans_8 *) front_rz;
		*trans_ptr = red_8;
		trans_ptr = (trans_8 *) rear_rz;
		*trans_ptr = red_8;
															
		unsigned address = (unsigned) front_rz;		
		unsigned higher_index = (address >> RZ_HIGHER_ADDR_BITS);	
		unsigned lower_index = 	((address & RZ_LOWER_CHAR_ADDR_MSK) >> RZ_NUMBER_OF_BITS); 
												
		*(((char *) zone_map[higher_index]) + lower_index) = 0xFF;													
		*(((char *) zone_map[higher_index]) + lower_index + 2) = 0xFF;													
	}

	else if (redzone_size == 16) {					
																
		trans_16 *trans_ptr = (trans_16 *) front_rz;
		*trans_ptr =  red_16;												
		trans_ptr = (trans_16 *) rear_rz;
		*trans_ptr =  red_16;
						
		unsigned address = (unsigned) front_rz;
		unsigned higher_index = (address >> RZ_HIGHER_ADDR_BITS);	
		unsigned lower_index = 	((address & RZ_LOWER_CHAR_ADDR_MSK) >> RZ_NUMBER_OF_BITS);					
												
		*((short *)(((char *) zone_map[higher_index]) + lower_index)) = 0xFFFF;							
		*((short *)(((char *) zone_map[higher_index]) + lower_index + 4)) = 0xFFFF;							
	}

	else if (redzone_size == 24){

		memset (front_rz, zone_value, front_rz_size);
		memset (rear_rz, zone_value, rear_rz_size);	
												
		unsigned address = (unsigned) front_rz;
		unsigned higher_index = (address >> RZ_HIGHER_ADDR_BITS);	
		unsigned lower_index = 	((address & RZ_LOWER_CHAR_ADDR_MSK) >> RZ_NUMBER_OF_BITS);					
		*((unsigned *)(((char *) zone_map[higher_index]) + lower_index)) |= 0x00FFFFFF;						
												
		address = (unsigned) rear_rz;		
		higher_index = (address >> RZ_HIGHER_ADDR_BITS);
		lower_index = ((address & RZ_LOWER_CHAR_ADDR_MSK) >> RZ_NUMBER_OF_BITS);
		*((unsigned *)(((char *) zone_map[higher_index]) + lower_index)) |= 0x00FFFFFF;						
	}

	else										
		abort();								
												
}

/*	Note that during uninitialization its not necessary to remark the ptr
*	area with anything. HOWEVER it is important to uninitialize the bitmap.
*	However we will do it too as we cannot afford large parts of stack getting
*	painted with the redzone value.
*	Note that this init_redzone can only be used for stack variables where it
*	is guaranteed apriori that bitmap pages corresponding to the stack have
*	been allocated.
* */

void uninit_both_redzones (void* front_rz, unsigned front_rz_size,
			 			 void* rear_rz, unsigned rear_rz_size)
{
	assert (front_rz != NULL);
	assert (front_rz_size != 0);
	assert (rear_rz != NULL);
	assert (rear_rz_size != 0);
	
	unsigned redzone_size = rear_rz_size;
	if (redzone_size == 8) {																
																													
		/* trans_8 *trans_ptr = (trans_8 *) front_rz;	
		*trans_ptr = null_8;										
		trans_ptr = (trans_8 *) rear_rz;	
		*trans_ptr = null_8;								*/								
																													
		unsigned address = (unsigned) front_rz;	
		unsigned higher_index = 															
			( address >> RZ_HIGHER_ADDR_BITS);									
		unsigned lower_index = 																
		((address & RZ_LOWER_CHAR_ADDR_MSK) >> 								
		 	RZ_NUMBER_OF_BITS);																	
																													
		*(((char *) zone_map[higher_index]) + lower_index)			
			= 0x00;																							
		*(((char *) zone_map[higher_index]) + lower_index + 2)	
			= 0x00;																							
	}

	else if (redzone_size == 16) {													
																													
		/* trans_16 *trans_ptr = (trans_16 *) front_rz;		
		*trans_ptr = null_16;									
		trans_ptr = (trans_16 *) rear_rz;					
		*trans_ptr = null_16;					*/											
																													
		unsigned address = (unsigned) front_rz;									
		unsigned higher_index = 															
			( address >> RZ_HIGHER_ADDR_BITS);									
		unsigned lower_index = 																
		((address & RZ_LOWER_CHAR_ADDR_MSK) >> 								
		 	RZ_NUMBER_OF_BITS);																	
																													
		*((short *)(((char *) zone_map[higher_index]) + lower_index))
			= 0x0000;																						
		*((short *)(((char *) zone_map[higher_index]) + lower_index + 4))
			= 0x0000;																						
																													
	}																												
	else if (redzone_size == 24){														
		/* unsigned count = front_rz_size;	
		void *front_ptr, *rear_ptr;				
												
		front_ptr = front_rz;			
		memset(front_ptr, 0, count);			
												
		rear_ptr = rear_rz;				
		memset(rear_ptr, 0, count);			*/										
																													
																													
		unsigned address = (unsigned) front_rz;					
		unsigned higher_index = 															
			( address >> RZ_HIGHER_ADDR_BITS);									
		unsigned lower_index = 																
		((address & RZ_LOWER_CHAR_ADDR_MSK) >> 								
		 	RZ_NUMBER_OF_BITS);																	
		*((unsigned *)(((char *) zone_map[higher_index]) 			
								+ lower_index))&= 0xFF000000;							
																													
		address = (unsigned) rear_rz;										
		higher_index = 																				
			( address >> RZ_HIGHER_ADDR_BITS);									
		lower_index = 																				
		((address & RZ_LOWER_CHAR_ADDR_MSK) >> 								
		 	RZ_NUMBER_OF_BITS);																	
		*((unsigned *)(((char *) zone_map[higher_index]) 			
								+ lower_index)) &= 0xFF000000;							
																													
	}

	else																										
		abort();																							
																													
}	

/*	A function to initialize an AREA OF FRONT REDZONE ONLY with redzone values and also mark the
*	bitmap.
*
*	This function is used to initialize redzone of individual field in SuperStruct and incomplete
*	structures.
* */
void init_front_redzone (void* front_rz, unsigned front_rz_size)
{

//	front_rz_size = 8U;
	assert (front_rz != NULL);
	assert (front_rz_size != 0);

	unsigned redzone_size = front_rz_size;

    redzone_size = front_rz_size > 24 ? 24: front_rz_size;
    DEBUGLOG("[Debug] : init_front_redzone (0x%08x, %u)\n", front_rz, front_rz_size);																							
	if (redzone_size == 8) {	
						
		DEBUGLOG("[DEBUG] : init_front_redzone - 1\n");																							
		trans_8 *trans_ptr = (trans_8 *) front_rz;
		DEBUGLOG("[DEBUG] : init_front_redzone - 2\n");		
																					
		if(trans_ptr)
			DEBUGLOG("[DEBUG] : trans_ptr NOT NULL\n");
		else
			DEBUGLOG("[DEBUG] : trans_ptr NULL\n");

	
		DEBUGLOG("[DEBUG] : red_8.redzone[0] = %x, red_8.redzone[1] = %x\n", red_8.redzone[0], red_8.redzone[1]);

		*trans_ptr = red_8;		
		DEBUGLOG("[DEBUG] : init_front_redzone - 3\n");																																												
		unsigned address = (unsigned) front_rz;					
		unsigned higher_index = 															
			( address >> RZ_HIGHER_ADDR_BITS);									
		unsigned lower_index = 																
		((address & RZ_LOWER_CHAR_ADDR_MSK) >> 								
		 	RZ_NUMBER_OF_BITS);																	
																													
		DEBUGLOG("[DEBUG] : init_front_redzone - 4\n");
		DEBUGLOG("[DEBUG] : init_front_redzone - zone_map 0x%08x high: 0x%08x low: 0x%08x\n", \
                (((unsigned char *) zone_map[higher_index]) + lower_index), higher_index, zone_map);
		*(((unsigned char *) zone_map[higher_index]) + lower_index)			
			|= 0xFF;																						
		DEBUGLOG("[DEBUG] : init_front_redzone - 5\n");
	}

	else if (redzone_size == 16) {													
																													
		trans_16 *trans_ptr = (trans_16 *) front_rz;		
		*trans_ptr =  red_16;																	
																													
		unsigned address = (unsigned) front_rz;					
		unsigned higher_index = 															
			( address >> RZ_HIGHER_ADDR_BITS);									
		unsigned lower_index = 																
		((address & RZ_LOWER_CHAR_ADDR_MSK) >> 								
		 	RZ_NUMBER_OF_BITS);																	
																													
		*((unsigned short *)(((unsigned char *) zone_map[higher_index]) 					
								+ lower_index))	|= 0xFFFF;								
																													
	}																												
	else if (redzone_size == 24){														
		memset(front_rz, zone_value, 24);										
																													
		unsigned address = (unsigned) front_rz;					
		unsigned higher_index = 															
			( address >> RZ_HIGHER_ADDR_BITS);									
		unsigned lower_index = 																
		((address & RZ_LOWER_CHAR_ADDR_MSK) >> 								
		 	RZ_NUMBER_OF_BITS);																	
		*((unsigned *)(((char *) zone_map[higher_index]) 			
								+ lower_index)) |= 0x00FFFFFF;							
																													
	}																												
	
	else																										
		abort();																															
    DEBUGLOG("[Debug] : Exiting init_front_redzone (0x%08x, %u)\n", front_rz, front_rz_size);
}			


/*	A function to uninitialize an AREA OF FRONT REDZONE ONLY with redzone values and also mark the
*	bitmap.
*
*	This function is used to uninitialize redzone of individual field in SuperStruct and incomplete
*	structures.
* */
void uninit_front_redzone (void* front_rz, unsigned front_rz_size)
{
	assert (front_rz != NULL);
	assert (front_rz_size != 0);

	unsigned redzone_size = front_rz_size;					

    redzone_size = front_rz_size > 24 ? 24: front_rz_size;
    //DEBUGLOG("[Debug] : uninit_front_redzone (0x%08x, %u)\n", front_rz, front_rz_size);																							
	if (redzone_size == 8) {																
																												 	
		unsigned address = (unsigned) front_rz;
		unsigned higher_index = 															
			( address >> RZ_HIGHER_ADDR_BITS);									
		unsigned lower_index = 																
		((address & RZ_LOWER_CHAR_ADDR_MSK) >> 								
		 	RZ_NUMBER_OF_BITS);																	
																													
		*(((char *) zone_map[higher_index]) + lower_index)			
			&= 0x00;																						
	}

	else if (redzone_size == 16) {													
																													
		unsigned address = (unsigned) front_rz;					
		unsigned higher_index = 															
			( address >> RZ_HIGHER_ADDR_BITS);									
		unsigned lower_index = 																
		((address & RZ_LOWER_CHAR_ADDR_MSK) >> 								
		 	RZ_NUMBER_OF_BITS);																	
																													
		*((short *)(((char *) zone_map[higher_index])					
								+ lower_index))	&= 0x0000;								
																													
	}																												

	else if (redzone_size == 24){														
																													
		unsigned address = (unsigned) front_rz;					
		unsigned higher_index = 															
			( address >> RZ_HIGHER_ADDR_BITS);									
		unsigned lower_index = 																
		((address & RZ_LOWER_CHAR_ADDR_MSK) >>								
		 	RZ_NUMBER_OF_BITS);																	
		*((unsigned *)(((char *) zone_map[higher_index]) 			
								+ lower_index)) &= 0xFF000000;							
	}																												

	else																										
		abort();																							
																													
}

/*	A function to initialize an AREA OF REAR REDZONE ONLY with redzone values and also mark the
*	bitmap.
*
*	This function is used to initialize redzone of last extra field in SuperStruct.
* */
void init_rear_redzone (void* rear_rz, unsigned rear_rz_size)
{
//	rear_rz_size = 8U;
	assert (rear_rz != NULL);
	assert (rear_rz_size != 0);

	unsigned redzone_size = rear_rz_size;					

    redzone_size = rear_rz_size > 24 ? 24: rear_rz_size;
    //DEBUGLOG("[Debug] : init_rear_redzone (0x%08x, %u)\n", rear_rz, rear_rz_size);																							
	if (redzone_size == 8) {																
																													
		trans_8 *trans_ptr = (trans_8 *) rear_rz;				
		*trans_ptr = red_8;																		
																													
		unsigned address = (unsigned) rear_rz;					
		unsigned higher_index = 															
			( address >> RZ_HIGHER_ADDR_BITS);									
		unsigned lower_index = 																
		((address & RZ_LOWER_CHAR_ADDR_MSK) >> 								
		 	RZ_NUMBER_OF_BITS);																	
																													
		*(((unsigned char *) zone_map[higher_index]) + lower_index)			
			|= 0xFF;																						
	}

	else if (redzone_size == 16) {													
																													
		trans_16 *trans_ptr = (trans_16 *) rear_rz;			
		*trans_ptr =  red_16;																	
																													
		unsigned address = (unsigned) rear_rz;					
		unsigned higher_index = 															
			( address >> RZ_HIGHER_ADDR_BITS);									
		unsigned lower_index = 																
		((address & RZ_LOWER_CHAR_ADDR_MSK) >> 								
		 	RZ_NUMBER_OF_BITS);																	
																													
		*((unsigned short *)(((unsigned char *) zone_map[higher_index]) 					
								+ lower_index)) |= 0xFFFF;									
	}																												

	else if (redzone_size == 24){														
		memset(rear_rz, zone_value, 24);											
																													
		unsigned address = (unsigned) rear_rz;					
		unsigned higher_index = 															
			( address >> RZ_HIGHER_ADDR_BITS);									
		unsigned lower_index = 																
		((address & RZ_LOWER_CHAR_ADDR_MSK) >> 								
		 	RZ_NUMBER_OF_BITS);																	
		*((unsigned *)(((char *) zone_map[higher_index]) 			
								+ lower_index)) |= 0x00FFFFFF;							
	}							

	else																										
		abort();																															
}

/*	A function to uninitialize an AREA OF REAR REDZONE ONLY by marking the
*	bitmap. For better performance, we don't uninitialize the redzone itself.
*
*	This function is used to uninitialize redzone of last extra field in SuperStruct.
* */
void uninit_rear_redzone (void* rear_rz, unsigned rear_rz_size)
{
	assert (rear_rz != NULL);
	assert (rear_rz_size != 0);

	unsigned redzone_size = rear_rz_size;					

    redzone_size = rear_rz_size > 24 ? 24: rear_rz_size;
    //DEBUGLOG("[Debug] : uninit_rear_redzone (0x%08x, %u)\n", rear_rz, rear_rz_size);																							
																													
	if (redzone_size == 8) {																
																													
		unsigned address = (unsigned) rear_rz;					
		unsigned higher_index = 															
			( address >> RZ_HIGHER_ADDR_BITS);									
		unsigned lower_index = 																
		((address & RZ_LOWER_CHAR_ADDR_MSK) >> 								
		 	RZ_NUMBER_OF_BITS);																	
																													
		*(((char *) zone_map[higher_index]) + lower_index)			
			&= 0x00;																						
	}						

	else if (redzone_size == 16) {													
																													
		unsigned address = (unsigned) rear_rz;					
		unsigned higher_index = 															
			( address >> RZ_HIGHER_ADDR_BITS);									
		unsigned lower_index = 																
		((address & RZ_LOWER_CHAR_ADDR_MSK) >> 								
		 	RZ_NUMBER_OF_BITS);																	
																													
		*((short *)(((char *) zone_map[higher_index]) +				
								+ lower_index)) &= 0x0000;								
																													
	}																												

	else if (redzone_size == 24){														
																													
		unsigned address = (unsigned) rear_rz;					
		unsigned higher_index = 															
			( address >> RZ_HIGHER_ADDR_BITS);									
		unsigned lower_index = 																
		((address & RZ_LOWER_CHAR_ADDR_MSK) >> 								
		 	RZ_NUMBER_OF_BITS);																	
		*((unsigned *)(((char *) zone_map[higher_index]) 			
								+ lower_index)) &= 0xFF000000;							
	}																												

	else																										
		abort();																							
																													
}


/*
 * TODO: 
 * Niranjan: This is commented currently as it is not needed.
 */
#if 0

/*	Note that during uninitialization its not necessary to remark the ptr
*	area with anything. HOWEVER it is important to uninitialize the bitmap.
*	However we will do it too as we cannot afford large parts of stack getting
*	painted with the redzone value.
*	Note that this init_redzone can only be used for stack variables where it
*	is guaranteed apriori that bitmap pages corresponding to the stack have
*	been allocated.
* */
#define uninit_superstruct_redzones(obj) 			do {										
		unsigned address = (unsigned) (&obj);		
		unsigned higher_index = 				
			( address >> RZ_HIGHER_ADDR_BITS);	
		unsigned lower_index = 					
		((address & RZ_LOWER_CHAR_ADDR_MSK) >> 		
		 	RZ_NUMBER_OF_BITS);					
		unsigned byte_count = ((unsigned)sizeof(obj)); 
		if ((byte_count % 8) != 0) 
			abort(); 
		if ((address % 8) != 0) 
			abort(); 
							
		char * curr_addr = address; 
			
		while(byte_count > 0) { 
			
		char *next_page_boundary = 
		(char *)((higher_index + 1) << RZ_HIGHER_ADDR_BITS); 
		unsigned int page_addr_remaining = (next_page_boundary - curr_addr); 
			
		unsigned int bits_to_set = (byte_count <= page_addr_remaining)? 
										byte_count : page_addr_remaining; 
			
		memset( (((char *) zone_map[higher_index]) + lower_index), 
						0, (bits_to_set g 8)); 
			
		curr_addr = (char *)((++higher_index) << RZ_HIGHER_ADDR_BITS); 
		lower_index = 0; 
		byte_count -= bits_to_set; 
		} 
		
		/*
		unsigned int bitmap_byte_count = (byte_count g 8); 
		unsigned bytes_to_set = 0; 
			
		do { 
		  unsigned rem_index_on_currpage = ((0x01 << 13) - lower_index); 
			unsigned rem_bytes_on_currpage = (rem_index_on_currpage); 
			if(rem_bytes_on_currpage < bitmap_byte_count) 
					bytes_to_set = rem_bytes_on_currpage; 
			else 
					bytes_to_set = bitmap_byte_count; 
			if(bytes_to_set != 0) 
				memset((((char*)zone_map[higher_index]) + lower_index),0x00, bytes_to_set);  
			bitmap_byte_count -= bytes_to_set; 
			if(bitmap_byte_count <= 0) 
					break; 
			else 
			{ 
					higher_index++; 
					lower_index = 0; 
			} 
	 	} while(1);  */ 
			
} while (0)

/*	The macro below is the "partial" initialization of a variable that has
*	been defined AND initialized in the definition itself.
*	Hence all that needs to be done is the setting of the bitmap. Hence the
*	term partiial
*	Note that there is no need to do any init checks because we know this can
*	be called by only the file that has the variable definition.
*	*/
#define	partial_init(obj)			do { 
															
	obj##_init__ = 1;									
	ensure_addr_bitmap(&(obj), 								
			(((char *)&(obj)) + sizeof(obj)));				
															
	unsigned redzone_size = rear_rz_size;	
																				
	if (redzone_size == 8) {							
		unsigned address = (unsigned)&obj;		
		unsigned higher_index = 				
			( address >> RZ_HIGHER_ADDR_BITS);	
		unsigned lower_index = 					
		((address & RZ_LOWER_CHAR_ADDR_MSK) >> 		
		 	RZ_NUMBER_OF_BITS);					
												
		*(((char *) zone_map[higher_index]) + lower_index)				
			&= 0x00;													
		*(((char *) zone_map[higher_index]) + lower_index + 2)			
			&= 0x00;													
	}											
	else if (redzone_size == 16) {					
		unsigned address = (unsigned)&obj;		
		unsigned higher_index = 				
			( address >> RZ_HIGHER_ADDR_BITS);	
		unsigned lower_index = 					
		((address & RZ_LOWER_CHAR_ADDR_MSK) >> 		
		 	RZ_NUMBER_OF_BITS);					
												
		*((short *)(((char *) zone_map[higher_index]) + lower_index))
			&= 0x0000;							
		*((short *)(((char *) zone_map[higher_index]) + lower_index + 4))
			&= 0x0000;							
												
	}											
	else if (redzone_size == 24){					
		unsigned address = (unsigned)front_rz;		
		unsigned higher_index = 				
			( address >> RZ_HIGHER_ADDR_BITS);	
		unsigned lower_index = 					
		((address & RZ_LOWER_CHAR_ADDR_MSK) >> 		
		 	RZ_NUMBER_OF_BITS);					
		*((unsigned *)(((char *) zone_map[higher_index]) + lower_index))
			&= 0xFF000000;						
												
		address = (unsigned) rear_rz;		
		higher_index = 							
			( address >> RZ_HIGHER_ADDR_BITS);	
		lower_index = 							
		((address & RZ_LOWER_CHAR_ADDR_MSK) >> 		
		 	RZ_NUMBER_OF_BITS);					
		*((unsigned *)(((char *) zone_map[higher_index]) + lower_index))
			&= 0xFF000000;						
												
	}											
	else										
		abort();								
} while(0)

/*
*	Note that the macro below holds for the case when the variable has been
*	defined in the given file BUT not initialized. Thus even the setting of
*	values in the redzone must be done here.
*	*/
#define	complete_init(var_name)		do {															
if (! var_name##_init__) { 									
															
	var_name##_init__ = 1;									
	ensure_addr_bitmap(&(var_name), 						
			(((char *)&(var_name)) + sizeof(var_name)));	
	init_both_redzones(var_name);								
															
}															
} while (0)														


/=============================================================================

/*	The macro below is the "partial" initialization of a variable that has
*	been defined AND initialized in the definition itself.
*	Hence all that needs to be done is the setting of the bitmap. Hence the
*	term partiial
*	Note that there is no need to do any init checks because we know this can
*	be called by only the file that has the variable definition.
*	*/
#define	front_partial_init(obj)		do { 
															
	obj##_init__ = 1;										
	obj##_ptr = &(obj.orig_var)								
	ensure_addr_bitmap(&(obj), 								
			(((char *)&(obj)) + sizeof(obj)));				
															
	unsigned redzone_size = front_rz_size;			
	if (redzone_size == 8) {								
		unsigned address = (unsigned)&obj;		
		unsigned higher_index = 				
			( address >> RZ_HIGHER_ADDR_BITS);	
		unsigned lower_index = 					
		((address & RZ_LOWER_CHAR_ADDR_MSK) >> 		
		 	RZ_NUMBER_OF_BITS);					
												
		*(((char *) zone_map[higher_index]) + lower_index)				
			&= 0x00;													
	}											
	else if (redzone_size == 16) {					
		unsigned address = (unsigned)&obj;		
		unsigned higher_index = 				
			( address >> RZ_HIGHER_ADDR_BITS);	
		unsigned lower_index = 					
		((address & RZ_LOWER_CHAR_ADDR_MSK) >> 		
		 	RZ_NUMBER_OF_BITS);					
												
		*((short *)(((char *) zone_map[higher_index]) + lower_index))
			&= 0x0000;							
												
	}											
	else if (redzone_size == 24){					
		unsigned address = (unsigned)front_rz;		
		unsigned higher_index = 				
			( address >> RZ_HIGHER_ADDR_BITS);	
		unsigned lower_index = 					
		((address & RZ_LOWER_CHAR_ADDR_MSK) >> 		
		 	RZ_NUMBER_OF_BITS);					
		*((unsigned *)(((char *) zone_map[higher_index]) + lower_index))
			&= 0xFF000000;						
												
	}											
	else										
		abort();								
} while(0)

/*
*	Note that the macro below holds for the case when the variable has been
*	defined in the given file BUT not initialized. Thus even the setting of
*	values in the redzone must be done here.
*	*/
#define	front_complete_init(obj)																
do {														
if (! obj##_init__) { 									
														
	obj##_init__ = 1;									
	obj##_ptr = &(obj.orig_var)							
	ensure_addr_bitmap(&(obj), 							
			(((char *)&(obj)) + sizeof(obj)));			
	init_front_redzone(obj);							
														
}														
} while (0)													



/*	The objective of the following macro is to set values in structures to the
*	supplied value. This is done through a pointer specifically because the
*	particular field could be a const which could never be assigned through
*	legal means.
* */
#define	correct_struct_field(type_expr, target, value)											
do {														
typeof(type_expr) ptr = &target;						
*ptr = value;											
} while (0)													

#endif

void is_char_red (unsigned int value,
				unsigned int orig_value_size,
				const void* ptr)
{

	//DEBUGLOG("[DEBUG] : is_char_red - start\n");																												 
	unsigned rz_value_size = (orig_value_size < 				 
					sizeof(value)) ? 															
					orig_value_size : sizeof(value);

	unsigned int rz_abort_arg;
																												 
	DEBUGLOG("[Deubg] : is_char_red (value %u, size %u, ptr 0x%08x)\n", value, rz_value_size, ptr);																												 
	if (rz_value_size == 1)																 {
		rz_abort_arg = (															 
				(value & 0xff) == '\x17'); 													}	 
	else if (rz_value_size == 2)													 
		rz_abort_arg = (																		 
				(value & 0xffff) == 0x1717); 												 
	else if (rz_value_size == 4)													 
		rz_abort_arg = (																		 
				(value) == 0x17171717); 												 
	else 																									 
		rz_abort_arg = (*((int *)(ptr)) == 0x17171717);			 
																												 
	//DEBUGLOG("[DEBUG] : rz_abort_arg = %u\n", rz_abort_arg);																												 
	if (unlikely(rz_abort_arg))
{
		 
	//	DEBUGLOG("[DEBUG] : unlikely - rz_abort_arg%u\n");																												 
		is_redzone(ptr);													 	 
}
}


/*	The basic objective of this method is to check whether an array access is
  *	safe. It just compares the index used with size of the array.	
  *	Its just being made into a function so that it can be used by CIL
  *	transformer
  *	Note that this is NOT supposed to be used with either:
  *	1.	Arrays within structs	
  *	2.	Arrays with length not specified	*/

unsigned is_array_acc_unsafe (unsigned int index, unsigned int array_size)
{
	if (index > array_size)
		return RZ_TRUE;

	return RZ_FALSE;
}

/********************************
 * Stack bitmap setup functions
 ********************************/

void ensure_addr_bitmap (void *addr_start, void *addr_end)
{
		unsigned curr_higher_index, final_higher_index;

		curr_higher_index = ((unsigned)addr_start) >> RZ_HIGHER_ADDR_BITS;
		final_higher_index = ((unsigned)addr_end) >> RZ_HIGHER_ADDR_BITS;

		do {
			if (likely((unsigned int) zone_map[curr_higher_index]))
				continue;
			else
				alloc_bitmap_page(curr_higher_index);
			
		}
		while(unlikely(++curr_higher_index <= final_higher_index));

}

//	This function is called at the start of each function call. The basic
//	objective of this function is to ensure that the bitmap pages
//	corresponding to the entire current stack frame are present in our bitmap.
//	The flag formal parameter specifies whether the current function has any
//	transformed variable. The point being that if the current function does
//	not have any transformed local variables then we should not be be
//	executing the function.
//void ensure_sframe_bitmap(void* frame_start, void* frame_end)
void ensure_sframe_bitmap(void)
{
    void * frame_start, *frame_end;

    frame_start = __builtin_frame_address(0);
    frame_end  =  __builtin_frame_address(1);

    DEBUGLOG("[DEBUG] ensure_sframe fstart 0x%08x fend 0x%08x\n", frame_start, frame_end);

    ensure_addr_bitmap (frame_start, frame_end);
}

// [DEBUG: added the below definitions from zcheck.c]

//=============================================================================
//	Note that for the time being we are forced to place this function in the
//	static library because of it requiring access to pthread functions. 
//
void
alloc_bitmap_page(unsigned higher_index)
{
	unsigned lock_index;
	//	Lets get down first to the business of allocating the page.
	//=================================================================
	/*	Determine the lock to be used. We use the mod Prime-number
	 *	method to ensure uniform distribution(???)	*/
	lock_index = higher_index % MT_ARRAY_SIZE;

	/*	This syntax has been picked up from malloc.c	*/
	(void)pthread_mutex_lock(&zonemap_acc_lock[lock_index]);

	/*	Note that we need to perform the check again because somebody
	 *	else may already have allocated the page while we were waiting
	 *	for it.	*/
	if(zone_map[higher_index] == 0) 
		if((zone_map[higher_index] = 
			//glibc_calloc(RZ_MAP_SIZE, sizeof(unsigned))) == 0)
			calloc(RZ_MAP_SIZE, sizeof(unsigned))) == 0)
			exit (1);

	(void)pthread_mutex_unlock(&zonemap_acc_lock[lock_index]);

}

//=============================================================================

void
is_redzone(void * ptr)
{
/*	The basic idea of this macro is that we will return only false value. This
 *	will help us evaluate what is the overhead of just making the call to this
 *	function and NOTHING ELSE.
 * */
#ifdef	RZ_DUMMY_CHECK
	//DEBUGLOG("[DEBUG] : In is_redzone - 1\n");
	return; 
#else
/*	The basic objective here is to pass the pointer to the stack variable
 *	where the pointer is stored. Since the stack variable will always be the
 *	same, its address will be unique per function, that the compiler will
 *	hopefully and NOT use a register to compute it. This strategy is gonna
 *	results in lots of writes that MAY NOT matter. Will have to check.
 * */

	//DEBUGLOG("[DEBUG] : In is_redzone - 2\n");
	unsigned index = (unsigned)ptr;
//	asm volatile ("movd %%mm0, %0\n" : "=r" (index) : );

	unsigned higher_index = index >> RZ_HIGHER_ADDR_BITS;
	unsigned lower_index = (index & RZ_LOWER_ADDR_MSK) >> RZ_BIT_POSITION_BITS;
	unsigned bit_position = index & RZ_BIT_POS_MSK;

	if(zone_map[higher_index] != NULL_PTR)
		if(zone_map[higher_index][lower_index] &  (unsigned)(1 << bit_position))
			abort();

	return;
#endif
}


//=============================================================================

#ifndef	RZ_TEST_MARKING

//=============================================================================

/*	The basic objective of this function is to mark the bits in the bitmap
 *	with 0 from given address for given number of bytes.
 *	Note that now we will now have three more invariants for these functions.
 *
 *	1.	The size of redzones to be marked must be a multiple of 8 bytes.
 *	2.	The redzones will be aligned on 8 byte boundaries.
 *	3.	The pages in bitmap will be allocated a-priori. Checking for that is
 *		NOT the responsibility of this function.
 *	*/
void 
mark_redzone(void *address, unsigned int bit_count)
{	
	char * curr_addr = address;
	unsigned index = (unsigned)address;

	//	While we acknowledge that the bitmap page is actually maintained as an
	//	array of unsigned ints, we will be accessing it as an array of
	//	unsigned characters.
	u_int32_t higher_index = (index >> RZ_HIGHER_ADDR_BITS);
	u_int32_t lower_index = (index & RZ_LOWER_CHAR_ADDR_MSK) >> RZ_NUMBER_OF_BITS;

	while(bit_count) {
		
		char *next_page_boundary = 
			(char *)((higher_index + 1) << RZ_HIGHER_ADDR_BITS);
		u_int32_t page_addr_remaining = (next_page_boundary - curr_addr);

		u_int32_t bits_to_set = (bit_count <= page_addr_remaining)? 
										bit_count : page_addr_remaining;

		//	Note that while we are measuring everything in terms of number of
		//	addresses that we will be setting, while supplying the value to
		//	memset, we must divide bits_to_set to get the number of bytes that
		//	memset will need to set.
		memset( (((char *)zone_map[higher_index]) + lower_index), 
				0xFF, (bits_to_set / 8));

		curr_addr = (char *)((++higher_index) << RZ_HIGHER_ADDR_BITS);
		lower_index = 0;
		bit_count -= bits_to_set;
	}
}


/*	The basic objective of this function is to mark the bits in the bitmap
 *	with 0 from given address for given number of bytes.
 *	Note that now we will now have three more invariants for these functions.
 *
 *	1.	The size of redzones to be marked must be a multiple of 8 bytes.
 *	2.	The redzones will be aligned on 8 byte boundaries.
 *	3.	The pages in bitmap will be allocated a-priori. Checking for that is
 *		NOT the responsibility of this function.
 *	*/
void 
unmark_redzone(void *address, unsigned int bit_count)
{	
	char * curr_addr = address;
	unsigned index = (unsigned)address;

	//	While we acknowledge that the bitmap page is actually maintained as an
	//	array of unsigned ints, we will be accessing it as an array of
	//	unsigned characters.
	u_int32_t higher_index = (index >> RZ_HIGHER_ADDR_BITS);
	u_int32_t lower_index = (index & RZ_LOWER_CHAR_ADDR_MSK) >> RZ_NUMBER_OF_BITS;

	while(bit_count) {
		
		char *next_page_boundary = 
			(char *)((higher_index + 1) << RZ_HIGHER_ADDR_BITS);
		u_int32_t page_addr_remaining = (next_page_boundary - curr_addr);

		u_int32_t bits_to_set = (bit_count <= page_addr_remaining)? 
										bit_count : page_addr_remaining;

		//	Note that while we are measuring everything in terms of number of
		//	addresses that we will be setting, while supplying the value to
		//	memset, we must divide bits_to_set to get the number of bytes that
		//	memset will need to set.
		memset( (((char *)zone_map[higher_index]) + lower_index), 
				0, (bits_to_set / 8));

		curr_addr = (char *)((++higher_index) << RZ_HIGHER_ADDR_BITS);
		lower_index = 0;
		bit_count -= bits_to_set;
	}
}

#else

void 
unmark_redzone(void *address, unsigned int bit_count) {}

void 
mark_redzone(void *address, unsigned int bit_count) {}

#endif	//	RZ_TEST_MARKING
//=============================================================================



