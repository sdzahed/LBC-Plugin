#ifndef MALLOCINSTR_H
#define MALLOCINSTR_H

void* mymalloc(size_t, const void*);
void myfree(void*, const void*);
void* myrealloc(void*, size_t, const void*);
void* mymemalign(size_t, size_t, const void*);

unsigned int debug;

#define MY_PRINTF(stmt){if(debug) stmt;}

#define LBC_MALLOC public_mALLOc
#define LBC_FREE public_fREe
#define LBC_REALLOC public_rEALLOc
#define LBC_MEMALIGN public_mEMALIGn

extern void* LBC_MALLOC(size_t);
extern void LBC_FREE(void*);
extern void* LBC_REALLOC(void*, size_t);
extern void* LBC_MEMALIGN(size_t, size_t);

#endif
