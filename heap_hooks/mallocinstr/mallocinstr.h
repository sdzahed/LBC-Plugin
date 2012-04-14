#ifndef MALLOCINSTR_H
#define MALLOCINSTR_H

void* mymalloc(size_t, const void*);
void myfree(void*, const void*);
void* myrealloc(void*, size_t, const void*);
void* mymemalign(size_t, size_t, const void*);

#endif
