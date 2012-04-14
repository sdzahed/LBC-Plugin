#ifndef HASHTABLE_H
#define HASHTABLE_H

void init_hashtable();
size_t get_size(const void* addr);
int insert_addr(const void* addr, size_t size);
int update_addr(void* oldaddr, const void* newaddr, size_t newsize);
int free_addr(void* addr);
void free_table();

#endif

