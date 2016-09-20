#ifndef MALLOC_H_   /* Include guard */
#define MALLOC_H_

void* malloc(size_t size);
void free(void* ptr);
void* calloc(size_t num, size_t size);
void* realloc(void *ptr, size_t size);

#endif // MALLOC_H_