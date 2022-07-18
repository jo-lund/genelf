#include <stdlib.h>

#define ARRAY_SIZE(x) (sizeof(x) / sizeof((x)[0]))

static inline void *xmalloc(size_t size)
{
    void *p;

    if ((p = malloc(size)) == NULL)
        exit(0);
    return p;
}

static inline void *xcalloc(size_t nmemb, size_t size)
{
    void *p;

    if ((p = calloc(nmemb, size)) == NULL)
        exit(0);
    return p;
}

static inline void *xrealloc(void *ptr, size_t size)
{
    if ((ptr = realloc(ptr, size)) == NULL)
        exit(0);
    return ptr;
}
