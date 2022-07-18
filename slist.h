#ifndef SLIST_H
#define SLIST_H

#define SLIST_FOREACH(l) \
    for (; (l); (l) = (l)->next)

struct slist {
    struct slist *next;
};

typedef int (*slist_cmp)(const struct slist *p1, const struct slist *p2);

/* Add element sorted based on the slist_cmp function */
static inline void slist_add(struct slist *head, struct slist *n, slist_cmp fn)
{
    struct slist **t = &head;

    while (*t) {
        if (fn(n, *t) < 0) {
            n->next = *t;
            break;
        }
        t = &(*t)->next;
    }
    *t = n;
}

static inline void slist_append(struct slist *head, struct slist *n)
{
    struct slist **t = &head;

    while (*t) {
        t = &(*t)->next;
    }
    *t = n;
}

static inline void slist_remove(struct slist *head, struct slist *n)
{
    struct slist **t = &head;

    while (*t) {
        if (*t == n) {
            *t = (*t)->next;
        }
        t = &(*t)->next;
    }
}

static inline unsigned int slist_size(struct slist *head)
{
    unsigned int size = 0;

    while (head) {
        size++;
        head = head->next;
    }
    return size;
}

#endif
