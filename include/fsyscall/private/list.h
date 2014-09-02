#if !defined(FSYSCALL_PRIVATE_LIST_H_INCLUDED)
#define FSYSCALL_PRIVATE_LIST_H_INCLUDED

#include <stdbool.h>

struct item {
	struct item *prev;
	struct item *next;
};

struct list {
	struct item *items;
	struct item head_sentinel;
	struct item tail_sentinel;
};

void	initialize_list(struct list *);
void	prepend_item(struct list *, struct item *);
void	remove_item(struct item *);
struct item
	*list_search(struct list *, bool (*)(struct item *, void *), void *);

#define	FIRST_ITEM(list)	(list)->items->next
#define	ITEM_NEXT(i)		((struct item *)(i))->next
#define	PREPEND_ITEM(list, i)	prepend_item((list), (struct item *)(i))
#define	REMOVE_ITEM(i)		remove_item((struct item *)(i))
#define	IS_LAST(i)		(ITEM_NEXT((i)) == NULL)
#define	IS_EMPTY(list)		(ITEM_NEXT(FIRST_ITEM((list))) == NULL)

#endif
