#if !defined(FSYSCALL_PRIVATE_LIST_H_INCLUDED)
#define FSYSCALL_PRIVATE_LIST_H_INCLUDED

struct item {
	struct item *prev;
	struct item *next;
};

struct list {
	struct item *items;
	struct item head_sentinel;
	struct item tail_sentinel;
};

void initialize_list(struct list *);
void prepend_item(struct list *, struct item *);

#define	FIRST_ITEM(list)	(list)->items->next
#define	PREPEND_ITEM(list, i)	prepend_item((list), (struct item *)(i))

#endif
