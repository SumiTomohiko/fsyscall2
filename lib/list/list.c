#include <stddef.h>

#include <fsyscall/private/list.h>

struct item *
list_search(struct list *list, bool (*cmp)(struct item *, void *), void *bonus)
{
	struct item *i;

	i = FIRST_ITEM(list);
	while (!IS_LAST(i) && !cmp(i, bonus))
		i = ITEM_NEXT(i);

	return (!IS_LAST(i) ? i : NULL);
}

void
initialize_list(struct list *list)
{
	struct item *head, *tail;

	head = &list->head_sentinel;
	tail = &list->tail_sentinel;
	head->prev = NULL;
	head->next = tail;
	tail->prev = head;
	tail->next = NULL;
	list->items = head;
}

void
remove_item(struct item *item)
{
	item->prev->next = item->next;
	item->next->prev = item->prev;
}

void
prepend_item(struct list *list, struct item *item)
{
	struct item *head = list->items;

	item->next = head->next;
	item->prev = head;
	head->next->prev = item;
	head->next = item;
}
