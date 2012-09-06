#include <stddef.h>

#include <fsyscall/private/list.h>

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
prepend_item(struct list *list, struct item *item)
{
	struct item *head = list->items;

	item->next = head->next;
	item->prev = head;
	head->next->prev = item;
	head->next = item;
}
