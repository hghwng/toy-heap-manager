struct list_head {
  struct list_head *next, *prev;
};

static inline void list_init(struct list_head *head) {
  head->next = head->prev = head;
}

static inline void list_add(struct list_head *head, struct list_head *obj) {
  obj->next = head->next;
  obj->prev = head;
  head->next = obj;
  obj->next->prev = obj;
}

static inline void list_del(struct list_head *obj) {
  obj->prev->next = obj->next;
  obj->next->prev = obj->prev;
}

static inline bool list_empty(struct list_head *head) {
  return head->next == head;
}

static inline void list_move(struct list_head *head, struct list_head *obj) {
  list_del(obj);
  list_add(head, obj);
}

#define LIST_HEAD(name) \
  struct list_head name = {&(name), &(name)}

#define list_first(head, type, member) \
  list_entry((head).next, type, member)
