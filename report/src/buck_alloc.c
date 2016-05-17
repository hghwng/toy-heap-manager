static void *record_alloc(size_t size) {
  size_t type;
  if (size < bucket_get_record_size(BUCKET_TYPE_MIN)) {
    type = BUCKET_TYPE_MIN;
  } else {
    // E.g. 0b101 .. 0b1000 -> type 3
    type = 8 * sizeof(unsigned int) - __builtin_clz((unsigned int)(size - 1));
  }

  // Create new bucket if needed
  struct list_head *head = g_free + type;
  if (list_empty(head) && !bucket_alloc(type)) return NULL;

  // Find an available (record, data) tuple
  size_t record_size = bucket_get_record_size(type);
  size_t record_num = bucket_get_max_records(type);
  struct bucket_header *header = list_first(g_free[type], struct bucket_header, bucket.list);

  size_t i = bitmap_find_one(&header->record_avail, record_num);
  if (i == -1ul) raise(SIGABRT);
  bitmap_clear(&header->record_avail, i);
  char *data = bucket_get_data(header, record_num) + record_size * i;
  dprint("DEBUG: record_alloc, header=%p i=%zu data=%p size=%zu\n", header, i, data, size);

  // Move to full if needed
  if (bitmap_count(&header->record_avail, record_num) == record_num - 1) {
    list_move(g_full + type, &header->bucket.list);
  }
  return data;
}

/*
 * Free the record given by index.
 */
static void record_free(struct bucket_header *header, size_t index) {
  size_t record_num = bucket_get_max_records(header->type);
  bitmap_set(&header->record_avail, index);

  size_t count = bitmap_count(&header->record_avail, record_num);
  if (count == 0) {
    bucket_free(header);
  } else {
    dprint("DEBUG: record_free header=%p, index=%zu, usage=%zu/%zu\n", header, index, count, record_num);
    list_move(g_free + header->type, &header->bucket.list);
  }
}

static bool record_can_realloc_inplace(struct bucket_header *header, size_t new_size) {
  size_t record_size = bucket_get_record_size(header->type);
  return new_size <= record_size;
}

