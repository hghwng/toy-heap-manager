static inline char *bucket_get_data(struct bucket_header *hdr, size_t num_records) {
  return (char *)&hdr->record_avail + bitmap_get_size(num_records);
}

/*
 * Get index from data pointer.
 */
static size_t bucket_get_index(struct bucket_header *header, void *ptr) {
  size_t record_num = bucket_get_max_records(header->type);
  void *data = bucket_get_data(header, record_num);
  return ((size_t)ptr - (size_t)(data)) / bucket_get_record_size(header->type);
}

/*
 * Get the bucket header associated with the pointer to user data.
 */
static inline struct bucket_header *util_ptr_to_header(void *ptr) {
  return (struct bucket_header *)((size_t)ptr & PAGE_BEGIN_MASK);
}
