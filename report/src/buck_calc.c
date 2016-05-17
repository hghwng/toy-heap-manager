/*
 * Get the max record size the given type of bucket can store.
 * i.e. data_size <= bucket_get_record_size(type)
 */
static inline size_t bucket_get_record_size(size_t type) {
  return 1ul << type;
}

/*
 * Calculate max number of records can store in a bucket.
 */
static inline size_t bucket_get_max_records(size_t type) {
  size_t body_size = PAGE_SIZE - sizeof(struct bucket_header);
  body_size -= sizeof(size_t) - 1;  // padding takes at most sizeof(size_t) - 1 bytes
  float total_size_per_record = bucket_get_record_size(type) + 1.0 / 8;
  return (size_t)(body_size / total_size_per_record);
}
