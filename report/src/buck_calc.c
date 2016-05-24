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
  size_t body_bits = (PAGE_SIZE - sizeof(struct bucket_header)) * 8;
  body_bits -= 64;                  // spaces for the reminder bits of bitmap
  float bits_per_record = bucket_get_record_size(type) * 8 + 1;
  return body_bits / bits_per_record;
}

