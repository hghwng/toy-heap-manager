void *malloc(size_t size) {
  void *ptr = NULL;
  if (size != 0) {
    if (size <= bucket_get_record_size(BUCKET_TYPE_MAX)) {
      ptr = record_alloc(size);
    } else {
      ptr = blob_alloc(size);
    }
  }
  dprint("DEBUG: malloc(%zu) = %p\n", size, ptr);
  return ptr;
}

void *calloc(size_t nmemb, size_t size) {
  dprint("DEBUG: calloc(%zu, %zu)\n", nmemb, size);
  void *ptr = malloc(nmemb * size);
  if (!ptr) return NULL;
  memset(ptr, 0, nmemb * size);
  return ptr;
}

void free(void *ptr) {
  if (!ptr) return;
  struct bucket_header *header = util_ptr_to_header(ptr);
  if (header->type == BUCKET_TYPE_BLOB) {
    blob_free(header);
  } else {
    size_t index = bucket_get_index(header, ptr);
    record_free(header, index);
  }
}

void *realloc(void *ptr, size_t size) {
  if (size == 0) {
    free(ptr);
    return NULL;
  }
  if (!ptr) return malloc(size);

  struct bucket_header *header = util_ptr_to_header(ptr);
  size_t max_avail;
  if (header->type == BUCKET_TYPE_BLOB) {
    max_avail = blob_get_size(header);
  } else {
    max_avail = bucket_get_record_size(header->type);
  }
  if (max_avail >= size) return ptr;

  void *new_address = malloc(size);
  if (ptr) memcpy(new_address, ptr, max_avail);
  free(ptr);

  dprint("DEBUG: realloc(%p, %zu) = %p\n", ptr, size, new_address);
  return new_address;
}
