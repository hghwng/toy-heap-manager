static void *blob_alloc(size_t size) {
  size_t pages = (size + sizeof(struct bucket_header) + ALIGN_SIZE - 1) / PAGE_SIZE + 1;
  void *ptr = virtual_alloc(pages);
  if (!ptr) return NULL;

  struct bucket_header *header = (struct bucket_header *)ptr;
  header->type = BUCKET_TYPE_BLOB;
  header->blob.pages_allocated = pages;

  return (void *)util_align((size_t)&header->record_avail, ALIGN_SIZE);
}

static void blob_free(struct bucket_header *header) {
  virtual_free(header, header->blob.pages_allocated);
}

static size_t blob_get_size(struct bucket_header *header) {
  size_t end = (size_t)header + header->blob.pages_allocated * PAGE_SIZE;
  size_t size = end - (size_t)&header->record_avail;
  return size;
}

