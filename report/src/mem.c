static void *virtual_alloc(size_t pages) {
  return mmap(NULL, pages * PAGE_SIZE, PROT_READ | PROT_WRITE,
              MAP_PRIVATE, g_fd, 0);
}

static void virtual_free(void *ptr, size_t pages) {
  int ret = munmap(ptr, pages);
  if (ret < 0) fprintf(stderr, "ERROR: virtual_free(%p, %zu)\n", ptr, pages);
}

