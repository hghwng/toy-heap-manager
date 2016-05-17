static inline size_t util_align(size_t size, size_t align) {
  // size % align: remaining bytes
  // align - size % align: bytes to pad
  // (align - size % align) % align: handle cases where (size % align == 0) already
  return size + (align - size % align) % align;
}
