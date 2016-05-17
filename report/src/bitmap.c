struct bitmap {
  uint64_t block[0];
};

static inline size_t bitmap_get_size(size_t num_elements) {
  size_t bytes = num_elements / 8 + (num_elements % 8 ? 1 : 0);
  return bytes % 8 ? (bytes / 8 + 1) * 8 : bytes;
}

static inline void bitmap_init(struct bitmap *map, size_t size, int init_val) {
  memset(map->block, init_val ? -1 : 0, size);
}

static inline void bitmap_set(struct bitmap *map, size_t index) {
  map->block[index / 64] |= 1ull << (index % 64);
}

static inline void bitmap_clear(struct bitmap *map, size_t index) {
  map->block[index / 64] &= ~(1ull << (index % 64));
}

static inline bool bitmap_test(struct bitmap *map, size_t index) {
  return map->block[index / 64] & (1u << (index % 64));
}

