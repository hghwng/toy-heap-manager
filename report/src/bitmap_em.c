static inline size_t bitmap_find_one(struct bitmap *map, size_t num_elements) {
  size_t num_blocks = num_elements / 64;
  if (num_elements % 64) map->block[num_blocks++] &= (1ull << (num_elements % 64)) - 1;

  for (size_t i = 0; i < num_blocks; ++i) {
    if (!map->block[i]) continue;
    size_t pos = __builtin_ctzll(map->block[i]);
    return i * 64 + pos;
  }

  return -1;
}

static inline size_t bitmap_count(struct bitmap *map, size_t num_elements) {
  size_t num_blocks = num_elements / 64;
  if (num_elements % 64) map->block[num_blocks++] &= (1ull << (num_elements % 64)) - 1;

  size_t ret = 0;
  for (size_t i = 0; i < num_blocks; ++i) {
    ret += __builtin_popcountll(map->block[i]);
  }

  return ret;
}

