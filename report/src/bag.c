struct bucket_header {
  union {
    struct {
      struct list_head list;
    } bucket;

    struct {
      size_t pages_allocated;
    } blob;
  };

  uint8_t type;
  struct bitmap record_avail;
};

