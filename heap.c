#include <sys/mman.h>
#include <signal.h>
#include <fcntl.h>
#include <memory.h>
#include <assert.h>
#include <stdio.h>
#include "list.h"
#include "heap.h"

#ifdef DEBUG
# define dprint(...) fprintf(stderr, __VA_ARGS__)
# define iprint(...) fprintf(stderr, __VA_ARGS__)
#else
# define dprint(...)
# define iprint(...)
#endif

static struct list_head g_free[BUCKET_TYPE_NUM];
static struct list_head g_full[BUCKET_TYPE_NUM];
static int g_fd;

/*
 * Pad size such that (size % align == 0).
 */
static inline size_t util_align(size_t size, size_t align) {
  // size % align: remaining bytes
  // align - size % align: bytes to pad
  // (align - size % align) % align: handle cases where (size % align == 0) already
  return size + (align - size % align) % align;
}

/*
 * Get the bucket header associated with the pointer to user data.
 */
static inline struct bucket_header *util_ptr_to_header(void *ptr) {
  return (struct bucket_header *)((size_t)ptr & PAGE_BEGIN_MASK);
}

/*
 * Initialize free and full buckets and /dev/zero.
 */
__attribute__((constructor)) static void init() {
  dprint("DEBUG: init\n");
  g_fd = open("/dev/zero", O_RDWR);
  if (g_fd < 0) raise(SIGABRT);
  for (int i = 0; i < BUCKET_TYPE_NUM; ++i) {
    list_init(g_free + i);
    list_init(g_full + i);
  }
}

/***************************
 *  Raw memory allocation  *
 ***************************/

static void *virtual_alloc(size_t pages) {
  return mmap(NULL, pages * PAGE_SIZE, PROT_READ | PROT_WRITE,
              MAP_PRIVATE, g_fd, 0);
}

static void virtual_free(void *ptr, size_t pages) {
  int ret = munmap(ptr, pages);
  if (ret < 0) fprintf(stderr, "ERROR: virtual_free(%p, %zu)\n", ptr, pages);
}

/******************************************
 *  Managed allocation for large objects  *
 ******************************************/

static void *blob_alloc(size_t size) {
  size_t pages = (size + sizeof(struct bucket_header) + ALIGN_SIZE - 1) / PAGE_SIZE + 1;
  void *ptr = virtual_alloc(pages);
  if (!ptr) return NULL;

  struct bucket_header *header = (struct bucket_header *)ptr;
  header->type = BUCKET_TYPE_BLOB;
  header->blob.pages_allocated = pages;

  return (void *)util_align((size_t)&header->bytes_used, ALIGN_SIZE);
}

static void blob_free(struct bucket_header *header) {
  virtual_free(header, header->blob.pages_allocated);
}

static bool blob_can_realloc_inplace(struct bucket_header *header, size_t new_size) {
  size_t end = (size_t)header + header->blob.pages_allocated * PAGE_SIZE;
  size_t avail = end - util_align((size_t)header->bytes_used, ALIGN_SIZE);
  return new_size <= avail;
}
/******************************************
 *  Managed allocation for small objects  *
 ******************************************/

/*
 * Get the max record size the given type of bucket can store.
 * i.e. data_size <= bucket_get_record_size(type)
 */
static inline size_t bucket_get_record_size(size_t type) {
  return 1ul << type;
}

static inline char *bucket_get_data(struct bucket_header *hdr, size_t num_records) {
  void *data = hdr->bytes_used + num_records;
  return (char *)util_align((size_t)data, ALIGN_SIZE);
}

/*
 * Calculate max number of records can store in a bucket.
 */
static inline size_t bucket_get_max_records(size_t type) {
  size_t body_size = PAGE_SIZE - sizeof(struct bucket_header);
  body_size -= sizeof(size_t) - 1;  // padding takes at most sizeof(size_t) - 1 bytes
  size_t total_size_per_record = bucket_get_record_size(type) + sizeof(uint16_t);
  return body_size / total_size_per_record;
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
 * Create a new bucket of given type, insert into the global list, then return
 * the bucket.
 */
static void *bucket_alloc(size_t type) {
  void *ptr = virtual_alloc(1);
  if (!ptr) return NULL;

  struct bucket_header *header = (struct bucket_header *)ptr;
  header->type = type;
  header->bucket.records_used = 0;
  list_add(g_free + type, &header->bucket.list);

  return ptr;
}

/*
 * Free the memory of the bucket, then remove it from the global list.
 */
static void bucket_free(struct bucket_header *bucket) {
  list_del(&bucket->bucket.list);
  virtual_free(bucket, 1);
}

/*
 * Allocate a record of given size from available buckets.
 */
static void *record_alloc(size_t size) {
  size_t type;
  if (size < bucket_get_record_size(BUCKET_TYPE_MIN)) {
    type = BUCKET_TYPE_MIN;
  } else {
    // E.g. 0b101 .. 0b1000 -> type 3
    type = 8 * sizeof(unsigned int) - __builtin_clz((unsigned int)(size - 1));
  }

  // Create new bucket if needed
  struct list_head *head = g_free + type;
  if (list_empty(head) && !bucket_alloc(type)) return NULL;

  // Find an available (record, data) tuple
  size_t record_size = bucket_get_record_size(type);
  size_t record_num = bucket_get_max_records(type);
  struct bucket_header *header = list_first(g_free[type], struct bucket_header, bucket.list);
  char *data = bucket_get_data(header, record_num);

  size_t i = 0;
  while (header->bytes_used[i]) ++i, data += record_size;
  dprint("DEBUG: record_alloc, header=%p i=%zu data=%p size=%zu\n", header, i, data, size);

  // Write metadata back
  header->bytes_used[i] = size;
  ++header->bucket.records_used;

  // Move to full if needed
  if (header->bucket.records_used == record_num) list_move(g_full + type, &header->bucket.list);
  return data;
}

/*
 * Free the record given by index.
 */
static void record_free(struct bucket_header *header, size_t index) {
  size_t record_num = bucket_get_max_records(header->type);
  --header->bucket.records_used;
  header->bytes_used[index] = 0;

  if (header->bucket.records_used == record_num - 1) {
    list_move(g_free + header->type, &header->bucket.list);
  } else if (header->bucket.records_used == 0) {
    bucket_free(header);
  }
}

static bool record_can_realloc_inplace(struct bucket_header *header, size_t new_size) {
  size_t record_size = bucket_get_record_size(header->type);
  return new_size <= record_size;
}

/*****************************************
 *  Exported functions to override libc  *
 *****************************************/

void *malloc(size_t size) {
  void *ptr = NULL;
  if (size != 0) {
    if (size <= bucket_get_record_size(BUCKET_TYPE_MAX)) {
      ptr = record_alloc(size);
    } else {
      ptr = blob_alloc(size);
    }
  }
  dprint("malloc(%zu) = %p\n", size, ptr);
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
    dprint("DEBUG: record_free, header = %p, type = %u, i = %zu, data = %p\n", header, header->type, index, ptr);
    record_free(header, index);
  }
}

void *realloc(void *ptr, size_t size) {
  if (!ptr) return malloc(size);

  struct bucket_header *header = util_ptr_to_header(ptr);
  if (header->type == BUCKET_TYPE_BLOB) {
    if (blob_can_realloc_inplace(header, size)) return ptr;
  } else {
    if (record_can_realloc_inplace(header, size)) return ptr;
  }

  void *new_address = malloc(size);
  if (ptr) memcpy(new_address, ptr, size);
  free(ptr);
  dprint("DEBUG: realloc(%p, %zu) = %p\n", ptr, size);
  return new_address;
}

