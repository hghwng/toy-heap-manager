#include <sys/mman.h>
#include <signal.h>
#include <fcntl.h>

#include <memory.h>
#include <stdio.h>
#include "list.h"
#include "heap.h"
#define dprint(...) fprintf(stderr, __VA_ARGS__)
#define iprint(...) fprintf(stderr, __VA_ARGS__)

static struct list_head g_free[BUCKET_TYPE_NUM];
static struct list_head g_full[BUCKET_TYPE_NUM];
static int g_fd;

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
  size_t pages = (size + sizeof(struct bucket_header)) / PAGE_SIZE + 1;
  void *ptr = virtual_alloc(pages);
  if (!ptr) return NULL;

  struct bucket_header *header = (struct bucket_header *)ptr;
  header->type = BUCKET_TYPE_BLOB;
  header->blob.bytes_in_use = size;
  header->blob.pages_allocated = pages;

  return (char *)ptr + sizeof(struct bucket_header);
}

static void blob_free(struct bucket_header *header) {
  virtual_free(header, header->blob.pages_allocated);
}

/******************************************
 *  Managed allocation for small objects  *
 ******************************************/

/*
 * Get the max record size the given type of bucket can store.
 * i.e. data_size <= bucket_get_size(type)
 */
static inline size_t bucket_get_size(size_t type) {
  return 1ul << type;
}

/*
 * Calculate max number of records can store in a bucket.
 */
static inline size_t bucket_max_record(size_t type) {
  size_t body_size = PAGE_SIZE - sizeof(struct bucket_header);
  size_t total_size_per_record = bucket_get_size(type) + sizeof(struct bucket_record);
  return body_size / total_size_per_record;
}

/*
 * Get the base of the records from the base of the header.
 */
static inline struct bucket_record *bucket_get_records(struct bucket_header *bucket) {
  return (struct bucket_record *)((char *)bucket + sizeof(struct bucket_header));
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
  header->bucket.records_in_use = 0;
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
  if (size < bucket_get_size(BUCKET_TYPE_MIN)) {
    type = BUCKET_TYPE_MIN;
  } else {
    type = 8 * sizeof(unsigned int) - __builtin_clz((unsigned int)(size - 1));
  }

  // Create new bucket if needed
  struct list_head *head = g_free + type;
  if (list_empty(head) && !bucket_alloc(type)) return NULL;

  // Find an available (record, data) tuple
  size_t record_size = bucket_get_size(type);
  size_t record_num = bucket_max_record(type);
  struct bucket_header *header = list_first(g_free[type], struct bucket_header, bucket.list);
  struct bucket_record *record = bucket_get_records(header);
  char *data = (char *)(record + record_num);
  size_t i = 0;
  while (record->bytes_in_use) ++record, data += record_size, ++i;
  iprint("INFO: record_alloc, header=%p i=%zu data=%p size=%zu\n", header, i, data, size);

  // Write metadata back
  record->bytes_in_use = size;
  ++header->bucket.records_in_use;

  // Move to full if needed
  if (header->bucket.records_in_use == record_num) list_move(g_full + type, &header->bucket.list);
  return data;
}

/*
 * Free the record given by index.
 */
static void record_free(struct bucket_header *header, size_t index) {
  size_t record_num = bucket_max_record(header->type);
  struct bucket_record *record = bucket_get_records(header);
  --header->bucket.records_in_use;
  record[index].bytes_in_use = 0;

  if (header->bucket.records_in_use == record_num - 1) {
    list_move(g_free + header->type, &header->bucket.list);
  } else if (header->bucket.records_in_use == 0) {
    bucket_free(header);
  }
}

/*****************************************
 *  Exported functions to override libc  *
 *****************************************/

void *malloc(size_t size) {
  void *ptr = NULL;
  if (size != 0) {
    if (size <= bucket_get_size(BUCKET_TYPE_MAX) && size > 512) {
      ptr = record_alloc(size);
    } else {
      ptr = blob_alloc(size);
    }
  }
  dprint("malloc(%zu) = %p\n", size, ptr);
  return ptr;
}

void free(void *ptr) {
  dprint("DEBUG: free(%p)\n", ptr);

  if (!ptr) return;
  struct bucket_header *header = (struct bucket_header *)((size_t)ptr & PAGE_BEGIN_MASK);
  if (header->type == BUCKET_TYPE_BLOB) {
    blob_free(header);
  } else {
    size_t offset = (size_t)ptr - (size_t)(
        bucket_get_records(header) + bucket_max_record(header->type));
    size_t idx = offset / bucket_get_size(header->type);
    iprint("INFO: record_free, header = %p, i = %zu, data = %p\n", header, idx, ptr);
    record_free(header, idx);
  }
}

void *calloc(size_t nmemb, size_t size) {
  dprint("DEBUG: calloc(%zu, %zu)\n", nmemb, size);
  return malloc(nmemb * size);
}

void *realloc(void *ptr, size_t size) {
  dprint("DEBUG: realloc(%p, %zu)\n", ptr, size);
  void *new_address = malloc(size);
  if (ptr) memcpy(new_address, ptr, size);
  free(ptr);
  return new_address;
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

