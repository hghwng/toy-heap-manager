#ifndef _HEAP_H_
#define _HEAP_H_
#include <stdint.h>
#include <stddef.h>
#include "bitmap.h"
#include "list.h"

#define ALIGN_SIZE        sizeof(size_t)
#define PAGE_SIZE         4096ul
#define PAGE_BEGIN_MASK   (~(PAGE_SIZE - 1ul))

#define BUCKET_TYPE_MIN   3     // 2^3 = 8
#define BUCKET_TYPE_MAX   10    // 2^10 = 1024
#define BUCKET_TYPE_NUM  (BUCKET_TYPE_MAX + 1)

#define BUCKET_TYPE_BLOB 0xff

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

/*
 * Format for bucket:
 *
 *   |<----------- PAGE_SIZE ------------>|
 *   --------------------------------------
 *   | header | bytes_used * N | data * N |
 *   --------------------------------------
 *
 * N denotes the maximium number of records can store in a bucket.
 * Consult bucket_max_record() for more details.
 */

#if DEBUG > 0
# define iprint(...) fprintf(stderr, __VA_ARGS__)
#else
# define iprint(...)
#endif

#if DEBUG > 1
# define dprint(...) fprintf(stderr, __VA_ARGS__)
#else
# define dprint(...)
#endif

#endif
