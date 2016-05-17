#ifndef _HEAP_H_
#define _HEAP_H_
#include <stdint.h>
#include <stddef.h>
#include "list.h"

#define PAGE_SIZE         4096
#define PAGE_BEGIN_MASK   (~(PAGE_SIZE - 1))

#define BUCKET_TYPE_MIN   3     // 2^3 = 8
#define BUCKET_TYPE_MAX   10    // 2^10 = 1024
#define BUCKET_TYPE_NUM  (BUCKET_TYPE_MAX + 1)

#define BUCKET_TYPE_BLOB 0xff

struct bucket_header {
  union {
    struct {
      struct list_head list;
      uint8_t records_in_use;
    } bucket;

    struct {
      size_t pages_allocated;
      size_t bytes_in_use;
    } blob;
  };
  uint8_t type;
} __attribute__((aligned (8)));

struct bucket_record {
  uint16_t bytes_in_use;
};

/*
 * Format for bucket:
 *
 *   |<--------- PAGE_SIZE ---------->|
 *   ----------------------------------
 *   | header | record * N | data * N |
 *   ----------------------------------
 *
 * N denotes the maximium number of records can store in a bucket.
 * Consult bucket_max_record() for more details.
 */

#endif
