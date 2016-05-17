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
