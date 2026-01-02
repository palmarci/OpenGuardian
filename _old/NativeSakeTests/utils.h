#ifndef UTILS
#define UTILS

void hex_dump(const void *data, int size);
void *get_so_base_addr(const char *so_filename);
void *load_library(const char *path);
void *load_function(void *handle, const char *func_name);
void debug_break();
void *get_random_data(int len);

#endif /* UTILS */
