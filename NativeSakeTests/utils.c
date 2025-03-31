#include "utils.h"
#include "common.h"

#include <signal.h>
#include <stdint.h>
#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>
#include <dlfcn.h>
#include <stdbool.h>

void hex_dump(const void *data, int size) {
    if (data == NULL) {
        printf("<NULL>");
        return;
    }
    const char *ptr = (const char *)data;
    for (int i = 0; i < size; i++) {
        printf("%02x ", ptr[i]);
    }
	//printf("\n");
}

void* get_so_base_addr(const char *so_filename) {
    char maps_filename[256];
    FILE *maps_file;
    char line[256];

    // Open /proc/self/maps to check memory mappings
    snprintf(maps_filename, sizeof(maps_filename), "/proc/self/maps");

    maps_file = fopen(maps_filename, "r");
    if (maps_file == NULL) {
        printf("[-] fopen");
        return NULL;
    }

    while (fgets(line, sizeof(line), maps_file)) {
        // Look for the shared object file in the mapping
        if (strstr(line, so_filename)) {
            // The first part of the line is the memory address range
            // Example line: 7f6f5c800000-7f6f5c81f000 r-xp 00000000 08:01 123456 /path/to/your/library.so
            void *base_addr;
            sscanf(line, "%p", &base_addr);
            fclose(maps_file);
            return base_addr;
        }
    }

    fclose(maps_file);
    printf("Library not found in memory mappings\n");
    exit(-1);
}

void* load_library(const char *path)
{
	void *handle = dlopen((const char *)path, RTLD_LAZY);
	if (!handle) {
		fprintf(stderr, "[-] Error loading library: %s\n", dlerror());
		exit(-1);
	}
	printf("[+] Library loaded successfully at %p\n", handle);
	return handle;
}

void *load_function(void *handle, const char *func_name)
{
	void *func = dlsym(handle, (const char *)func_name);
	if (!func) {
		fprintf(stderr, "[-] Error finding %s: %s\n", func_name, dlerror());
		exit(-1);
	}
	printf("[+] %s -> %p\n", func_name, func);
	return func;
}

void debug_break()
{
	pid_t pid = getpid();
	printf("[i] Sending SIGINT signal to process %d\n", pid);

	if (kill(pid, SIGINT) == -1) {
		printf("[-] [-] Error sending signal");
		exit(-1);
	}
}

void* get_random_data(int len) {

	if (HOOK_RANDOM) {
		void* ptr = malloc(len);
		memset(ptr, 0x42, len);
		return ptr;
	}

    int fd = open("/dev/urandom", O_RDONLY);
    if (fd == -1) {
        printf("[-] Failed to open /dev/urandom");
        exit(-1);
    }

    void *buffer = malloc(len);
    if (buffer == NULL) {
        printf("[-] Failed to allocate memory");
        close(fd);
        exit(-1);
    }

    int bytesRead = read(fd, buffer, len);
    if (bytesRead != len) {
        printf("[-] Failed to read enough random data");
        free(buffer);
        close(fd);
        exit(-1);
    }

    close(fd);
    return buffer;
}

