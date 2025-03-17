#include <stdio.h>
#include <stdlib.h>
#include <dlfcn.h>
// #include <jni.h>
#include <signal.h>
#include <unistd.h>

#include "main.h"

static void *sake_handle;
static void *android_handle;

static SakeKeyDatabaseOpen_t SakeKeyDatabaseOpen = NULL;

void init_sake()
{
	// Load the SAKE library
	sake_handle = dlopen(SAKE_LIBRARY, RTLD_LAZY);
	if (!sake_handle)
	{
		fprintf(stderr, "Error loading SAKE library: %s\n", dlerror());
		exit(-1);
	}
	printf("sake_handle is open at %p\n", sake_handle);

	SakeKeyDatabaseOpen = (SakeKeyDatabaseOpen_t)dlsym(sake_handle, "Java_com_medtronic_minimed_sake_SakeJNI_Sake_1KeyDatabase_1Open");
	if (!SakeKeyDatabaseOpen)
	{
		fprintf(stderr, "Error finding Java_com_medtronic_minimed_sake_SakeJNI_Sake_1KeyDatabase_1Open: %s\n", dlerror());
		exit(-1);
	}
	printf("SakeKeyDatabaseOpen @ %p\n", SakeKeyDatabaseOpen);
}

/*
void init_android() {
	// Load libandroid.so to access JNI functions
	android_handle = dlopen("libandroid.so", RTLD_LAZY);
	if (!android_handle) {
		fprintf(stderr, "Error loading libandroid.so: %s\n", dlerror());
		exit(-1);
	}
	printf("libandroid is open at %p\n", android_handle);

	// Load JNI_CreateJavaVM function from libandroid.so
	my_JNI_CreateJavaVM = (JNI_CreateJavaVM_t) dlsym(android_handle, "JNI_CreateJavaVM");

	if (!my_JNI_CreateJavaVM) {
		fprintf(stderr, "Error finding JNI_CreateJavaVM: %s\n", dlerror());
		exit(-1);
	}
	printf("my_JNI_CreateJavaVM @ %p\n", my_JNI_CreateJavaVM);
}
*/

void debug_break() {
	pid_t pid = getpid();
    printf("Sending SIGINT signal to process %d\n", pid);

    if (kill(pid, SIGINT) == -1) {
        perror("Error sending signal");
        exit(-1);
    }
}

void close_all()
{
	// Close the loaded libraries
	dlclose(sake_handle);
	dlclose(android_handle);
}

int main(int argc, char *argv[])
{
	bool debug = false;

	if (argc == 2) {
		if (strcmp(argv[1], "debug") == 0) {
			debug = true;
		} else {
			printf("starting in normal mode!\n");
		}
	}

	init_sake();
	// init_android();

	if (debug) {
		debug_break();
	}

	uint32_t *key_db = malloc(8);

	//									env 		thiz		a0			a1			a2			a3
	int retval = SakeKeyDatabaseOpen(0xAAAAAAAA, 0xBBBBBBBB, key_db, 0xDDDDDDDD, &TEST_KEY_DB, sizeof(TEST_KEY_DB));
	printf("SakeKeyDatabaseOpen returned %d\n", retval);

	close_all();
	return 0;
}
