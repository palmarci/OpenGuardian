#include <dlfcn.h>
#include <fcntl.h>
#include <link.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "utils.h"
#include "server.h"
#include "keydb.h"

void *library_handle = NULL;

char TEST_KEY_DB[] = {0xf7, 0x59, 0x95, 0xe7, 0x04, 0x01, 0x01, 0x1b, 0xc1, 0xbf, 0x7c, 0xbf, 0x36, 0xfa, 0x1e, 0x23, 0x67, 0xd7, 0x95, 0xff, 0x09, 0x21, 0x19, 0x03, 0xda, 0x6a, 0xfb, 0xe9, 0x86, 0xb6, 0x50, 0xf1, 0x41, 0x79, 0xc0, 0xe6, 0x85, 0x2e, 0x0c, 0xe3, 0x93, 0x78, 0x10, 0x78, 0xff, 0xc6, 0xf5, 0x19, 0x19, 0xe2, 0xea, 0xef, 0xbd, 0xe6, 0x9b, 0x8e, 0xca, 0x21, 0xe4, 0x1a, 0xb5, 0x9b, 0x88, 0x1a, 0x0b, 0xea, 0x02, 0x86, 0xea, 0x91, 0xdc, 0x75, 0x82, 0xa8, 0x6a, 0x71, 0x4e, 0x17, 0x37, 0xf5, 0x58, 0xf0, 0xd6, 0x6d, 0xc1, 0x89, 0x5c};

int main(int argc, char *argv[])
{
	bool debug = false;

	if (argc == 2)
	{
		if (strcmp((const char *)argv[1], "--debug") == 0)
		{
			debug = true;
			printf("[+] Debug mode enabled.\n");
		}
		else
		{
			printf("[i] Starting in normal mode!\n");
		}
	}

	library_handle = load_library(SAKE_LIBRARY_PATH);

	if (debug)
	{
		debug_break();
	}

	hook_init();
	char *p_keydb = keydb_init(library_handle, &TEST_KEY_DB, sizeof(TEST_KEY_DB));

	server_init(library_handle, p_keydb);
	printf("\n");

	client_init(library_handle, p_keydb);
	printf("\n");

	SakeMsg *p_in_server_msg = malloc(sizeof(SakeMsg));
	SakeMsg *p_out_server_msg = malloc(sizeof(SakeMsg));

	SakeMsg *p_in_client_msg = malloc(sizeof(SakeMsg));
	SakeMsg *p_out_client_msg = malloc(sizeof(SakeMsg));

	// step 0: regenerate shit internally
	server_handshake(NULL, p_out_server_msg);
	client_handshake(NULL, p_out_client_msg);

	// step 1: exchange empty msgs
	client_handshake(p_out_server_msg, p_out_client_msg);
	server_handshake(p_out_client_msg, p_out_server_msg);

	for (int i = 0; i < 6; i++ ) {
		client_handshake(p_out_server_msg, p_out_client_msg);
		server_handshake(p_out_client_msg, p_out_server_msg);
	}

	//SakeMsg* bak = malloc(sizeof(SakeMsg));
	//memcpy(bak, p_out_server_msg, sizeof(SakeMsg));

	
	//client_handshake(p_out_server_msg, p_out_client_msg);

	//	printf("[i] p_keydb after server init: ");
	// hex_dump(p_keydb, sizeof(TEST_KEY_DB));
	//	printf("\n");

	return 1;

	/*
	client_init(library_handle);

	SakeMsg* p_out_msg = malloc(sizeof(SakeMsg));
	SakeMsg* p_in_sake_msg = malloc(sizeof(SakeMsg));
	int hsret;


	// f6f61518 - f6f5a000(base)
	// f6f5c518 - f6f55000

	// ***** step 0 ***** -> call with null
	//memset(p_out_msg, 0xAA, sizeof(SakeMsg));
	printf("\n\n[i] step 0: ");
	hex_dump(p_out_msg, sizeof(SakeMsg));
	printf(" -> ");
	hsret = SakeServerHandshake(0xAAAAAAAA, 0xBBBBBBBB, p_sake_server, 0xDDDDDDDD, NULL, 0xFFFFFFFF, p_out_msg, 0x11111111);
	hex_dump(p_out_msg, sizeof(SakeMsg));
	printf("\n");
	printf("\thandshake retval = 0x%x\n", hsret);
	print_sake_server_state(p_sake_server);


	// ***** step 1 ***** -> call with all 00s
	int size = 20;
	memset(p_in_sake_msg, 0, size);
	p_in_sake_msg->size = size;
	printf("\n\n[i] step 1: ");
	hex_dump(p_in_sake_msg, sizeof(SakeMsg));
	printf(" -> ");
	hsret = SakeServerHandshake(0xAAAAAAAA, 0xBBBBBBBB, p_sake_server, 0xDDDDDDDD, p_in_sake_msg, 0xFFFFFFFF, p_out_msg, 0x11111111);
	hex_dump(p_out_msg, sizeof(SakeMsg));
	printf("\n");
	printf("\thandshake retval = 0x%x\n", hsret);
	print_sake_server_state(p_sake_server);

	// ***** step 2 *****
	char* random_buff = get_random_data(20);
	memcpy(p_in_sake_msg->data, random_buff, 20);
	p_in_sake_msg->data[8] = 0x1; // fix device type? -> has to match the device type in the keydb
	p_in_sake_msg->size = 20;
	printf("\n\n[i] step 2: ");
	hex_dump(p_in_sake_msg, sizeof(SakeMsg));
	printf(" -> ");
	hsret = SakeServerHandshake(0xAAAAAAAA, 0xBBBBBBBB, p_sake_server, 0xDDDDDDDD, p_in_sake_msg, 0xFFFFFFFF, p_out_msg, 0x11111111);
	hex_dump(p_out_msg, sizeof(SakeMsg));
	printf("\n");
	printf("\thandshake retval = 0x%x\n", hsret);
	print_sake_server_state(p_sake_server);

	// ***** step 3 *****
	char* random_buff2 = get_random_data(20);
	memcpy(p_in_sake_msg->data, random_buff2, 20);
	p_in_sake_msg->size = 20;
	printf("\n\n[i] step 3: ");
	hex_dump(p_in_sake_msg, sizeof(SakeMsg));
	printf(" -> ");
	hsret = SakeServerHandshake(0xAAAAAAAA, 0xBBBBBBBB, p_sake_server, 0xDDDDDDDD, p_in_sake_msg, 0xFFFFFFFF, p_out_msg, 0x11111111);
	hex_dump(p_out_msg, sizeof(SakeMsg));
	printf("\n");
	printf("[i] handshake status = 0x%x\n", hsret);
	print_sake_server_state(p_sake_server);

	*/

	dlclose(library_handle);
	return 0;
}
