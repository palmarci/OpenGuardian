#include "client.h"
#include "utils.h"
#include "common.h"

static SakeClient_Init_t SakeClient_Init = NULL;
static SakeNewClient_t SakeNewClient = NULL;
static SakeClientHandshake_t SakeClientHandshake = NULL;

static void *client_handle;
static int handshake_step = 0;

int client_handshake(SakeMsg* msg_in, SakeMsg* msg_out) {
	printf("\n\n[i] client step %d\n", handshake_step);

	printf("\tin: ");
    hex_dump(msg_in, sizeof(SakeMsg));

    printf("\n\tout: ");
    hex_dump(msg_out, sizeof(SakeMsg));

    int retval = SakeClientHandshake(0xAAAAAAAA, 0xBBBBBBBB, client_handle, 0xDDDDDDDD, msg_in, 0xFFFFFFFF, msg_out, 0x11111111);
    printf("\n\tretval = 0x%x\n", retval);

	printf("\tin: ");
    hex_dump(msg_in, sizeof(SakeMsg));

    printf("\n\tout: ");
    hex_dump(msg_out, sizeof(SakeMsg));

    printf("\n");
	
    client_print_status();
    handshake_step++;

}


void client_print_status()
{
    int client_state = *((uint32_t *)client_handle);
    int last_error = *((uint32_t *)(client_handle + 0x74));
    printf("\tstate = 0x%x\n\tlast_err = 0x%x", client_state, last_error);
    //hex_dump((client_handle + 0x4), 8);
    //printf("\n\tClient_challenge = ");
   // hex_dump(client_handle + 0xc, 8);
    printf("\n");
    return;
}

void client_init(void *hLib, void* key_db)
{
    SakeClient_Init = (SakeClient_Init_t)load_function(hLib, "Java_com_medtronic_minimed_sake_SakeJNI_Sake_1Client_1Init");
    SakeNewClient = (SakeNewClient_t)load_function(hLib, "Java_com_medtronic_minimed_sake_SakeJNI_new_1SAKE_1CLIENT_1S");
    SakeClientHandshake = (SakeClientHandshake_t)load_function(hLib, "Java_com_medtronic_minimed_sake_SakeJNI_Sake_1Client_1Handshake");

	client_handle = SakeNewClient(0xAAAAAAAA, 0xBBBBBBBB);
	printf("[i] sake client allocated at %p\n", client_handle);

	SakeClient_Init(0xAAAAAAAA, 0xBBBBBBBB, client_handle, 0xDDDDDDDD, key_db, 0xFFFFFFFF);
	printf("[+] client initialized successfully.\n");
	
    client_print_status();

    return;
}