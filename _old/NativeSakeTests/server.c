#include "server.h"
#include "utils.h"
#include "common.h"

static SakeServer_Init_t SakeServer_Init = NULL;
static SakeNewServer_t SakeNewServer = NULL;
static SakeServerHandshake_t SakeServerHandshake = NULL;

static void *server_handle;
static int handshake_step = 0;

int server_handshake(SakeMsg* msg_in, SakeMsg* msg_out) {
	printf("\n\n[i] server step %d\n", handshake_step);

	printf("\tin: ");
    hex_dump(msg_in, sizeof(SakeMsg));

    printf("\n\tout: ");
    hex_dump(msg_out, sizeof(SakeMsg));

    int retval = SakeServerHandshake(0xAAAAAAAA, 0xBBBBBBBB, server_handle, 0xDDDDDDDD, msg_in, 0xFFFFFFFF, msg_out, 0x11111111);
    printf("\n\tretval = 0x%x\n", retval);

	printf("\tin: ");
    hex_dump(msg_in, sizeof(SakeMsg));

    printf("\n\tout: ");
    hex_dump(msg_out, sizeof(SakeMsg));

    printf("\n");
	server_print_status();
    handshake_step++;

}

void server_print_status()
{
    int sake_status = *((uint32_t *)server_handle);
    int last_error = *((uint32_t *)(server_handle + 0xa4));
    printf("\tstate = 0x%x\n\tlast_err = 0x%x\n\tclient_challenge = ", sake_status, last_error);
    hex_dump((server_handle + 0x4), 8);
    printf("\n\tserver_challenge = ");
    hex_dump(server_handle + 0xc, 8);
    printf("\n");
    return;
}

void server_init(void *hLib, void* key_db)
{
    SakeServer_Init = (SakeServer_Init_t)load_function(hLib, "Java_com_medtronic_minimed_sake_SakeJNI_Sake_1Server_1Init");
    SakeNewServer = (SakeNewServer_t)load_function(hLib, "Java_com_medtronic_minimed_sake_SakeJNI_new_1SAKE_1SERVER_1S");
    SakeServerHandshake = (SakeServerHandshake_t)load_function(hLib, "Java_com_medtronic_minimed_sake_SakeJNI_Sake_1Server_1Handshake");

	server_handle = SakeNewServer(0xAAAAAAAA, 0xBBBBBBBB);
	printf("[i] New sake server is at %p\n", server_handle);

	SakeServer_Init(0xAAAAAAAA, 0xBBBBBBBB, server_handle, 0xDDDDDDDD, key_db, 0xFFFFFFFF);
	printf("[+] Server initialized successfully.\n");
	server_print_status();

    return;
}