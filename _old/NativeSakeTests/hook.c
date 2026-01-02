
#include "stdbool.h"

#include "InlineHook.h"

#include "hook.h"
#include "common.h"

static void hook_fake_read_random(struct pt_regs *regs)
{
    int count = regs->uregs[0];          // r0 = input count
    void *dest = (void *)regs->uregs[1]; // r1 = dest ptr
    printf("[i] intercepted read random: ptr = %p, len = 0x%x\n", dest, count);

    char *temp_buff = malloc(count);
    memset(temp_buff, 0x69, count);
    memcpy(dest, temp_buff, count);
    regs->uregs[0] = 1; // r0 = output status -> set to true
    return;
}

static void hook_setup(void *pHookAddr, void (*onCallBack)(struct pt_regs *))
{

    THUMB_INLINE_HOOK_INFO *pstInlineHook = malloc(sizeof(THUMB_INLINE_HOOK_INFO));

    pstInlineHook->pHookAddr = pHookAddr;
    pstInlineHook->onCallBack = onCallBack;

    if (HookThumb(pstInlineHook) == false)
    {
        printf("\n[-] hook failed for %p!\n", pHookAddr);
        exit(-1);
    }
    else
    {
        printf("\n[+] function @ %p is hooked!\n", pHookAddr);
    }
}

void hook_init() {

    if (!HOOK_RANDOM) {
        printf("[i] skipping random hooking...\n");
        return;
    }

    void* base_addr =  get_so_base_addr("libandroid-sake");
    printf("[i] sake base addr = %p\n", base_addr);
    void* read_random_addr = (void*)(base_addr + 0x7518);
    printf("[i] read random function should be at %p\n", read_random_addr),
    hook_setup(read_random_addr, &hook_fake_read_random);

}