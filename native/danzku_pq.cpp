#include <cstdio>
#include <cstdint>
#include <cstring>
#include <ctime>
#include <unistd.h>
#include <sys/mman.h>
#include <dlfcn.h>
#include <link.h>
#include <string>

static const char* LOG_PATH="/sdcard/DanzKu_PQ_Global_Hook.txt";
static void log_line(const char* msg) {
    FILE* f=fopen(LOG_PATH,"a"); if(!f) return;
    time_t t=time(nullptr); tm tmv{}; localtime_r(&t,&tmv);
    char ts[32]; strftime(ts,sizeof(ts),"%Y-%m-%d %H:%M:%S",&tmv);
    fprintf(f,"[%s] %s\n",ts,msg); fclose(f);
}

#if defined(__aarch64__)

static uintptr_t find_module_base(const char* needle) {
    FILE* f=fopen("/proc/self/maps","r"); if(!f) return 0;
    char line[1024]; uintptr_t a,b;
    while(fgets(line,sizeof(line),f)) {
        if(strstr(line,needle) && sscanf(line,"%lx-%lx",&a,&b)==2) {
            fclose(f); return a;
        }
    }
    fclose(f); return 0;
}

static bool patch_branch(void* target, void* hook, uint8_t saved[16]) {
    uintptr_t t=(uintptr_t)target, h=(uintptr_t)hook;
    memcpy(saved,(void*)t,16);

    // ldr x16, #8 ; br x16 ; .quad hook
    uint32_t insn[2]={0x58000050,0xd61f0200};
    uint64_t addr=h;
    uintptr_t page=t & ~(uintptr_t)(getpagesize()-1);
    if(mprotect((void*)page,getpagesize(),PROT_READ|PROT_WRITE|PROT_EXEC)!=0)
        return false;
    memcpy((void*)t,insn,sizeof(insn));
    memcpy((void*)(t+8),&addr,8);
    __builtin___clear_cache((char*)t,(char*)(t+16));
    mprotect((void*)page,getpagesize(),PROT_READ|PROT_EXEC);
    return true;
}

static void* trampoline(void* target,const uint8_t saved[16]) {
    void* mem=mmap(nullptr,64,PROT_READ|PROT_WRITE|PROT_EXEC,
                   MAP_PRIVATE|MAP_ANONYMOUS,-1,0);
    if(mem==MAP_FAILED) return nullptr;
    memcpy(mem,saved,16);
    uintptr_t back=(uintptr_t)target+16;
    uint32_t insn[2]={0x58000050,0xd61f0200};
    memcpy((uint8_t*)mem+16,insn,8);
    memcpy((uint8_t*)mem+24,&back,8);
    __builtin___clear_cache((char*)mem,(char*)mem+32);
    return mem;
}

/*
 * enableDisplayColor(unsigned int) is a member function. On AArch64:
 * x0 = this, w1 = enable. Return is void.
 */
using EnableDisplayColor = void(*)(void*, unsigned int);
static EnableDisplayColor original_fn=nullptr;

extern "C" void danzku_enableDisplayColor(void* self, unsigned int enable) {
    log_line(enable ? "HOOK enableDisplayColor(1)" :
                      "HOOK enableDisplayColor(0)");
    // Force the feature enabled while preserving the original call.
    if(original_fn) original_fn(self,1);
}

static uint8_t saved_bytes[16];

__attribute__((constructor))
static void install_hook() {
    log_line("DanzKu PQ library loaded; installing enableDisplayColor hook");

    const char* name="/vendor/lib64/hw/mt6789/vendor.mediatek.hardware.pq@2.15-impl.so";
    uintptr_t base=find_module_base("vendor.mediatek.hardware.pq@2.15-impl.so");
    if(!base) {
        log_line("ERROR: PQ implementation library not mapped");
        return;
    }

    // Verified symbol offset from the target build.
    constexpr uintptr_t ENABLE_DISPLAY_COLOR_OFF=0x37758;
    void* target=(void*)(base+ENABLE_DISPLAY_COLOR_OFF);

    void* tramp=trampoline(target,saved_bytes);
    if(!tramp) {
        log_line("ERROR: trampoline allocation failed");
        return;
    }
    original_fn=(EnableDisplayColor)tramp;

    if(!patch_branch(target,(void*)&danzku_enableDisplayColor,saved_bytes)) {
        log_line("ERROR: patching enableDisplayColor failed");
        original_fn=nullptr;
        return;
    }

    char buf[256];
    snprintf(buf,sizeof(buf),"HOOK ACTIVE target=%p hook=%p trampoline=%p",
             target,(void*)&danzku_enableDisplayColor,tramp);
    log_line(buf);
}
#else
extern "C" void danzku_pq_init() {
    log_line("ERROR: PQ hook requires arm64-v8a");
}
#endif
