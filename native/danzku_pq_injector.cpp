#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <cstdint>
#include <cstdarg>
#include <ctime>
#include <sys/ptrace.h>
#include <linux/ptrace.h>
#include <sys/wait.h>
#include <sys/uio.h>
#include <sys/types.h>
#include <unistd.h>
#include <errno.h>
#include <dlfcn.h>
#include <string>

#if defined(__aarch64__)
#include <sys/user.h>
#endif

static std::string g_log="/sdcard/DanzKu_PQ_Global_Hook.txt";

static void log_line(const char* fmt, ...) {
    FILE* f=fopen(g_log.c_str(),"a"); if(!f) return;
    time_t t=time(nullptr); tm tmv{}; localtime_r(&t,&tmv);
    char ts[32]; strftime(ts,sizeof(ts),"%Y-%m-%d %H:%M:%S",&tmv);
    fprintf(f,"[%s] ",ts);
    va_list ap; va_start(ap,fmt); vfprintf(f,fmt,ap); va_end(ap);
    fputc('\n',f); fclose(f);
}

#if defined(__aarch64__)

static uintptr_t module_base(pid_t pid,const char* needle) {
    char p[64]; snprintf(p,sizeof(p),"/proc/%d/maps",pid);
    FILE* f=fopen(p,"r"); if(!f) return 0;
    char line[1024]; uintptr_t a,b;
    while(fgets(line,sizeof(line),f)) {
        if(strstr(line,needle) && sscanf(line,"%lx-%lx",&a,&b)==2) {
            fclose(f); return a;
        }
    }
    fclose(f); return 0;
}

static uintptr_t local_module_base(const char* needle) {
    FILE* f=fopen("/proc/self/maps","r"); if(!f) return 0;
    char line[1024]; uintptr_t a,b;
    while(fgets(line,sizeof(line),f)) {
        if(strstr(line,needle) && sscanf(line,"%lx-%lx",&a,&b)==2) {
            fclose(f); return a;
        }
    }
    fclose(f); return 0;
}

static bool read_mem(pid_t pid, uintptr_t addr, void* buf, size_t len) {
    struct iovec l{buf,len}, r{(void*)addr,len};
    return process_vm_readv(pid,&l,1,&r,1,0)==(ssize_t)len;
}

static bool write_mem(pid_t pid, uintptr_t addr, const void* buf, size_t len) {
    struct iovec l{(void*)buf,len}, r{(void*)addr,len};
    return process_vm_writev(pid,&l,1,&r,1,0)==(ssize_t)len;
}

static bool getregs(pid_t pid, user_pt_regs& r) {
    struct iovec io{&r,sizeof(r)};
    return ptrace(PTRACE_GETREGSET,pid,(void*)NT_PRSTATUS,&io)==0;
}

static bool setregs(pid_t pid, user_pt_regs& r) {
    struct iovec io{&r,sizeof(r)};
    return ptrace(PTRACE_SETREGSET,pid,(void*)NT_PRSTATUS,&io)==0;
}

/*
 * Execute a remote function using the tracee's current PC.
 * The original instruction is replaced temporarily by:
 *   BLR X16
 *   BRK #0
 * X16 contains the target function. After the call returns, execution
 * reaches BRK and the tracer observes X0.
 */
static long remote_call(pid_t pid, uintptr_t fn, const uintptr_t* args, int n) {
    user_pt_regs saved{}, regs{};
    if(!getregs(pid,saved)) {
        log_line("ERROR: PTRACE_GETREGSET failed errno=%d (%s)",errno,strerror(errno));
        return -1;
    }

    uintptr_t pc=saved.pc;
    uint32_t original[2]{};
    if(!read_mem(pid,pc,original,sizeof(original))) {
        log_line("ERROR: cannot read remote PC 0x%lx",pc);
        return -1;
    }

    regs=saved;
    for(int i=0;i<n && i<8;i++) regs.regs[i]=args[i];
    regs.regs[16]=fn;

    // BLR X16 ; BRK #0
    uint32_t callcode[2]={0xd63f0200,0xd4200000};

    if(!write_mem(pid,pc,callcode,sizeof(callcode))) {
        log_line("ERROR: cannot patch remote PC");
        return -1;
    }

    if(!setregs(pid,regs)) {
        write_mem(pid,pc,original,sizeof(original));
        log_line("ERROR: PTRACE_SETREGSET failed errno=%d (%s)",errno,strerror(errno));
        return -1;
    }

    if(ptrace(PTRACE_CONT,pid,0,0)!=0) {
        write_mem(pid,pc,original,sizeof(original));
        setregs(pid,saved);
        log_line("ERROR: PTRACE_CONT failed errno=%d (%s)",errno,strerror(errno));
        return -1;
    }

    int status=0;
    if(waitpid(pid,&status,0)<0) {
        write_mem(pid,pc,original,sizeof(original));
        setregs(pid,saved);
        log_line("ERROR: waitpid failed errno=%d (%s)",errno,strerror(errno));
        return -1;
    }

    long ret=-1;
    if(WIFSTOPPED(status)) {
        user_pt_regs after{};
        if(getregs(pid,after)) {
            ret=(long)after.regs[0];
            log_line("remote call stopped signal=%d x0=0x%lx",
                     WSTOPSIG(status),(uintptr_t)after.regs[0]);
        }
    } else {
        log_line("ERROR: tracee did not stop normally status=0x%x",status);
    }

    write_mem(pid,pc,original,sizeof(original));
    setregs(pid,saved);
    return ret;
}

static bool remote_dlopen(pid_t pid,const char* libpath) {
    uintptr_t remote_libc=module_base(pid,"/apex/com.android.runtime/lib64/bionic/libc.so");
    if(!remote_libc) remote_libc=module_base(pid,"/system/lib64/libc.so");

    uintptr_t local_libc=local_module_base("/apex/com.android.runtime/lib64/bionic/libc.so");
    if(!local_libc) local_libc=local_module_base("/system/lib64/libc.so");

    void* local_dl=dlsym(RTLD_DEFAULT,"dlopen");
    if(!remote_libc || !local_libc || !local_dl) {
        log_line("ERROR: cannot resolve libc/dlopen local=%p remote=0x%lx dl=%p",
                 (void*)local_libc,remote_libc,local_dl);
        return false;
    }

    uintptr_t remote_dl=remote_libc+((uintptr_t)local_dl-local_libc);
    log_line("libc local=0x%lx remote=0x%lx dlopen=0x%lx",
             local_libc,remote_libc,remote_dl);

    user_pt_regs r{};
    if(!getregs(pid,r)) return false;

    // Keep path below current SP but preserve enough headroom.
    uintptr_t remote_str=r.sp-0x800;
    size_t len=strlen(libpath)+1;
    if(!write_mem(pid,remote_str,libpath,len)) {
        log_line("ERROR: write remote library path failed errno=%d (%s)",errno,strerror(errno));
        return false;
    }

    uintptr_t args[2]={remote_str,(uintptr_t)(RTLD_NOW|RTLD_GLOBAL)};
    long h=remote_call(pid,remote_dl,args,2);

    // dlopen returns NULL on failure. A valid handle must be a mapped address.
    if(h<=0 || (uintptr_t)h==UINTPTR_MAX) {
        log_line("ERROR: remote dlopen failed return=0x%lx", (uintptr_t)h);
        return false;
    }

    // Verify that the requested library is now mapped in the target.
    uintptr_t loaded=module_base(pid,"libdanzku_pq.so");
    if(!loaded) {
        log_line("ERROR: dlopen returned 0x%lx but library is not mapped", (uintptr_t)h);
        return false;
    }

    log_line("remote dlopen SUCCESS handle=0x%lx mapped=0x%lx",
             (uintptr_t)h,loaded);
    return true;
}

int main(int argc,char** argv) {
    pid_t pid=0; std::string lib;
    for(int i=1;i<argc;i++) {
        if(!strcmp(argv[i],"--pid")&&i+1<argc) pid=atoi(argv[++i]);
        else if(!strcmp(argv[i],"--library")&&i+1<argc) lib=argv[++i];
        else if(!strcmp(argv[i],"--log")&&i+1<argc) g_log=argv[++i];
    }

    log_line("DanzKu ARM64 injector start pid=%d",pid);
    log_line("library=%s",lib.c_str());

    if(pid<=0||lib.empty()) {
        log_line("ERROR invalid arguments");
        return 2;
    }

    if(ptrace(PTRACE_ATTACH,pid,0,0)!=0) {
        log_line("ERROR ptrace attach failed errno=%d (%s)",errno,strerror(errno));
        return 3;
    }

    int st=0;
    waitpid(pid,&st,0);
    if(!WIFSTOPPED(st)) {
        log_line("ERROR: tracee did not stop after attach status=0x%x",st);
        ptrace(PTRACE_DETACH,pid,0,0);
        return 4;
    }

    log_line("ptrace attached");

    bool ok=remote_dlopen(pid,lib);

    ptrace(PTRACE_DETACH,pid,0,0);
    log_line("ptrace detached");
    log_line("remote-dlopen status=%s",ok?"SUCCESS":"FAILED");

    return ok?0:5;
}
#else
int main(int,char**) { return 6; }
#endif
