#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <cstdint>
#include <cstdarg>
#include <ctime>
#include <dlfcn.h>
#include <dirent.h>
#include <fcntl.h>
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <sys/uio.h>
#include <sys/types.h>
#include <unistd.h>
#include <errno.h>
#include <elf.h>
#include <string>
#include <vector>

#if defined(__aarch64__)
#include <sys/user.h>
#endif

static std::string g_log="/sdcard/DanzKu_PQ_Global_Hook.txt";

static void log_line(const char *fmt, ...) {
    FILE *f=fopen(g_log.c_str(),"a"); if(!f) return;
    time_t t=time(nullptr); tm tmv{}; localtime_r(&t,&tmv);
    char ts[32]; strftime(ts,sizeof(ts),"%Y-%m-%d %H:%M:%S",&tmv);
    fprintf(f,"[%s] ",ts);
    va_list ap; va_start(ap,fmt); vfprintf(f,fmt,ap); va_end(ap);
    fputc('\n',f); fclose(f);
}

#if defined(__aarch64__)

static uintptr_t module_base(pid_t pid,const char* needle) {
    char p[64]; snprintf(p,sizeof(p),"/proc/%d/maps",pid);
    FILE *f=fopen(p,"r"); if(!f) return 0;
    char line[1024]; uintptr_t a,b;
    while(fgets(line,sizeof(line),f)) {
        if(strstr(line,needle)) {
            if(sscanf(line,"%lx-%lx",&a,&b)==2) { fclose(f); return a; }
        }
    }
    fclose(f); return 0;
}

static uintptr_t local_module_base(const char* needle) {
    FILE *f=fopen("/proc/self/maps","r"); if(!f) return 0;
    char line[1024]; uintptr_t a,b;
    while(fgets(line,sizeof(line),f)) {
        if(strstr(line,needle)) {
            if(sscanf(line,"%lx-%lx",&a,&b)==2) { fclose(f); return a; }
        }
    }
    fclose(f); return 0;
}

static bool read_mem(pid_t pid, uintptr_t addr, void *buf, size_t len) {
    struct iovec l{buf,len}, r{(void*)addr,len};
    return process_vm_readv(pid,&l,1,&r,1)==(ssize_t)len;
}
static bool write_mem(pid_t pid, uintptr_t addr, const void *buf, size_t len) {
    struct iovec l{(void*)buf,len}, r{(void*)addr,len};
    return process_vm_writev(pid,&l,1,&r,1)==(ssize_t)len;
}

static bool getregs(pid_t pid, user_pt_regs &r) {
    return ptrace(PTRACE_GETREGS,pid,0,&r)==0;
}
static bool setregs(pid_t pid, user_pt_regs &r) {
    return ptrace(PTRACE_SETREGS,pid,0,&r)==0;
}

/*
 * Remote call helper for AArch64. This deliberately uses a real function
 * already mapped in the target (libc/dlopen), then executes a BRK instruction
 * as the return trap. The original register state is restored by the caller.
 */
static long remote_call(pid_t pid, uintptr_t fn, const uintptr_t *args, int n) {
    user_pt_regs saved{}, regs{};
    if(!getregs(pid,saved)) return -1;
    regs=saved;
    for(int i=0;i<n && i<8;i++) regs.regs[i]=args[i];

    // Put a breakpoint after a BLR X16.
    uintptr_t pc=saved.pc;
    uint32_t original=0;
    if(!read_mem(pid,pc,&original,4)) return -1;
    uint32_t brk=0xd4200000;
    if(!write_mem(pid,pc,&brk,4)) return -1;
    regs.regs[16]=fn;
    regs.pc=pc;
    if(!setregs(pid,regs)) { write_mem(pid,pc,&original,4); return -1; }

    // Execute: PC points at original instruction, so use an inline BLR by
    // temporarily changing PC to a tiny scratch is not possible without
    // executable memory. Instead use the target's existing instruction:
    // set X16=fn and replace current instruction with BLR X16 (0xd63f0200).
    uint32_t blr=0xd63f0200;
    if(!write_mem(pid,pc,&blr,4)) { write_mem(pid,pc,&original,4); return -1; }
    if(ptrace(PTRACE_CONT,pid,0,0)!=0) { write_mem(pid,pc,&original,4); return -1; }
    int st=0;
    waitpid(pid,&st,0);
    long ret=-1;
    if(WIFSTOPPED(st)) {
        user_pt_regs after{};
        if(getregs(pid,after)) ret=(long)after.regs[0];
    }
    write_mem(pid,pc,&original,4);
    setregs(pid,saved);
    return ret;
}

static bool remote_dlopen(pid_t pid, const char *libpath) {
    uintptr_t remote_libc=module_base(pid,"/apex/com.android.runtime/lib64/bionic/libc.so");
    if(!remote_libc) remote_libc=module_base(pid,"/system/lib64/libc.so");
    uintptr_t local_libc=local_module_base("/apex/com.android.runtime/lib64/bionic/libc.so");
    if(!local_libc) local_libc=local_module_base("/system/lib64/libc.so");
    void *dl=dlsym(RTLD_DEFAULT,"dlopen");
    uintptr_t local_dl=(uintptr_t)dl;
    if(!remote_libc || !local_libc || !local_dl) {
        log_line("ERROR: cannot resolve libc/dlopen base");
        return false;
    }
    uintptr_t remote_dl=remote_libc+(local_dl-local_libc);
    log_line("libc local=%p remote=%p dlopen=%p",(void*)local_libc,(void*)remote_libc,(void*)remote_dl);

    // Use target stack below SP for a short path; keep well away from active frames.
    user_pt_regs r{};
    if(!getregs(pid,r)) return false;
    uintptr_t remote_str=(uintptr_t)(r.sp-0x400);
    size_t len=strlen(libpath)+1;
    if(!write_mem(pid,remote_str,libpath,len)) {
        log_line("ERROR: write remote path failed errno=%d",errno);
        return false;
    }

    uintptr_t args[2]={remote_str,RTLD_NOW|RTLD_GLOBAL};
    long h=remote_call(pid,remote_dl,args,2);
    log_line("remote dlopen returned 0x%lx",h);
    return h!=0;
}

int main(int argc,char**argv) {
    pid_t pid=0; std::string lib;
    for(int i=1;i<argc;i++) {
        if(!strcmp(argv[i],"--pid")&&i+1<argc) pid=atoi(argv[++i]);
        else if(!strcmp(argv[i],"--library")&&i+1<argc) lib=argv[++i];
        else if(!strcmp(argv[i],"--log")&&i+1<argc) g_log=argv[++i];
    }
    log_line("DanzKu ARM64 injector start pid=%d",pid);
    log_line("library=%s",lib.c_str());
    if(pid<=0||lib.empty()) { log_line("ERROR invalid arguments"); return 2; }

    if(ptrace(PTRACE_ATTACH,pid,0,0)!=0) {
        log_line("ERROR ptrace attach failed errno=%d (%s)",errno,strerror(errno));
        return 3;
    }
    int st=0; waitpid(pid,&st,0);
    log_line("ptrace attached");

    bool ok=remote_dlopen(pid,lib.c_str());

    ptrace(PTRACE_DETACH,pid,0,0);
    log_line("ptrace detached");
    log_line("remote-dlopen status=%s",ok?"SUCCESS":"FAILED");
    return ok?0:4;
#else
    log_line("ERROR: injector requires arm64-v8a");
    return 5;
#endif
}
