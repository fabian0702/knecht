long write(int fd, const void *buf, unsigned long count)
{
    long ret;

    asm volatile(
        "mov $1, %%rax\n" // syscall number for write (1)
        "mov %1, %%rdi\n" // fd
        "mov %2, %%rsi\n" // buf
        "mov %3, %%rdx\n" // count
        "syscall\n"
        "mov %%rax, %0\n"                     // return value
        : "=r"(ret)                           // output
        : "r"((long)fd), "r"(buf), "r"(count) // inputs
        : "rax", "rdi", "rsi", "rdx"          // clobbered registers
    );

    return ret;
}

long read(int fd, void *buf, unsigned long count)
{
    long ret;
    asm volatile(
        "mov $0, %%rax\n"
        "mov %1, %%rdi\n"
        "mov %2, %%rsi\n"
        "mov %3, %%rdx\n"
        "syscall\n"
        "mov %%rax, %0\n"
        : "=r"(ret)
        : "r"((long)fd), "r"(buf), "r"(count)
        : "rax", "rdi", "rsi", "rdx");
    return ret;
}

// int open(const char *pathname, int flags, mode_t mode)
long open(const char *pathname, int flags, int mode)
{
    long ret;
    asm volatile(
        "mov $2, %%rax\n"
        "mov %1, %%rdi\n"
        "mov %2, %%rsi\n"
        "mov %3, %%rdx\n"
        "syscall\n"
        "mov %%rax, %0\n"
        : "=r"(ret)
        : "r"(pathname), "r"((long)flags), "r"((long)mode)
        : "rax", "rdi", "rsi", "rdx");
    return ret;
}

// int close(int fd)
long close(int fd)
{
    long ret;
    asm volatile(
        "mov $3, %%rax\n"
        "mov %1, %%rdi\n"
        "syscall\n"
        "mov %%rax, %0\n"
        : "=r"(ret)
        : "r"((long)fd)
        : "rax", "rdi");
    return ret;
}

// void exit(int status)
__attribute__((noreturn)) void exit(int status)
{
    asm volatile(
        "mov $60, %%rax\n"
        "mov %0, %%rdi\n"
        "syscall\n"
        :
        : "r"((long)status)
        : "rax", "rdi");
    __builtin_unreachable();
}