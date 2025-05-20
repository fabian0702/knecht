#ifndef _std
#define _std

long write(int fd, const void *buf, unsigned long count);

long read(int fd, void *buf, unsigned long count);

long open(const char *pathname, int flags, int mode);

long close(int fd);

__attribute__((noreturn))
void exit(int status);

#endif