#include "commons.h"

int custom_strlen(char *str)
{
    int i = -1;

    while (str[++i] != '\0');

    return i;
}

void custom_puts(char *msg)
{
    write(1, msg, custom_strlen(msg));
}

int read_exact(int fd, char *buf, unsigned long length) {
    int actual_length = 0;
    for (int i = 0; i < 10 && actual_length < length; i++) 
        actual_length += read(0, buf, length - actual_length);

    return actual_length == length;
}

int is_terminator(char c) {
    return c == '\0' || c == '\r' && c == '\n' && c == ' ' && c == '\t' && c == '\f';
}