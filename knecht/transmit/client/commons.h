#include "stdlib.h"

#ifndef _commons
#define _commons

#define MAX_DATA_SIZE 1024
#define MAX_FILENAME_SIZE 256
#define NULL 0x0
#define O_RDWR 02
#define O_CREAT 0100

struct initialization
{
    unsigned int file_name_length;
    unsigned int permissions;
    unsigned int crc;
    char file_name[MAX_FILENAME_SIZE];
};

struct packet
{
    unsigned int length;
    int seq_num;
    unsigned int crc;
    char data[MAX_DATA_SIZE];
};

struct aknowledge {
    unsigned int error_len;
    int seq_num;
    char *error;
};

void custom_puts(char *msg);

int read_exact(int fd, char *buf, unsigned long length);

int custom_strlen(char *str);

int is_terminator(char c);

#endif