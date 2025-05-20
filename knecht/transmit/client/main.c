#include "commons.h"
#include "base64.h"

#define b64_to_size(size) ((size % 3 == 0 ? size : 3 - (size % 3) + size) / 3 * 4)

#define header_size b64_to_size(sizeof(int) * 3)
#define akn_header_length b64_to_size(sizeof(int) * 2)

unsigned int crc32b(unsigned char *message, unsigned int size)
{
    int i, j;
    unsigned int byte, crc, mask;

    crc = 0xFFFFFFFF;
    for(int i = 0; i < size; i++)
    {
        byte = message[i]; // Get next byte.
        crc = crc ^ byte;
        for (j = 7; j >= 0; j--)
        { // Do eight times.
            mask = -(crc & 1);
            crc = (crc >> 1) ^ (0xEDB88320 & mask);
        }
    }
    return ~crc;
}

int read_packet(struct packet *packet, int seq_num)
{
    char input[MAX_B64_DATA];

    if (!read_exact(0, &input, header_size))
    {
        send_status(seq_num, "[!] failed to read packet header fully");
        return 0;
    }

    if (!b64_decode(input, (char *)packet, header_size))
    {
        send_status(seq_num, "[!] failed to read packet header fully");
        return 0;
    }

    if (packet->length <= 0)
    {
        send_status(seq_num, "[+] finished transmition");
        return 1;
    }

    int encoded_size = b64_to_size(packet->length);
    if (!read_exact(0, &input, encoded_size))
    {
        send_status(seq_num, "[!] failed to read packet body fully");
        return 0;
    }

    if (!b64_decode(input, &packet->data, encoded_size))
    {
        send_status(seq_num, "[!] failed to decode packet body");
        return 0;
    }

    if (crc32b(&packet->data, packet->length) != packet->crc)
    {
        send_status(seq_num, "[!] crc check failed on packet");
        return 0;
    }

    if (packet->seq_num != seq_num) {
        send_status(seq_num, "[!] invalide seq_number");
        return 0;
    }

    send_status(seq_num, "[+] success");

    return 1;
}

int read_initialization(struct initialization *initialization)
{
    char input[MAX_B64_DATA];

    if (!read_exact(0, &input, header_size))
    {
        send_status(-1, "[!!!] failed to read init packet header fully");
        exit(-1);
    }

    if (!b64_decode(input, (char *)initialization, header_size))
    {
        send_status(-1, "[!!!] failed to decode init packet header");
        exit(-1);
    }

    if (initialization->file_name_length <= 0)
    {
        send_status(-1, "[!!!] no filename provided");
        exit(-1);
    }

    int encoded_size = b64_to_size(initialization->file_name_length);
    if (!read_exact(0, &input, encoded_size))
    {
        send_status(-1, "[!!!] failed to read filepath fully");
        exit(-1);
    }

    if (!b64_decode(input, &initialization->file_name, encoded_size))
    {
        send_status(-1, "[!!!] failed to decode filepath");
        exit(-1);
    }

    if (crc32b(&initialization->file_name, initialization->file_name_length) != initialization->crc)
    {
        send_status(-1, "[!!!] crc check failed for filename");
        exit(-1);
    }

    send_status(-1, "[+] success");
    return 1;
}

int send_akn(struct aknowledge *aknowledge)
{
    char out[MAX_B64_DATA];

    if (!b64_encode(aknowledge, &out, sizeof(int) * 2))
        return 0;

    if (!write(1, &out, akn_header_length))
        return 0;

    if (aknowledge->error_len)
    {

        if (!b64_encode(aknowledge->error, &out, aknowledge->error_len))
            return 0;

        if (!write(1, &out, b64_to_size(aknowledge->error_len)))
            return 0;
    }
}

void send_status(int seq_num, char *msg)
{
    struct aknowledge akn = {.error = msg, .error_len = custom_strlen(msg), .seq_num = seq_num};


    if (!send_akn(&akn))
    {
        custom_puts("[!!!] Fatal error, failed to send aknowledge, exiting");
        exit(-1);
    }
}

void _start()
{
    write(1, "connected\n", 10);

    struct initialization initialization;

    read_initialization(&initialization);

    int fd = open(initialization.file_name, O_RDWR | O_CREAT, initialization.permissions);

    if (fd < 0) {
        send_status(-1, "[!!!] failed to open file");
        exit(-1);
    }

    struct packet packet;

    for (int sequence_number = 0;; sequence_number++) {
        int retry = 0;
        while (retry < 10 && !read_packet(&packet, sequence_number)) retry++; 
        if (retry >= 10) {
            send_status(sequence_number, "[!!!] retries exhausted terminating transmition");
            exit(-1);
        }
        if (packet.length == 0) break;  // transmition complete
        write(fd, &packet.data, packet.length);
    }

    close(fd);

    send_status(-1, "[+] transmition complete");

    exit(0);
}