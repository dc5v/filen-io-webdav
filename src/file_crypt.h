#ifndef FILE_ENCRYPTION_H
#define FILE_ENCRYPTION_H

#define KEY_LENGTH 32
#define IV_LENGTH 12
#define BUFFER_SIZE 4096

typedef enum { ENC, DEC } Operation;

void file_crypt(const char *src_fname, const char *dest_fname, const unsigned char *key, const unsigned char *iv, Operation op);

#endif
