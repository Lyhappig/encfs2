#ifndef FILE_CRYPT_H
#define FILE_CRYPT_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <openssl/evp.h>
#include <openssl/aes.h>

#define SHA_ENC_ROUNDS 5
/* 写的标准长度为 4096B; 读的最大长度为 32KB; 取块长为 1024B 分块加密*/
#define BLOCKSIZE 1024
#define FAILURE 0
#define SUCCESS 1
#define ENC_LOG 1

extern void log_msg(const char *, ...);

int do_crypt(FILE* in, FILE* out, int action, char* key_str);

int buf_crypt(FILE *in, int size, char *cipher, int* cipher_len, int action, char* key_str);

#endif  //FILE_CRYPT_H