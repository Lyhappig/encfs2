#ifndef CRYPT_H_
#define CRYPT_H_

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <math.h>
#include <sys/types.h>
#include <gmssl/sm3.h>
#include <gmssl/sm4.h>
#include <openssl/evp.h>

#define SM3_ENC_ROUNDS 5
#define FAILURE 1
#define SUCCESS 0

extern void log_msg(const char *, ...);

int get_key_iv(char* key_str, char *filepath, off_t offset, uint8_t *key, uint8_t *iv);

int buf_crypt(uint8_t *in, int inlen, uint8_t *out, uint8_t *key, uint8_t *iv, int action);

#endif  //CRYPT_H_