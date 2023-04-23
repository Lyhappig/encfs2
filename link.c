#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <math.h>
#include <openssl/evp.h>
#include <openssl/aes.h>

uint8_t key[32], iv[32];

int main() {
    EVP_CIPHER_CTX ctx;

    int action = 1;

    char s[32];
    for(int i = 0; i < 32; i++) s[i] = 'a';
    // s[32] = '\0';

    char *key_str = "12345";

    char inbuf[1024], outbuf[1024];
    int inlen = 0, outlen;

    memcpy(inbuf + inlen, s, strlen(s));
    inlen += strlen(s);
    printf("%s\n", inbuf);
    

    EVP_BytesToKey(EVP_aes_256_cbc(), EVP_sha256(), NULL,
			   (unsigned char*)key_str, strlen(key_str), 5, key, iv);
    // 初始化 EVP_CIPHER_CTX
	EVP_CIPHER_CTX_init(&ctx);
	// 设置EVP_CIPHER_CTX参数：enc 1 = encrypt, 0 = decrypt
	EVP_CipherInit_ex(&ctx, EVP_aes_256_cbc(), NULL, key, iv, action);

    if(!EVP_CipherUpdate(&ctx, outbuf, &outlen, inbuf, inlen)) {
		/* Error */
		fprintf(stderr, "EVP_CipherUpdate Block error\n");
		EVP_CIPHER_CTX_cleanup(&ctx);
	}

    if(!EVP_CipherFinal_ex(&ctx, outbuf, &outlen)){
			/* Error */
		fprintf(stderr, "EVP_CipherFinal_ex error\n");
		EVP_CIPHER_CTX_cleanup(&ctx);
	}

    printf("%s %d\n", outbuf, outlen);


    return 0;
}

