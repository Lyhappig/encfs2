#include "file-crypt.h"

int min(int x, int y) {
	return x < y ? x : y;
}


/**
 * AES_256_CBC加密（输出到文件out）
 * @param in 读取文件
 * @param out 写入文件
 * @param enc 1/0/-1: 加密/解密/原封不动
 * @param key_str 加密口令
 * @return 1/0: 加密成功/失败
*/
int do_crypt(FILE* in, FILE* out, int action, char* key_str){

    /* 读入字符数组 */
    unsigned char inbuf[BLOCKSIZE];
    int inlen;
    /* 输出字符数组 */
    unsigned char outbuf[BLOCKSIZE + EVP_MAX_BLOCK_LENGTH];
    int outlen;
    int writelen;

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    unsigned char key[32];
    unsigned char iv[32];

    int i;

    if(action >= 0){
		// 确保密钥口令不为空
		if(!key_str){
	    	/* Error */
	    	fprintf(stderr, "Key_str must not be NULL\n");
	    	return FAILURE;
		}
		// 通过EVP_BytesToKey将输入的口令生成密钥，采用哈希算法SHA-256生成AES-256需要的密钥
		i = EVP_BytesToKey(EVP_aes_256_cbc(), EVP_sha256(), NULL,
			   (unsigned char*)key_str, strlen(key_str), SHA_ENC_ROUNDS, key, iv);
		// 检查EVP_BytesToKey派生密钥是否为32字节（256比特）
		if (i != 32) {
	    	/* Error */
	    	fprintf(stderr, "Key size is %d bits - should be 256 bits\n", i*8);
	    	return FAILURE;
		}
		/* 初始化加密程序 */
		// EVP_CIPHER_CTX_free(ctx);
		EVP_CipherInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv, action);
    }

	int total_len = 0;

    for(;;){
		/* Read Block */
		inlen = fread(inbuf, sizeof(*inbuf), BLOCKSIZE, in);
		if(inlen <= 0){
	    	/* EOF -> Break Loop */
	    	break;
		}
	
		/* If in cipher mode, perform cipher transform on block */
		if(action >= 0) {
	    	if(!EVP_CipherUpdate(ctx, outbuf, &outlen, inbuf, inlen)) {
		    	/* Error */
		    	EVP_CIPHER_CTX_free(ctx);
		    	return FAILURE;
			}
		} else {
	    	memcpy(outbuf, inbuf, inlen);
	    	outlen = inlen;
		}

		/* Write Block */
		writelen = fwrite(outbuf, sizeof(*outbuf), outlen, out);
		if(writelen != outlen){
	    	/* Error */
	    	perror("fwrite error");
	    	EVP_CIPHER_CTX_free(ctx);
	    	return FAILURE;
		}
		total_len += outlen;
    }
    
    /* If in cipher mode, handle necessary padding */
    if(action >= 0){
		/* Handle remaining cipher block + padding */
		if(!EVP_CipherFinal_ex(ctx, outbuf, &outlen)){
			/* Error */
			EVP_CIPHER_CTX_free(ctx);
			return FAILURE;
	    }
		/* Write remainign cipher block + padding*/
		fwrite(outbuf, sizeof(*inbuf), outlen, out);
		EVP_CIPHER_CTX_free(ctx);
		total_len += outlen;
    }

	log_msg("write to temp file's length is %d\n", total_len);

    /* 返回写入文件的字节数 */
    return total_len;
}

/**
 * AES_256_CBC加密（输出到cipher）
 * @param in 明文（文件内容）
 * @param size 读取长度([4KB, 32KB])
 * @param cipher 密文
 * @param cipher_len 密文长度
 * @param action 1/0/-1: 加密/解密/复制
 * @param key_str 加密口令
 * @return 1/other 成功/失败
*/
int buf_crypt(FILE *in, int size, char *cipher, int* cipher_len, int action, char* key_str) {
	
	/* 读入字符数组 */
    uint8_t *inbuf = (uint8_t *) malloc(BLOCKSIZE);
    int inlen = 0;
	/* 输出字符数组 */
    uint8_t *outbuf = (uint8_t *) malloc(BLOCKSIZE + EVP_MAX_BLOCK_LENGTH);
    int outlen = 0;
	/* 密文中间结果 */
	uint8_t *cipher_buf = (uint8_t *) malloc(size + EVP_MAX_BLOCK_LENGTH);
   	*cipher_len = 0;

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    unsigned char key[32];
    unsigned char iv[32];
    
    int i;

	// fprintf(stderr, "begin init\n");

    /* 初始化加密密钥和加密程序 */
    if(action >= 0) {
		// 确保密钥口令不为空
		if(!key_str){
	    	/* Error */
	    	fprintf(stderr, "Key_str must not be NULL\n");
	    	return FAILURE;
		}
		// 通过EVP_BytesToKey将输入的口令生成密钥，采用哈希算法SHA-256生成AES-256需要的密钥
		i = EVP_BytesToKey(EVP_aes_256_cbc(), EVP_sha256(), NULL,
			   (unsigned char*)key_str, strlen(key_str), SHA_ENC_ROUNDS, key, iv);
		// 检查EVP_BytesToKey派生密钥是否为32字节（256比特）
		if (i != 32) {
	    	/* Error */
	    	fprintf(stderr, "Key size is %d bits - should be 256 bits\n", i * 8);
	    	return FAILURE;
		}
		// 初始化 EVP_CIPHER_CTX
		// EVP_CIPHER_CTX_init(ctx);
		// 设置EVP_CIPHER_CTX参数：enc 1 = encrypt, 0 = decrypt
		EVP_CipherInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv, action);
    }

	// fprintf(stderr, "begin decrypt\n");

    for(i = 0; i <= size; i += BLOCKSIZE) {
		/* 读取一块 */
		inlen = fread(inbuf, sizeof(*inbuf), BLOCKSIZE, in);
		// fprintf(stderr, "%d, ", inlen);

		if(inlen <= 0){
	    	break;
		}

		// fprintf(stderr, "read from in, inlen: %d\n", inlen);

		/* If in cipher mode, perform cipher transform on block */
		if(action >= 0) {
	    	if(!EVP_CipherUpdate(ctx, outbuf, &outlen, inbuf, inlen)) {
		    	/* Error */
				fprintf(stderr, "EVP_CipherUpdate Block error\n");
		    	EVP_CIPHER_CTX_free(ctx);
		    	return FAILURE;
			}
		} else {
	    	memcpy(outbuf, inbuf, inlen);
	    	outlen = inlen;
		}

		// 将该块结果复制到密文
		memcpy(cipher_buf + *cipher_len, outbuf, outlen);
		*cipher_len += outlen;
    }

	log_msg("cipher len is: %d\n", *cipher_len);

	
	/* If in cipher mode, handle necessary padding */
    if(action >= 0){
		/* Handle remaining cipher block + padding */
		outlen = 0;
		if(!EVP_CipherFinal_ex(ctx, outbuf, &outlen)){
			/* Error */
			fprintf(stderr, "EVP_CipherFinal_ex error\n");
			EVP_CIPHER_CTX_free(ctx);
			return FAILURE;
	    }
		memcpy(cipher_buf + *cipher_len, outbuf, outlen);
		*cipher_len += outlen;
		EVP_CIPHER_CTX_free(ctx);
    }

	*cipher_len = min(size, *cipher_len);

	cipher = realloc(cipher, *cipher_len);
	memcpy(cipher, cipher_buf, *cipher_len);

	free(inbuf);
	free(outbuf);
	free(cipher_buf);

	fprintf(stderr, "size %d is ok\n", size);

    /* Success */
    return SUCCESS;
}