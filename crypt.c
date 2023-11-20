#include "crypt.h"

static inline void get_ctr(uint8_t *iv, int num) {
	__uint128_t suf = 0;
	for(int i = 0; i < 16; i++) 
		suf = (suf << 8) | iv[i];
	suf += num;
	for(int i = 15; i >= 0; i--) {
		iv[i] = suf & 0xff;
		suf >>= 8;
	}
} 


/**
 * 获取加密的密钥和iv
 * @param key_str passphrase
 * @param filepath file path(as salt)
 * @param key pointer key
 * @param iv pointer iv
 * @return 0/1: success/failure
*/
int get_key_iv(char* key_str, char *filepath, off_t offset, uint8_t *key, uint8_t *iv) {
	if(key_str == NULL || filepath == NULL) {
	    log_msg("key_str or filepath must not be NULL\n");
	    return FAILURE;
	}
	int key_size = EVP_BytesToKey(EVP_aes_128_cbc(), EVP_sm3(), (uint8_t *) filepath,
			   (uint8_t *)key_str, strlen(key_str), SM3_ENC_ROUNDS, key, iv);
	if (key_size != 16) {
	    log_msg("Key size is %d bits - should be 128 bits\n", key_size * 8);
	    return FAILURE;
	}
	get_ctr(iv, offset / 16);
	return SUCCESS;
}


/**
 * sm4_ctr加密
*/
int sm4_cbc_crypt(uint8_t *inbuf, int inlen, uint8_t *outbuf, uint8_t* key, uint8_t *iv, int action) {
	SM4_KEY sm4_key;
	sm4_set_encrypt_key(&sm4_key, key);
	if(action) {
		sm4_ctr_encrypt(&sm4_key, iv, inbuf, inlen, outbuf);
	} else {
		sm4_ctr_decrypt(&sm4_key, iv, inbuf, inlen, outbuf);
	}
	return SUCCESS;	
}


/**
 * 文件内容加密
 * @param in 明文（文件内容）
 * @param inlen 读取长度
 * @param out 密文
 * @param key key
 * @param iv iv
 * @param action 1/0: 加密/解密
 * @return 0/1 成功/失败
*/
int buf_crypt(uint8_t *in, int inlen, uint8_t *out, uint8_t *key, uint8_t *iv, int action) {
	if(sm4_cbc_crypt(in, inlen, out, key, iv, action) == FAILURE) {
		log_msg("sm4_cbc_crypt error\n");
		return FAILURE;
	}
	return SUCCESS;
}