/*
	Cryptographic functions built on top of GNU libgcrypt.
*/

#include <mZipAES.h>

#include <gcrypt.h>


#ifdef BYTE_ORDER_1234
void betole64(unsigned long long *x) {
*x = (*x & 0x00000000FFFFFFFF) << 32 | (*x & 0xFFFFFFFF00000000) >> 32;
*x = (*x & 0x0000FFFF0000FFFF) << 16 | (*x & 0xFFFF0000FFFF0000) >> 16;
*x = (*x & 0x00FF00FF00FF00FF) << 8  | (*x & 0xFF00FF00FF00FF00) >> 8;
}
#endif



int MZAE_gen_salt(char* salt, int saltlen)
{
	if (saltlen != 8 && saltlen != 12 && saltlen != 16)
		return 1;
	
	memcpy(salt, gcry_random_bytes(saltlen, 1), saltlen);

	return 0;
}



int MZAE_derive_keys(char* password, char* salt, int saltlen, char** aes_key, char** hmac_key, char** vv)
{
	int keylen = 0;
	char *kdfbuf;

	if (saltlen == 8)
		keylen = 16;
	else if (saltlen == 12)
		keylen = 24;
	else if (saltlen == 16)
		keylen = 32;
	else
		return 1;
	
	kdfbuf = (char*) malloc(2*keylen+2);
	if (! kdfbuf)
		return 2;
	
	if (gcry_kdf_derive(password, strlen(password), GCRY_KDF_PBKDF2, GCRY_MD_SHA1, salt, saltlen, 1000, 2*keylen+2, kdfbuf))
		return 3;
	
	*aes_key = kdfbuf;
	*hmac_key = kdfbuf+keylen;
	*vv = kdfbuf+2*keylen;

	return 0;
}



int MZAE_ctr_crypt(char* key, unsigned int keylen, char* src, unsigned int srclen, char** dst)
{
	gcry_cipher_hd_t cipher;
	char ctr_counter_le[16];
	char ctr_encrypted_counter[16];
#ifdef BYTE_ORDER_1234
	char ctr_counter_be[16];
#endif
	const char* p = ctr_encrypted_counter;
	const char* q = p+8;
	char *pbuf;
	unsigned int i, ilen, olen;

	if (!keylen || !srclen)
		return -1;

	if (gcry_cipher_open(&cipher, GCRY_CIPHER_AES256, 1, 0) || gcry_cipher_setkey(cipher, key, keylen))
		return 1;

#ifdef BYTE_ORDER_1234
	memset(ctr_counter_be, 0, 16);
#else
	memset(ctr_counter_le, 0, 16);
#endif
	
	*dst = pbuf = (char*) malloc(srclen);
	if (!pbuf)
		return 2;

	for (i=0; i < srclen/16; i++) {
#ifndef BYTE_ORDER_1234
		(*((unsigned long long*) ctr_counter_le))++;
#else	
		(*((unsigned long long*) ctr_counter_be))++;
		*((unsigned long long*) ctr_counter_le) = *((unsigned long long*) ctr_counter_be);
		betole64((unsigned long long*)ctr_counter_le);
#endif
		gcry_cipher_encrypt(cipher, ctr_encrypted_counter, 16, ctr_counter_le, 16);
		*((unsigned long long*) pbuf) = *((unsigned long long*) src) ^ *((unsigned long long*) p);
		pbuf+=sizeof(long long);
		src+=sizeof(long long);
		*((unsigned long long*) pbuf) = *((unsigned long long*) src) ^ *((unsigned long long*) q);
		pbuf+=sizeof(long long);
		src+=sizeof(long long);
	}

	if ((i = srclen%16)) {
#ifndef BYTE_ORDER_1234
		(*((unsigned long long*) ctr_counter_le))++;
#else	
		(*((unsigned long long*) ctr_counter_be))++;
		*((unsigned long long*) ctr_counter_le) = *((unsigned long long*) ctr_counter_be);
		betole64((unsigned long long*)ctr_counter_le);
#endif
		gcry_cipher_encrypt(cipher, ctr_encrypted_counter, 16, ctr_counter_le, 16);
		while (i--)
			*pbuf++ = *src++ ^ *p++;
	}

	gcry_cipher_close(cipher);

	return 0;
}



int MZAE_hmac_sha1_80(char* key, unsigned int keylen, char* src, unsigned int srclen, char** hmac)
{
	gcry_mac_hd_t mac;
	int olen;

	if (!keylen || !srclen)
		return -1;

	if (gcry_mac_open(&mac, GCRY_MAC_HMAC_SHA1, 0, 0) || gcry_mac_setkey(mac, key, keylen))
		return 1;
	
	gcry_mac_write(mac, src, srclen);
	
	*hmac = (char*) malloc(20);
	if (! *hmac)
		return 2;
	gcry_mac_read(mac, *hmac, &olen);
	
	gcry_mac_close(mac);

	return 0;
}
