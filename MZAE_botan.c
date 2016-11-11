/*
	Cryptographic functions built on top of Botan.
*/

#include <mZipAES.h>

#include <botan/ffi.h>


#ifdef BYTE_ORDER_1234
void betole64(unsigned long long *x) {
*x = (*x & 0x00000000FFFFFFFF) << 32 | (*x & 0xFFFFFFFF00000000) >> 32;
*x = (*x & 0x0000FFFF0000FFFF) << 16 | (*x & 0xFFFF0000FFFF0000) >> 16;
*x = (*x & 0x00FF00FF00FF00FF) << 8  | (*x & 0xFF00FF00FF00FF00) >> 8;
}
#endif



int MZAE_gen_salt(char* salt, int saltlen)
{
	botan_rng_t rng;

	if (saltlen != 8 && saltlen != 12 && saltlen != 16)
		return 1;
	
	if (botan_rng_init(&rng, "system") ||	botan_rng_get(rng, salt, saltlen))
		return 2;
	
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
	
	if (botan_pbkdf("PBKDF2(SHA-1)", kdfbuf, 2*keylen+2, password, salt, saltlen, 1000))
		return 3;
	
	*aes_key = kdfbuf;
	*hmac_key = kdfbuf+keylen;
	*vv = kdfbuf+2*keylen;

	return 0;
}



int MZAE_ctr_crypt(char* key, unsigned int keylen, char* src, unsigned int srclen, char** dst)
{
	botan_cipher_t cipher;
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

	if (botan_cipher_init(&cipher, "AES-256/ECB", 0) || botan_cipher_set_key(cipher, key, keylen))
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
		botan_cipher_update(cipher, 1, ctr_encrypted_counter, 16, &olen, ctr_counter_le, 16, &ilen);
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
		botan_cipher_update(cipher, 1, ctr_encrypted_counter, 16, &olen, ctr_counter_le, 16, &ilen);
		while (i--)
			*pbuf++ = *src++ ^ *p++;
	}

	return 0;
}



int MZAE_hmac_sha1_80(char* key, unsigned int keylen, char* src, unsigned int srclen, char** hmac)
{
	botan_mac_t mac;
	int olen;

	if (!keylen || !srclen)
		return -1;

	if (botan_mac_init(&mac, "HMAC(SHA-1)", 0) ||	botan_mac_set_key(mac, key, keylen))
		return 1;
	
	botan_mac_update(mac, src, srclen);

	*hmac = (char*) malloc(20);
	if (! *hmac)
		return 2;
	botan_mac_final(mac, *hmac);

	return 0;
}