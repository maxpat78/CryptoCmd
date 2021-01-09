/*
 *  Copyright (C) 2016, 2021  <maxpat78> <https://github.com/maxpat78>
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License along
 *  with this program; if not, write to the Free Software Foundation, Inc.,
 *  51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

/*
	Cryptographic functions built on top of Botan 2.x library
*/

#include <mZipAES.h>

#include <botan/ffi.h>

#ifdef BYTE_ORDER_1234
void betole64(uint64_t *x) {
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
	
	if (botan_pwdhash("PBKDF2(SHA-1)", 1000, 0, 0, kdfbuf, 2*keylen+2, password, 0, salt, saltlen))
		return 3;
	
	*aes_key = kdfbuf;
	*hmac_key = kdfbuf+keylen;
	*vv = kdfbuf+2*keylen;

	return 0;
}



int MZAE_ctr_crypt(char* key, uint32_t keylen, char* src, uint32_t srclen, char** dst)
{
	botan_block_cipher_t cipher;
	char ctr_counter_le[16];
	char ctr_encrypted_counter[16];
#ifdef BYTE_ORDER_1234
	char ctr_counter_be[16];
#endif
	const char* p = ctr_encrypted_counter;
	const char* q = p+8;
	char *pbuf;
	uint32_t i, ilen, olen;

	if (!keylen || !srclen)
		return -1;

	if (botan_block_cipher_init(&cipher, "AES-256") || botan_block_cipher_set_key(cipher, key, keylen))
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
		(*((uint64_t*) ctr_counter_le))++;
#else	
		(*((uint64_t*) ctr_counter_be))++;
		*((uint64_t*) ctr_counter_le) = *((uint64_t*) ctr_counter_be);
		betole64((uint64_t*)ctr_counter_le);
#endif
		botan_block_cipher_encrypt_blocks(cipher, ctr_counter_le, ctr_encrypted_counter, 1);
		*((uint64_t*) pbuf) = *((uint64_t*) src) ^ *((uint64_t*) p);
		pbuf+=sizeof(uint64_t);
		src+=sizeof(uint64_t);
		*((uint64_t*) pbuf) = *((uint64_t*) src) ^ *((uint64_t*) q);
		pbuf+=sizeof(uint64_t);
		src+=sizeof(uint64_t);
	}

	if ((i = srclen%16)) {
#ifndef BYTE_ORDER_1234
		(*((uint64_t*) ctr_counter_le))++;
#else	
		(*((uint64_t*) ctr_counter_be))++;
		*((uint64_t*) ctr_counter_le) = *((uint64_t*) ctr_counter_be);
		betole64((uint64_t*)ctr_counter_le);
#endif
		botan_block_cipher_encrypt_blocks(cipher, ctr_counter_le, ctr_encrypted_counter, 1);
		while (i--)
			*pbuf++ = *src++ ^ *p++;
	}

	return 0;
}



int MZAE_hmac_sha1_80(char* key, uint32_t keylen, char* src, uint32_t srclen, char** hmac)
{
	botan_mac_t mac;

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
