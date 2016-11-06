/*
	Cryptographic functions built on top of Mozilla NSS.
*/

#include <mZipAES.h>

#include <nss/pk11pub.h>
#include <nss/seccomon.h>


#ifdef BYTE_ORDER_1234
void betole64(unsigned long long *x) {
*x = (*x & 0x00000000FFFFFFFF) << 32 | (*x & 0xFFFFFFFF00000000) >> 32;
*x = (*x & 0x0000FFFF0000FFFF) << 16 | (*x & 0xFFFF0000FFFF0000) >> 16;
*x = (*x & 0x00FF00FF00FF00FF) << 8  | (*x & 0xFF00FF00FF00FF00) >> 8;
}
#endif



int AE_gen_salt(char* salt, int saltlen)
{
	if (saltlen != 8 && saltlen != 12 && saltlen != 16)
		return 1;
	
	if (! NSS_IsInitialized()) {
		NSS_NoDB_Init(".");
		if (! NSS_IsInitialized())
			return -1;
	}

	PK11_GenerateRandom(salt, saltlen);

	return 0;
}



int AE_derive_keys(char* password, char* salt, int saltlen, char** aes_key, char** hmac_key, char** vv)
{
	int keylen = 0;
	char *kdfbuf;

	SECItem si, pi, *pkd;
	SECAlgorithmID *algid;
	PK11SlotInfo *slot;
	PK11SymKey *sk = NULL;

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

	if (! NSS_IsInitialized()) {
		NSS_NoDB_Init(".");
		if (! NSS_IsInitialized())
			return -1;
	}

	si.type = 0; // siBuffer
	si.data = salt;
	si.len = saltlen;
	
	algid = PK11_CreatePBEV2AlgorithmID(SEC_OID_PKCS5_PBKDF2, SEC_OID_PKCS5_PBKDF2, SEC_OID_HMAC_SHA1, 2*keylen+2, 1000, &si);

	slot = PK11_GetBestSlot(CKM_PKCS5_PBKD2, 0);
	
	if (!algid || !slot)
		return 3;

	pi.type = 0; // siBuffer
	pi.data = password;
	pi.len = strlen(password);

	sk = PK11_PBEKeyGen(slot, algid, &pi, 0, 0);
	PK11_ExtractKeyValue(sk);
	pkd = PK11_GetKeyData(sk);

	memcpy(kdfbuf, pkd->data, 2*keylen+2);
	*aes_key = kdfbuf;
	*hmac_key = kdfbuf+keylen;
	*vv = kdfbuf+2*keylen;

	PK11_FreeSymKey(sk);
	PK11_FreeSlot(slot);

	return 0;
}



int AE_ctr_crypt(char* key, unsigned int keylen, char* src, unsigned int srclen, char** dst)
{
	SECItem ki;
	PK11SlotInfo* slot;
	PK11SymKey* sk = NULL;
	SECItem* sp = NULL;
	PK11Context* ctxt = NULL;
	int olen;

	char ctr_counter_le[16];
	char ctr_encrypted_counter[16];
#ifdef BYTE_ORDER_1234
	char ctr_counter_be[16];
#endif
	const char* p = ctr_encrypted_counter;
	const char* q = p+8;
	char *pbuf;
	unsigned int i;

	if (!keylen || !srclen)
		return -1;

	if (! NSS_IsInitialized()) {
		NSS_NoDB_Init(".");
		if (! NSS_IsInitialized())
			return -1;
	}

	slot = PK11_GetBestSlot(CKM_AES_ECB, 0);

	ki.type = 0; // siBuffer
	ki.data = key;
	ki.len = keylen;

	sk = PK11_ImportSymKey(slot, CKM_AES_ECB, PK11_OriginUnwrap, CKA_ENCRYPT, &ki, 0);
	sp = PK11_ParamFromIV(CKM_AES_ECB, 0);
	ctxt = PK11_CreateContextBySymKey(CKM_AES_ECB, CKA_ENCRYPT, sk, sp);

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
		PK11_CipherOp(ctxt, ctr_encrypted_counter, &olen, 16, ctr_counter_le, 16);
		*((unsigned long long*) pbuf)++ = *((unsigned long long*) src)++ ^ *((unsigned long long*) p);
		*((unsigned long long*) pbuf)++ = *((unsigned long long*) src)++ ^ *((unsigned long long*) q);
	}

	if ((i = srclen%16)) {
#ifndef BYTE_ORDER_1234
		(*((unsigned long long*) ctr_counter_le))++;
#else	
		(*((unsigned long long*) ctr_counter_be))++;
		*((unsigned long long*) ctr_counter_le) = *((unsigned long long*) ctr_counter_be);
		betole64((unsigned long long*)ctr_counter_le);
#endif
		PK11_CipherOp(ctxt, ctr_encrypted_counter, &olen, 16, ctr_counter_le, 16);
		while (i--)
			*pbuf++ = *src++ ^ *p++;
	}

	PK11_DestroyContext(ctxt, 1);
	PK11_FreeSymKey(sk);
	PK11_FreeSlot(slot);

	return 0;
}



int AE_hmac_sha1_80(char* key, unsigned int keylen, char* src, unsigned int srclen, char** hmac)
{
	SECItem ki, np;
	PK11SlotInfo* slot;
	PK11SymKey* sk = NULL;
	PK11Context* ctxt = NULL;
	int olen;

	if (!keylen || !srclen)
		return -1;

	if (! NSS_IsInitialized()) {
		NSS_NoDB_Init(".");
		if (! NSS_IsInitialized())
			return -1;
	}

	ki.type = 0; // siBuffer
	ki.data = key;
	ki.len = keylen;

	slot = PK11_GetBestSlot(CKM_SHA_1_HMAC, 0);
	sk = PK11_ImportSymKey(slot, CKM_SHA_1_HMAC, PK11_OriginUnwrap, CKA_SIGN, &ki, 0);

	memset(&np, 0, sizeof(np));
	ctxt = PK11_CreateContextBySymKey(CKM_SHA_1_HMAC, CKA_SIGN, sk, &np);
	PK11_DigestBegin(ctxt);
	PK11_DigestOp(ctxt, src, srclen);
	*hmac = (char*) malloc(20);
	PK11_DigestFinal(ctxt, *hmac, &olen, 20);

	PK11_DestroyContext(ctxt, 1);
	PK11_FreeSymKey(sk);
	PK11_FreeSlot(slot);

	return 0;
}
