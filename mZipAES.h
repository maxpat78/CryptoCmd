/*
   mZipAES

   A micro reader & writer for AES encrypted ZIP archives.

   Functions are provided to create in memory a deflated and AES-256 encrypted
   ZIP archive from a single input, and to extract from such an archive.

   Zlib is required to support Deflate algorithm.
   
   Cryptographic functions (i.e. PBKDF2 keys derivation, SHA-1 HMAC, AES 
   encryption) require one of these kits: OpenSSL or LibreSSL, Botan,
   GNU libgcrypt or Mozilla NSS.
*/

#if !defined(__MZIPAES__)
#define __MZIPAES__

/*
	Generates a random salt for the keys derivation function.
	
	salt		a pre allocated buffer receiving the salt
	saltlen		length of the required salt (must be 8, 12 or 16)
*/
int AE_gen_salt(char* salt, int saltlen);


/*
	Generates keys for AES encryption and HMAC-SHA1, plus a 16-bit verification
	value, from a password and a random salt.
	
	password	password to encrypt and authenticate archive contents
	salt		the random salt generated with AE_gen_salt
	saltlen		its length
	aes_key		pointer receiving the address of the generated AES key
	hmac_key	pointer receiving the address of the generated HMAC key
	vv			pointer receiving the address of the verification value
*/
int AE_derive_keys(char* password, char* salt, int saltlen, char** aes_key, char** hmac_key, char** vv);


/*
	Encrypts data into a newly allocated buffer, using AES in CTR mode with a
	little endian counter.
	
	key			the AES key computated with AE_derive_keys
	keylen		its length in bytes
	src			points to the data to encrypt
	srclen		length of the data to encrypt
	dst			pointer receiving the address of the encrypted data buffer
*/
int AE_ctr_crypt(char* key, unsigned int keylen, char* src, unsigned int srclen, char** dst);


/*
	Computates the HMAC-SHA1 for a given buffer.
	
	key			the HMAC key computated with AE_derive_keys
	keylen		its length in bytes
	src			points to the data to calculate the HMAC for
	srclen		length of such data
	dst			pointer receiving the address of the HMAC string
*/
int AE_hmac_sha1_80(char* key, unsigned int keylen, char* src, unsigned int srclen, char** hmac);


/*
	Computates the ZIP crc32.
	
	crc			initial crc value to update
	src			source buffer
	srclen		its length
*/
unsigned long AE_crc(unsigned long crc, char* src, unsigned int srclen);


/*
	One pass deflate.
	
	src			uncompressed data
	srclen		its length
	dst			pointer receiving the address of the compressed data
	dstlen		pointer receiving the length of the compressed data

	Returns zero in case of success.
*/
int AE_deflate(char* src, unsigned int srclen, char** dst, unsigned int* dstlen);


/*
	One pass inflate.
	
	src			compressed data
	srclen		its length
	dst			pre-allocated buffer receiving the uncompressed data
	dstlen		its length

	Returns zero in case of success.
*/
int AE_inflate(char* src, unsigned int srclen, char* dst, unsigned int dstlen);
#endif // __MZIPAES__